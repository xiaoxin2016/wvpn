package webvpn

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestParseSetCookieKeepsTheValueVerbatim(t *testing.T) {
	// Every one of these is either dropped or rewritten by net/http's own
	// cookie handling, and every one of them is a session somebody loses.
	cases := []struct{ raw, name, pair string }{
		{"JSESSIONID=abc123; Path=/; HttpOnly", "JSESSIONID", "JSESSIONID=abc123"},
		{"user=张三; Path=/", "user", "user=张三"},
		{"token=a b c; Path=/", "token", "token=a b c"},
		{"sig=a,b; Path=/", "sig", "sig=a,b"},
		{`quoted="v1,v2"; Path=/`, "quoted", `quoted="v1,v2"`},
		{"empty=; Path=/", "empty", "empty="},
	}
	for _, tc := range cases {
		sc, ok := parseSetCookie(tc.raw)
		if !ok {
			t.Errorf("parseSetCookie(%q) failed", tc.raw)
			continue
		}
		if sc.Name != tc.name || sc.Pair != tc.pair {
			t.Errorf("parseSetCookie(%q) = %q / %q", tc.raw, sc.Name, sc.Pair)
		}
	}
	if _, ok := parseSetCookie("novalue"); ok {
		t.Error("a header with no = was accepted")
	}
}

func TestRewriteSetCookie(t *testing.T) {
	sc, _ := parseSetCookie("sid=张三 x; Path=/app; Domain=.corp.example; Secure; HttpOnly; SameSite=None; Max-Age=600")

	overHTTP := sc.rewrite("/p/https/app.corp.example/app", false)
	if !strings.HasPrefix(overHTTP, "sid=张三 x;") {
		t.Errorf("payload changed: %q", overHTTP)
	}
	for _, want := range []string{"HttpOnly", "Max-Age=600", "SameSite=Lax", "Path=/p/https/app.corp.example/app"} {
		if !strings.Contains(overHTTP, want) {
			t.Errorf("missing %q in %q", want, overHTTP)
		}
	}
	for _, bad := range []string{"Domain=", "Secure", "SameSite=None"} {
		if strings.Contains(overHTTP, bad) {
			t.Errorf("kept %q in %q", bad, overHTTP)
		}
	}

	overTLS := sc.rewrite("/p/https/app.corp.example/app", true)
	if !strings.Contains(overTLS, "Secure") || !strings.Contains(overTLS, "SameSite=None") {
		t.Errorf("a TLS gateway should keep Secure and SameSite=None: %q", overTLS)
	}
}

func TestDomainScope(t *testing.T) {
	target, _ := url.Parse("https://app.corp.example/x")
	cases := []struct {
		raw          string
		jar, browser bool
	}{
		{"a=1; Path=/", false, true},                 // host-only
		{"a=1; Domain=app.corp.example", true, true}, // its own host
		{"a=1; Domain=.corp.example", true, false},   // shared by SSO
		{"a=1; Domain=corp.example", true, false},    // same, no dot
		{"a=1; Domain=other.example", false, false},  // a browser rejects this too
	}
	for _, tc := range cases {
		sc, _ := parseSetCookie(tc.raw)
		jar, browser := sc.domainScope(target)
		if jar != tc.jar || browser != tc.browser {
			t.Errorf("domainScope(%q) = %v/%v, want %v/%v", tc.raw, jar, browser, tc.jar, tc.browser)
		}
	}
}

func TestFilterCookieHeader(t *testing.T) {
	header := "wvsid=secret; JSESSIONID=abc; user=张三 x; last=1"
	got := filterCookieHeader(header, "wvsid")
	if strings.Contains(got, "secret") {
		t.Errorf("session cookie survived: %q", got)
	}
	for _, want := range []string{"JSESSIONID=abc", "user=张三 x", "last=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("lost %q from %q", want, got)
		}
	}
	if names := cookieHeaderNames(got); !names["JSESSIONID"] || names["wvsid"] {
		t.Errorf("cookieHeaderNames = %v", names)
	}
	if got := appendCookiePairs("", []string{"a=1", "b=2"}); got != "a=1; b=2" {
		t.Errorf("appendCookiePairs on an empty header = %q", got)
	}
}

// The single sign-on case: the identity provider sets a cookie for the whole
// domain, and the application on another host has to get it back.
func TestJarCarriesDomainCookiesAcrossHosts(t *testing.T) {
	jars := newSessionJars()
	key := jarKey("session-token")
	jar := jars.get(key)
	if jar == nil {
		t.Fatal("no jar")
	}

	sso, _ := url.Parse("https://sso.corp.example/login")
	sc, _ := parseSetCookie("SSOSESSION=值 with space; Domain=.corp.example; Path=/; HttpOnly")
	storeShared(jar, sso, []*http.Cookie{sc.toHTTPCookie()})

	app, _ := url.Parse("https://app.corp.example/portal")
	pairs := jarPairs(jars.lookup(key), app, nil)
	if len(pairs) != 1 || pairs[0] != "SSOSESSION=值 with space" {
		t.Fatalf("the application did not receive the shared cookie: %v", pairs)
	}

	// A different browser has a different jar.
	if other := jars.lookup(jarKey("another-token")); other != nil {
		t.Error("jars are shared between sessions")
	}
	// A cookie the browser already sends is not duplicated.
	if pairs := jarPairs(jar, app, map[string]bool{"SSOSESSION": true}); len(pairs) != 0 {
		t.Errorf("duplicate cookie: %v", pairs)
	}
	// An unrelated domain sees nothing.
	outside, _ := url.Parse("https://elsewhere.test/")
	if pairs := jarPairs(jar, outside, nil); len(pairs) != 0 {
		t.Errorf("cookie leaked to another domain: %v", pairs)
	}
}

func TestJarKeyIsNotTheToken(t *testing.T) {
	key := jarKey("super-secret-token")
	if strings.Contains(key, "super-secret-token") || key == "" {
		t.Errorf("jarKey = %q", key)
	}
	if jarKey("") != "" {
		t.Error("an empty token should produce no key")
	}
}

// The same flow as above, but through the handler: what the origin sets, what
// the browser is told, and what the next host gets back.
func TestProxyKeepsDomainCookiesServerSide(t *testing.T) {
	h := New(Options{SessionCookie: "wvsid", Guard: &Guard{AllowPrivate: true}})
	target, _ := url.Parse("https://sso.corp.example/login")
	info := &reqInfo{target: target, jarKey: jarKey("browser-token")}

	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "SSOSESSION=张三 令牌; Domain=.corp.example; Path=/; HttpOnly")
	resp.Header.Add("Set-Cookie", "prefs=dark; Path=/ui")
	resp.Header.Add("Set-Cookie", "wvsid=stolen; Path=/")
	h.rewriteCookies(resp, info)

	got := resp.Header.Values("Set-Cookie")
	if len(got) != 1 || !strings.HasPrefix(got[0], "prefs=dark") {
		t.Fatalf("browser cookies = %q", got)
	}
	if !strings.Contains(got[0], "Path=/p/https/sso.corp.example/ui") {
		t.Errorf("path not rewritten: %q", got[0])
	}

	// The application on another host in the same domain gets the shared one.
	app, _ := url.Parse("https://app.corp.example/portal")
	pairs := jarPairs(h.jars.lookup(info.jarKey), app, nil)
	if len(pairs) != 1 || pairs[0] != "SSOSESSION=张三 令牌" {
		t.Fatalf("the application did not receive the sign-on cookie: %v", pairs)
	}

	// Without a signed-in browser there is no jar, so the cookie stays with the
	// browser rather than disappearing.
	anon := &reqInfo{target: target}
	resp2 := &http.Response{Header: http.Header{}}
	resp2.Header.Add("Set-Cookie", "SSOSESSION=x; Domain=.corp.example; Path=/")
	h.rewriteCookies(resp2, anon)
	if got := resp2.Header.Values("Set-Cookie"); len(got) != 1 {
		t.Fatalf("anonymous cookies = %q", got)
	}
}
