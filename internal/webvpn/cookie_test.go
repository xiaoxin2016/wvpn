package webvpn

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		// Shared by sign-on: the jar carries it between hosts, and the browser
		// keeps a scoped copy so the site's own scripts can still read it.
		{"a=1; Domain=.corp.example", true, true},
		{"a=1; Domain=corp.example", true, true},    // same, no dot
		{"a=1; Domain=other.example", false, false}, // a browser rejects this too
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

	// Both reach the browser, and both are confined to the site that set them:
	// the shared one so the site's own scripts can read it back, the host-only
	// one as ever. Neither carries a Domain the gateway cannot honour.
	got := resp.Header.Values("Set-Cookie")
	if len(got) != 2 {
		t.Fatalf("browser cookies = %q", got)
	}
	for _, sc := range got {
		if strings.Contains(sc, "Domain=") {
			t.Errorf("a Domain the gateway cannot honour survived: %q", sc)
		}
		if !strings.Contains(sc, "Path=/p/https/sso.corp.example/") {
			t.Errorf("cookie not confined to the site that set it: %q", sc)
		}
	}
	if !strings.Contains(got[0], "SSOSESSION=张三 令牌") || !strings.Contains(got[0], "HttpOnly") {
		t.Errorf("the shared cookie was not passed to the browser intact: %q", got[0])
	}
	if !strings.Contains(got[1], "Path=/p/https/sso.corp.example/ui") {
		t.Errorf("path not rewritten: %q", got[1])
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

// A page that writes its own cookie with a domain — a login handing the browser
// an access token for the whole company domain — has nowhere to put it behind
// one origin, so the shim reports it and the gateway keeps it in the jar.
func TestPageWrittenDomainCookieReachesTheJar(t *testing.T) {
	h := New(Options{SessionCookie: "wvsid", Guard: &Guard{AllowPrivate: true}})

	post := func(target, cookie, session string) int {
		body, _ := json.Marshal(map[string]string{"t": target, "c": cookie})
		r := httptest.NewRequest(http.MethodPost, cookieRoute, bytes.NewReader(body))
		if session != "" {
			r.Header.Set("Cookie", "wvsid="+session)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}

	if code := post("http://eiop.corp.example/uopsLogin/uopsLogin.do",
		"accessToken=474ca9; domain=corp.example; path=/; max-age=43200", "browser-token"); code != http.StatusNoContent {
		t.Fatalf("reporting the cookie gave %d", code)
	}

	// The other host in the same domain — the one the login response points at
	// — now gets the token replayed to it.
	other, _ := url.Parse("http://eiop-chn-slb-pj-4.corp.example/#/portal-setting/account")
	pairs := jarPairs(h.jars.lookup(jarKey("browser-token")), other, nil)
	if len(pairs) != 1 || pairs[0] != "accessToken=474ca9" {
		t.Fatalf("the sibling host did not receive the token: %v", pairs)
	}
	// And a site outside that domain does not.
	outside, _ := url.Parse("http://elsewhere.test/")
	if pairs := jarPairs(h.jars.lookup(jarKey("browser-token")), outside, nil); len(pairs) != 0 {
		t.Errorf("the token leaked outside its domain: %v", pairs)
	}

	// A page cannot use this to plant a cookie on a domain its own host is not
	// part of, which is the rule a browser applies to a Domain attribute.
	post("http://eiop.corp.example/", "planted=1; domain=victim.test", "browser-token")
	victim, _ := url.Parse("http://www.victim.test/")
	if pairs := jarPairs(h.jars.lookup(jarKey("browser-token")), victim, nil); len(pairs) != 0 {
		t.Errorf("a cookie was planted on an unrelated domain: %v", pairs)
	}

	// Nor can it overwrite the gateway's own session.
	post("http://eiop.corp.example/", "wvsid=stolen; domain=corp.example", "browser-token")
	same, _ := url.Parse("http://eiop.corp.example/")
	for _, p := range jarPairs(h.jars.lookup(jarKey("browser-token")), same, nil) {
		if strings.HasPrefix(p, "wvsid=") {
			t.Error("a page overwrote the gateway session cookie")
		}
	}
}

// A browser can hold two cookies of the same name at different scopes, and
// sends both. The one the site last set is the one it means.
func TestResolveShadowedCookies(t *testing.T) {
	cases := []struct {
		name, header string
		current      map[string]string
		want         string
		shadowed     []string
	}{{
		name:   "nothing to settle",
		header: "a=1; b=2",
		want:   "a=1; b=2",
	}, {
		// The shape eiop produced: a stale copy from outside the tunnel sorts
		// first, and a site reading the first one reads the stale one.
		name:     "the value the site set wins, and keeps its place",
		header:   "galaxy_token=STALE; JSESSIONID=abc; ip=x; galaxy_token=FRESH",
		current:  map[string]string{"galaxy_token": "FRESH"},
		want:     "JSESSIONID=abc; ip=x; galaxy_token=FRESH",
		shadowed: []string{"galaxy_token"},
	}, {
		name:     "with nothing of our own, the newer of two equal paths is last",
		header:   "tok=OLD; other=1; tok=NEW",
		want:     "other=1; tok=NEW",
		shadowed: []string{"tok"},
	}, {
		name:     "three copies collapse to one",
		header:   "t=A; t=B; t=C",
		current:  map[string]string{"t": "B"},
		want:     "t=B",
		shadowed: []string{"t"},
	}, {
		name:     "a value the gateway does not know still collapses",
		header:   "t=A; t=B",
		current:  map[string]string{"t": "Z"},
		want:     "t=B",
		shadowed: []string{"t"},
	}, {
		name:     "bytes are carried over untouched",
		header:   "u=张三 与 空格; u=张三 新的",
		current:  map[string]string{"u": "张三 新的"},
		want:     "u=张三 新的",
		shadowed: []string{"u"},
	}, {
		name:   "an empty header is left alone",
		header: "",
		want:   "",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, shadowed := resolveShadowedCookies(tc.header, tc.current)
			if got != tc.want {
				t.Errorf("header = %q, want %q", got, tc.want)
			}
			if strings.Join(shadowed, ",") != strings.Join(tc.shadowed, ",") {
				t.Errorf("shadowed = %v, want %v", shadowed, tc.shadowed)
			}
		})
	}
}
