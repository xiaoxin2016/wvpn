package webvpn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A site that authenticates with a token of its own sends its API calls with
// credentials: "omit". The shim sends them with cookies after all so the
// gateway can check its session, and marks them; the site must still see what
// "omit" means — no cookies in, none kept from the response.
func TestOmittedCredentialsReachTheSiteWithoutCookies(t *testing.T) {
	type seen struct{ cookie, marker string }
	var last seen
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = seen{cookie: r.Header.Get("Cookie"), marker: r.Header.Get(OmitCredentialsHeader)}
		w.Header().Add("Set-Cookie", "fresh=from-api; Path=/")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(origin.Close)
	host := originHost(t, origin)
	target, _ := url.Parse("http://" + host + "/")

	h := New(Options{SessionCookie: "wvsid", Guard: &Guard{AllowPrivate: true}})
	gw := httptest.NewServer(h)
	t.Cleanup(gw.Close)

	// The browser's session keys a jar that already holds a cookie for this
	// site, next to one the site set in the browser.
	storeShared(h.jars.get(jarKey("session-1")), target, []*http.Cookie{{Name: "SSO", Value: "from-jar", Path: "/"}})
	browserCookies := "wvsid=session-1; " + CookiePrefix + "sid=from-browser"

	call := func(marked bool) *http.Response {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, gw.URL+"/p/http/"+host+"/api/getAuthorInfo.json", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Cookie", browserCookies)
		if marked {
			req.Header.Set(OmitCredentialsHeader, "omit")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	// An ordinary call carries the site's cookies from both places, which is
	// what makes the marked one below a real comparison.
	resp := call(false)
	if !strings.Contains(last.cookie, "sid=from-browser") || !strings.Contains(last.cookie, "SSO=from-jar") {
		t.Fatalf("unmarked call: site saw Cookie %q, want the browser's and the jar's", last.cookie)
	}
	if got := resp.Header.Values("Set-Cookie"); len(got) != 1 || !strings.HasPrefix(got[0], CookiePrefix+"fresh=") {
		t.Fatalf("unmarked call: browser was given %q", got)
	}

	// The marked call: the gateway saw its session (the call went through at
	// all), and the site saw neither cookies nor the marker.
	resp = call(true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("marked call: %d", resp.StatusCode)
	}
	if last.cookie != "" {
		t.Errorf("marked call: site saw Cookie %q, want none", last.cookie)
	}
	if last.marker != "" {
		t.Errorf("marked call: the marker reached the site: %q", last.marker)
	}
	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("marked call: browser was given %q, want nothing — an omitted response sets no cookies", got)
	}
}

// Cookies a credential-less response sets are kept nowhere: not in the browser,
// and not in the jar either, where a domain-scoped one would otherwise go.
func TestOmittedResponseCookiesAreNotKept(t *testing.T) {
	h := New(Options{SessionCookie: "wvsid", Guard: &Guard{AllowPrivate: true}})
	target, _ := url.Parse("https://sso.corp.example/api")
	info := &reqInfo{target: target, jarKey: jarKey("session-1"), omitCookies: true}

	resp := &http.Response{Header: http.Header{}, Request: &http.Request{URL: target}}
	resp.Header.Add("Set-Cookie", "SSOSESSION=x; Domain=.corp.example; Path=/")
	resp.Header.Add("Set-Cookie", "local=y; Path=/")
	h.rewriteCookies(resp, info)

	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Errorf("browser was given %q", got)
	}
	app, _ := url.Parse("https://app.corp.example/")
	if jar := h.jars.lookup(info.jarKey); jar != nil {
		if pairs := jarPairs(jar, app, nil); len(pairs) != 0 {
			t.Errorf("the jar kept %v", pairs)
		}
	}
}

// The header name is written twice, once here and once in the shim; the two
// have to agree or the marker silently stops working.
func TestShimMarksOmittedRequestsWithTheGatewaysHeader(t *testing.T) {
	data, err := assetsFS.ReadFile("assets/shim.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"`+OmitCredentialsHeader+`"`) {
		t.Errorf("shim.js does not use %q", OmitCredentialsHeader)
	}
}
