package webvpn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// ssoOrigin stands in for an identity provider: it accepts exactly one return
// address, the one registered for the real application, and rejects anything
// else — which is what a gateway address would be.
func ssoOrigin(t *testing.T, registered string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("redirect_uri"); got != registered {
			http.Error(w, "unregistered redirect_uri: "+got, http.StatusBadRequest)
			return
		}
		io.WriteString(w, "state="+r.URL.Query().Get("state"))
	})

	mux.HandleFunc("/saml", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if got := r.PostFormValue("RelayState"); got != registered {
			http.Error(w, "unregistered RelayState: "+got, http.StatusBadRequest)
			return
		}
		io.WriteString(w, "SAMLRequest="+r.PostFormValue("SAMLRequest"))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, client *http.Client, url, contentType, body string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(out)
}

func TestRestoresEncodedReturnAddress(t *testing.T) {
	const app = "http://app.corp.test/callback"
	sso := ssoOrigin(t, app)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, sso)

	// This is what the browser sends: the application built its redirect_uri
	// from a link the gateway had already rewritten.
	gateway := gw.URL + "/p/http/app.corp.test/callback"
	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/authorize"+
		"?redirect_uri="+url.QueryEscape(gateway)+"&state=xyz", nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	if body != "state=xyz" {
		t.Errorf("body = %q, want the state carried through untouched", body)
	}
}

func TestRestoresBareGatewayOriginFromReferer(t *testing.T) {
	const app = "http://app.corp.test"
	sso := ssoOrigin(t, app)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, sso)

	// location.origin on a proxied page is the gateway's own origin: under the
	// path codec it names no target at all, so the page the browser came from
	// is what it stands for.
	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/authorize"+
		"?redirect_uri="+url.QueryEscape(gw.URL)+"&state=s", map[string]string{
		"Referer": gw.URL + "/p/http/app.corp.test/home",
	})

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

func TestRestoresFormBody(t *testing.T) {
	const app = "http://app.corp.test/acs"
	sso := ssoOrigin(t, app)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, sso)

	gateway := gw.URL + "/p/http/app.corp.test/acs"
	form := "SAMLRequest=abc%3D%3D&RelayState=" + url.QueryEscape(gateway)
	resp, body := post(t, client, gw.URL+"/p/http/"+host+"/saml",
		"application/x-www-form-urlencoded", form, nil)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
	if body != "SAMLRequest=abc==" {
		t.Errorf("body = %q, want the other fields untouched", body)
	}
}

func TestRestoreCanBeTurnedOff(t *testing.T) {
	sso := ssoOrigin(t, "http://app.corp.test/callback")
	gw, client := gatewayFor(t, Options{
		RestoreFor: func(*url.URL) bool { return false },
	})
	host := originHost(t, sso)

	gateway := gw.URL + "/p/http/app.corp.test/callback"
	resp, _ := get(t, client, gw.URL+"/p/http/"+host+"/authorize"+
		"?redirect_uri="+url.QueryEscape(gateway), nil)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want the provider to see the gateway address", resp.StatusCode)
	}
}

func TestRestoreQueryForms(t *testing.T) {
	codec, err := NewHostCodec("intra.corp.com", "app.intra.corp.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	h := New(Options{Codec: codec})
	page, _ := url.Parse("https://soc.corp.com/home")

	cases := []struct {
		name, in, want string
	}{{
		name: "sub-domain form",
		in:   "redirect_uri=" + url.QueryEscape("https://soc-corp-com-s.intra.corp.com/cb"),
		want: "redirect_uri=" + url.QueryEscape("https://soc.corp.com/cb"),
	}, {
		name: "path form on the portal host",
		in:   "service=" + url.QueryEscape("https://app.intra.corp.com/p/https/soc.corp.com/cb"),
		want: "service=" + url.QueryEscape("https://soc.corp.com/cb"),
	}, {
		name: "bare portal origin stands for the page",
		in:   "redirect_uri=" + url.QueryEscape("https://app.intra.corp.com/cb"),
		want: "redirect_uri=" + url.QueryEscape("https://soc.corp.com/cb"),
	}, {
		name: "a target that is not the gateway is left alone",
		in:   "redirect_uri=" + url.QueryEscape("https://elsewhere.example/cb"),
		want: "redirect_uri=" + url.QueryEscape("https://elsewhere.example/cb"),
	}, {
		name: "names, order and unrelated values survive",
		in:   "a=1&redirect_uri=" + url.QueryEscape("https://soc-corp-com-s.intra.corp.com/cb") + "&b=%E4%B8%AD&flag",
		want: "a=1&redirect_uri=" + url.QueryEscape("https://soc.corp.com/cb") + "&b=%E4%B8%AD&flag",
	}, {
		name: "nothing to do",
		in:   "code=abc&state=1",
		want: "code=abc&state=1",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := h.restoreQuery(tc.in, page, "sso-corp-com-s.intra.corp.com")
			if got != tc.want {
				t.Errorf("restoreQuery(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// appOrigin stands in for the application the user actually wanted, and is the
// address the identity provider has on file.
func appOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<html><body>app</body></html>")
	}))
	t.Cleanup(srv.Close)
	return srv
}

// document is what a browser sends when it navigates to a new top-level page.
var document = map[string]string{
	"Sec-Fetch-Dest": "document",
	"Accept":         "text/html",
}

func TestRestoresWithoutARefererFromTheBrowsersTrail(t *testing.T) {
	app := appOrigin(t)
	sso := ssoOrigin(t, "http://"+originHost(t, app))
	gw, client := gatewayFor(t, Options{})

	// The browser opens the application, which is what a Referer would have
	// named had the site not suppressed it.
	resp, _ := get(t, client, gw.URL+"/p/http/"+originHost(t, app)+"/", document)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("opening the application: %d", resp.StatusCode)
	}

	// It then navigates to the provider carrying location.origin — the bare
	// gateway address — and no Referer at all.
	resp, body := get(t, client, gw.URL+"/p/http/"+originHost(t, sso)+"/authorize"+
		"?redirect_uri="+url.QueryEscape(gw.URL)+"&state=s", document)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %q", resp.StatusCode, body)
	}
}

func TestPageMemoryAttributesRequests(t *testing.T) {
	pages := newPageMemory()
	app, _ := url.Parse("http://app.corp.test/home")
	idp, _ := url.Parse("http://sso.corp.test/authorize")

	// The first document a browser opens has nothing behind it.
	if got := pages.record("b1", app, true); got != nil {
		t.Errorf("first navigation attributed to %v, want nothing", got)
	}
	// Anything that page fetches for itself belongs to that page.
	if got := pages.record("b1", idp, false); got == nil || got.Host != "app.corp.test" {
		t.Errorf("sub-resource attributed to %v, want the application", got)
	}
	// Navigating on is attributed to the page that started it.
	if got := pages.record("b1", idp, true); got == nil || got.Host != "app.corp.test" {
		t.Errorf("navigation attributed to %v, want the application", got)
	}
	// And the trail moves along with the browser.
	if got := pages.record("b1", app, true); got == nil || got.Host != "sso.corp.test" {
		t.Errorf("second navigation attributed to %v, want the provider", got)
	}
	// One browser's trail says nothing about another's.
	if got := pages.record("b2", idp, true); got != nil {
		t.Errorf("a second browser inherited %v", got)
	}
	// A browser that cannot be identified is not tracked at all.
	if got := pages.record("", app, true); got != nil {
		t.Errorf("an unkeyed request was attributed to %v", got)
	}
}

func TestPageMemoryForgetsIdleBrowsers(t *testing.T) {
	pages := newPageMemory()
	now := time.Now()
	pages.now = func() time.Time { return now }
	app, _ := url.Parse("http://app.corp.test/home")
	idp, _ := url.Parse("http://sso.corp.test/authorize")

	pages.record("b1", app, true)
	now = now.Add(pageIdleTTL + time.Minute)
	// The sweep runs when a browser is first seen, so a new one triggers it.
	pages.record("b2", app, true)
	if _, ok := pages.m["b1"]; ok {
		t.Error("an idle browser was kept")
	}
	if got := pages.record("b1", idp, true); got != nil {
		t.Errorf("a forgotten browser came back with %v", got)
	}
}

func TestDocumentRequests(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		method  string
		want    bool
	}{
		{"navigation", map[string]string{"Sec-Fetch-Dest": "document"}, "GET", true},
		{"fetch", map[string]string{"Sec-Fetch-Dest": "empty"}, "GET", false},
		{"image", map[string]string{"Sec-Fetch-Dest": "image"}, "GET", false},
		{"frame", map[string]string{"Sec-Fetch-Dest": "iframe"}, "GET", false},
		{"form post", map[string]string{"Sec-Fetch-Dest": "document"}, "POST", true},
		{"old browser navigating", map[string]string{"Accept": "text/html,*/*"}, "GET", true},
		{"old browser fetching", map[string]string{"Accept": "application/json"}, "GET", false},
		{"api call", map[string]string{"Accept": "text/html"}, "PUT", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := isDocumentRequest(r); got != tc.want {
				t.Errorf("isDocumentRequest = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStrayRecoveryWithoutAReferer(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, origin)

	// A browser that has not been seen cannot be attributed to anything.
	resp, _ := get(t, client, gw.URL+"/api/profile", map[string]string{
		"User-Agent": "unseen-browser",
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("an unattributable stray gave %d, want 404", resp.StatusCode)
	}

	// Once the browser is reading a page, a request that escaped rewriting is
	// recovered from that page even with the Referer suppressed.
	if resp, _ = get(t, client, gw.URL+"/p/http/"+host+"/", document); resp.StatusCode != http.StatusOK {
		t.Fatalf("opening the site: %d", resp.StatusCode)
	}
	resp, _ = get(t, client, gw.URL+"/api/profile", nil)
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("stray status = %d, want a redirect into the site", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "/p/http/"+host+"/api/profile"; got != want {
		t.Errorf("stray Location = %q, want %q", got, want)
	}

	// The Referer still wins when there is one: it names the page exactly.
	other := originServer(t)
	resp, _ = get(t, client, gw.URL+"/api/profile", map[string]string{
		"Referer": gw.URL + "/p/http/" + originHost(t, other) + "/dir/page",
	})
	if got, want := resp.Header.Get("Location"), "/p/http/"+originHost(t, other)+"/api/profile"; got != want {
		t.Errorf("with a Referer, Location = %q, want %q", got, want)
	}
}

func TestUnwrapsAGatewayPathFoldedIntoATarget(t *testing.T) {
	h := New(Options{Guard: &Guard{AllowPrivate: true}})

	cases := []struct {
		name, in, want string
	}{{
		// What a page produces from "my base path" + location.pathname.
		name: "the gateway folded into the middle",
		in:   "http://soc.corp.test/ZULXYAIK8642/p/http/soc.corp.test/",
		want: "http://soc.corp.test/ZULXYAIK8642/",
	}, {
		name: "with a path of its own after it",
		in:   "http://soc.corp.test/base/p/http/soc.corp.test/app/js/x.js",
		want: "http://soc.corp.test/base/app/js/x.js",
	}, {
		name: "folded in twice",
		in:   "http://soc.corp.test/a/p/http/soc.corp.test/b/p/http/soc.corp.test/c",
		want: "http://soc.corp.test/a/b/c",
	}, {
		name: "a reference to another host is left alone",
		in:   "http://soc.corp.test/base/p/http/elsewhere.test/x",
		want: "http://soc.corp.test/base/p/http/elsewhere.test/x",
	}, {
		name: "an ordinary path is left alone",
		in:   "http://soc.corp.test/base/app/js/x.js",
		want: "http://soc.corp.test/base/app/js/x.js",
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in, err := url.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := h.unwrapTarget(in).String(); got != tc.want {
				t.Errorf("unwrapTarget(%s) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestFoldedGatewayPathRedirectsTheBrowser(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, origin)

	// The browser has to be moved to the address the page meant, or what it
	// reads back about where it is stays wrong and every relative reference
	// on the page is measured from the wrong place.
	resp, _ := get(t, client, gw.URL+"/p/http/"+host+"/base/p/http/"+host+"/page2", document)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want a redirect", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "/p/http/"+host+"/base/page2"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}

	// A request that needs no repair is proxied, not redirected.
	resp, _ = get(t, client, gw.URL+"/p/http/"+host+"/", document)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("an ordinary request was disturbed: %d", resp.StatusCode)
	}
}
