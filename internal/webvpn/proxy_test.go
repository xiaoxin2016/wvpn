package webvpn

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// originServer is a stand-in for the site behind the gateway.
func originServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// A value Go's own cookie writer would mangle, and a Secure flag the
		// gateway has to drop because this leg is plain HTTP.
		w.Header().Add("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly")
		w.Header().Add("Set-Cookie", "name=张三 与 空格; Path=/")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><head><title>o</title></head><body>`+
			`<a href="/page2">two</a><img src="img/x.png"></body></html>`)
	})

	mux.HandleFunc("/gz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Content-Encoding", "gzip")
		zw := gzip.NewWriter(w)
		defer zw.Close()
		io.WriteString(zw, `<html><head></head><body><a href="/deep/link">x</a></body></html>`)
	})

	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/page2?q=1", http.StatusFound)
	})

	mux.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		// The escape hatch no patch can intercept, written the way a login
		// script writes it.
		fmt.Fprintf(w, `location.href = "http://%s/next"; var cdn = "https://cdn.other.example/l.js";`, r.Host)
	})

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "referer="+r.Header.Get("Referer")+"\n")
		io.WriteString(w, "origin="+r.Header.Get("Origin")+"\n")
		io.WriteString(w, "cookie="+r.Header.Get("Cookie")+"\n")
		io.WriteString(w, "accept-encoding="+r.Header.Get("Accept-Encoding")+"\n")
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// gatewayFor wires a gateway that is allowed to reach the test origin.
func gatewayFor(t *testing.T, opts Options) (*httptest.Server, *http.Client) {
	t.Helper()
	if opts.Guard == nil {
		opts.Guard = &Guard{AllowPrivate: true}
	}
	gw := httptest.NewServer(New(opts))
	t.Cleanup(gw.Close)
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return gw, client
}

func get(t *testing.T, client *http.Client, url string, headers map[string]string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func originHost(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func TestProxyRewritesDocument(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, origin)

	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{
		`href="/p/http/` + host + `/page2"`,
		`src="/p/http/` + host + `/img/x.png"`,
		`<script src="/_wv/shim.js">`,
		`window.__WV__=`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q\n---\n%s", want, body)
		}
	}

	// The origin's cookie is re-scoped onto the gateway's path space, loses its
	// Domain, and drops Secure because this gateway is plain HTTP.
	cookies := resp.Header.Values("Set-Cookie")
	if len(cookies) != 2 {
		t.Fatalf("Set-Cookie headers = %q", cookies)
	}
	for _, sc := range cookies {
		if !strings.Contains(sc, "Path=/p/http/"+host+"/") {
			t.Errorf("cookie path not rewritten: %q", sc)
		}
		if strings.Contains(sc, "Domain=") || strings.Contains(sc, "Secure") {
			t.Errorf("cookie kept Domain or Secure over plain HTTP: %q", sc)
		}
	}
	// The payload has to survive byte for byte: Go's cookie parser would have
	// dropped this one outright.
	if !strings.Contains(cookies[1], "name=张三 与 空格") {
		t.Errorf("cookie value was mangled: %q", cookies[1])
	}
	if !strings.Contains(cookies[0], "HttpOnly") {
		t.Errorf("HttpOnly was lost: %q", cookies[0])
	}
}

func TestProxyRewritesGzippedBody(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, origin)

	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/gz", nil)
	if resp.Header.Get("Content-Encoding") != "" {
		t.Errorf("Content-Encoding survived rewriting: %q", resp.Header.Get("Content-Encoding"))
	}
	if !strings.Contains(body, `href="/p/http/`+host+`/deep/link"`) {
		t.Errorf("gzipped body was not rewritten: %s", body)
	}
}

func TestProxyRewritesRedirect(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, origin)

	resp, _ := get(t, client, gw.URL+"/p/http/"+host+"/redirect", nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "/p/http/"+host+"/page2?q=1"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestProxyTranslatesRefererAndStripsSessionCookie(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{SessionCookie: "wvsid"})
	host := originHost(t, origin)

	_, body := get(t, client, gw.URL+"/p/http/"+host+"/echo", map[string]string{
		"Referer": gw.URL + "/p/http/" + host + "/page1",
		"Origin":  gw.URL,
		"Cookie":  "wvsid=secret; app=keepme",
	})

	if !strings.Contains(body, "referer=http://"+host+"/page1") {
		t.Errorf("Referer not translated:\n%s", body)
	}
	if !strings.Contains(body, "origin=http://"+host) {
		t.Errorf("Origin not translated:\n%s", body)
	}
	if strings.Contains(body, "secret") {
		t.Errorf("gateway session cookie leaked upstream:\n%s", body)
	}
	if !strings.Contains(body, "app=keepme") {
		t.Errorf("origin cookie was dropped:\n%s", body)
	}
	if !strings.Contains(body, "accept-encoding=gzip") {
		t.Errorf("upstream Accept-Encoding was not normalised:\n%s", body)
	}
}

func TestProxyRefusesInternalTargetByDefault(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{Guard: &Guard{}})
	host := originHost(t, origin)

	resp, _ := get(t, client, gw.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a loopback target", resp.StatusCode)
	}
}

func TestGotoAndStrayRecovery(t *testing.T) {
	origin := originServer(t)
	gw, client := gatewayFor(t, Options{})
	host := originHost(t, origin)

	resp, _ := get(t, client, gw.URL+"/_wv/go?url="+url.QueryEscape("http://"+host+"/page2"), nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("goto status = %d", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "/p/http/"+host+"/page2"; got != want {
		t.Errorf("goto Location = %q, want %q", got, want)
	}

	// A root-relative URL that escaped rewriting is recovered from the Referer.
	resp, _ = get(t, client, gw.URL+"/late/xhr", map[string]string{
		"Referer": gw.URL + "/p/http/" + host + "/dir/page",
	})
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("stray status = %d", resp.StatusCode)
	}
	if got, want := resp.Header.Get("Location"), "/p/http/"+host+"/late/xhr"; got != want {
		t.Errorf("stray Location = %q, want %q", got, want)
	}
}

func TestPortalRenders(t *testing.T) {
	gw, client := gatewayFor(t, Options{Portal: Portal{
		Name: "测试网关",
		Categories: []Category{{
			Name:  "常用",
			Items: []Bookmark{{Name: "示例", URL: "https://example.com/a"}},
		}},
	}})
	resp, body := get(t, client, gw.URL+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	for _, want := range []string{"测试网关", "常用", `href="/p/https/example.com/a"`} {
		if !strings.Contains(body, want) {
			t.Errorf("portal missing %q", want)
		}
	}
	// A target opens in its own tab, so the portal stays where it is.
	if !strings.Contains(body, `id="jump" target="_blank"`) {
		t.Error("the address form does not open a new tab")
	}
	if !strings.Contains(body, `href="/p/https/example.com/a" target="_blank" rel="noopener"`) {
		t.Errorf("a bookmark does not open a new tab:\n%s", body)
	}
}

func TestShimIsServed(t *testing.T) {
	gw, client := gatewayFor(t, Options{})
	resp, body := get(t, client, gw.URL+shimPath, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(body, "__WV__") {
		t.Errorf("shim body looks wrong: %.120s", body)
	}
}

func TestSubdomainModeEndToEnd(t *testing.T) {
	origin := originServer(t)
	codec, err := NewHostCodec("gw.test", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	gw, client := gatewayFor(t, Options{Codec: codec})
	host := originHost(t, origin)

	// The plain path form is served on every gateway host, which is how a
	// target the label form cannot express stays reachable.
	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// Links come back in the sub-domain form, port and all.
	name, port, _ := strings.Cut(host, ":")
	want := "http://" + strings.ReplaceAll(name, ".", "-") + "-p" + port + ".gw.test/page2"
	if !strings.Contains(body, `href="`+want+`"`) {
		t.Errorf("subdomain rewriting wrong, want %q:\n%s", want, body)
	}
}

func TestProxyEnforcesSitePolicy(t *testing.T) {
	origin := originServer(t)
	host := originHost(t, origin)
	name, _, _ := strings.Cut(host, ":")

	// Denylist: the target is refused before a connection is attempted.
	denied, client := gatewayFor(t, Options{Guard: &Guard{
		AllowPrivate: true,
		Site:         fakeSite{hosts: map[string]Verdict{name: VerdictDeny}},
	}})
	resp, _ := get(t, client, denied.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("denylisted target: %d, want 403", resp.StatusCode)
	}

	// Allowlist: an unlisted target is refused, a listed one still works.
	gw, client := gatewayFor(t, Options{Guard: &Guard{
		AllowPrivate: true,
		Site:         fakeSite{allowlist: true, hosts: map[string]Verdict{name: VerdictAllow}},
	}})
	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allowlisted target: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "/p/http/"+host+"/page2") {
		t.Error("allowlisted target was not rewritten")
	}
	resp, _ = get(t, client, gw.URL+"/p/https/elsewhere.test/", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unlisted target: %d, want 403", resp.StatusCode)
	}
}

// fakeIdentity stands in for the auth layer.
type fakeIdentity struct {
	email string
	admin bool
}

func (f fakeIdentity) User(*http.Request) (string, bool, bool) { return f.email, f.admin, true }

func TestAdminBypassesSitePolicy(t *testing.T) {
	origin := originServer(t)
	host := originHost(t, origin)
	name, _, _ := strings.Cut(host, ":")
	site := fakeSite{hosts: map[string]Verdict{name: VerdictDeny}}

	user, client := gatewayFor(t, Options{
		Guard:    &Guard{AllowPrivate: true, Site: site},
		Identity: fakeIdentity{email: "alice@test.com"},
	})
	resp, _ := get(t, client, user.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("normal user reached a denylisted site: %d", resp.StatusCode)
	}

	admin, client := gatewayFor(t, Options{
		Guard:    &Guard{AllowPrivate: true, Site: site},
		Identity: fakeIdentity{email: "root@test.com", admin: true},
	})
	resp, body := get(t, client, admin.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin was blocked by the site policy: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "/p/http/"+host+"/page2") {
		t.Error("admin request was not rewritten")
	}

	// The command-line boundary is not a console setting, so it still binds.
	locked, client := gatewayFor(t, Options{
		Guard:    &Guard{AllowPrivate: true, DenyHosts: []string{name}, Site: site},
		Identity: fakeIdentity{email: "root@test.com", admin: true},
	})
	resp, _ = get(t, client, locked.URL+"/p/http/"+host+"/", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin bypassed the command-line denylist: %d", resp.StatusCode)
	}
}

func TestProxyRewritesScriptBodies(t *testing.T) {
	origin := originServer(t)
	host := originHost(t, origin)
	gw, client := gatewayFor(t, Options{JSScope: JSRelated})

	resp, body := get(t, client, gw.URL+"/p/http/"+host+"/app.js", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// An absolute address stays absolute: a script does arithmetic on the
	// strings it holds, and turning one into a path changes the answer.
	if !strings.Contains(body, `location.href = "`+gw.URL+`/p/http/`+host+`/next"`) {
		t.Errorf("script navigation was not rewritten absolutely: %s", body)
	}
	if !strings.Contains(body, `"https://cdn.other.example/l.js"`) {
		t.Errorf("an unrelated host was rewritten: %s", body)
	}

	// With script rewriting off, the body is passed through untouched.
	plain, client := gatewayFor(t, Options{})
	_, body = get(t, client, plain.URL+"/p/http/"+host+"/app.js", nil)
	if !strings.Contains(body, `location.href = "http://`+host+`/next"`) {
		t.Errorf("JSOff still rewrote the script: %s", body)
	}
}

func TestCodecCanChangeAtRuntime(t *testing.T) {
	origin := originServer(t)
	host := originHost(t, origin)

	// What the admin console does: swap the addressing scheme under a running
	// gateway.
	var current Codec = PlainCodec{}
	gw, client := gatewayFor(t, Options{CodecFor: func() Codec { return current }})

	_, body := get(t, client, gw.URL+"/p/http/"+host+"/", nil)
	if !strings.Contains(body, `href="/p/http/`+host+`/page2"`) {
		t.Fatalf("path form not in use: %s", body)
	}

	subdomain, err := NewHostCodec("app.intra.corp.com", "", "8080", false)
	if err != nil {
		t.Fatal(err)
	}
	current = subdomain

	name, port, _ := strings.Cut(host, ":")
	want := "http://" + strings.ReplaceAll(name, ".", "-") + "-p" + port + ".app.intra.corp.com:8080/page2"
	_, body = get(t, client, gw.URL+"/p/http/"+host+"/", nil)
	if !strings.Contains(body, `href="`+want+`"`) {
		t.Errorf("the new scheme did not take effect, want %q:\n%s", want, body)
	}
}
