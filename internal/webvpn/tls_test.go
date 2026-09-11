package webvpn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// tlsOrigin is an HTTPS site with a certificate no system root vouches for —
// the ordinary situation on an internal network.
func tlsOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><head></head><body><a href="/inner">inner</a></body></html>`)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func postForm(t *testing.T, client *http.Client, target string, form url.Values) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestUntrustedCertificateAsksThenRemembers(t *testing.T) {
	origin := tlsOrigin(t)
	host := originHost(t, origin)
	gw, client := gatewayFor(t, Options{})
	path := "/p/https/" + host + "/"
	fp := fingerprint(origin.Certificate())

	// A page load is answered with the interstitial, not a bare failure.
	resp, body := get(t, client, gw.URL+path, map[string]string{"Accept": "text/html"})
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	for _, want := range []string{"证书不受信任", fp, `action="/_wv/trust"`, `value="` + host + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("interstitial missing %q", want)
		}
	}

	// A sub-resource cannot render a page, so it fails plainly instead.
	resp, body = get(t, client, gw.URL+path, map[string]string{"Accept": "image/png"})
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(body, "<html") {
		t.Errorf("sub-resource got %d: %.60s", resp.StatusCode, body)
	}

	// A confirmation for a certificate the gateway never offered is refused.
	bad := postForm(t, client, gw.URL+trustPath, url.Values{
		"host": {host}, "fingerprint": {"AA:BB"}, "next": {path},
	})
	bad.Body.Close()
	if bad.StatusCode != http.StatusForbidden {
		t.Fatalf("forged confirmation: %d, want 403", bad.StatusCode)
	}

	// The real confirmation goes through, and the request then succeeds.
	ok := postForm(t, client, gw.URL+trustPath, url.Values{
		"host": {host}, "fingerprint": {fp}, "next": {path},
	})
	ok.Body.Close()
	if ok.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirmation: %d, want 303", ok.StatusCode)
	}
	if loc := ok.Header.Get("Location"); loc != path {
		t.Errorf("Location = %q, want %q", loc, path)
	}

	resp, body = get(t, client, gw.URL+path, map[string]string{"Accept": "text/html"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after confirmation: %d", resp.StatusCode)
	}
	if !strings.Contains(body, `href="/p/https/`+host+`/inner"`) {
		t.Errorf("body was not rewritten after confirmation: %s", body)
	}
}

func TestTrustIsPinnedToTheCertificate(t *testing.T) {
	first := tlsOrigin(t)
	host := originHost(t, first)
	gw, client := gatewayFor(t, Options{})
	path := "/p/https/" + host + "/"

	get(t, client, gw.URL+path, map[string]string{"Accept": "text/html"}) // offer
	resp := postForm(t, client, gw.URL+trustPath, url.Values{
		"host": {host}, "fingerprint": {fingerprint(first.Certificate())}, "next": {path},
	})
	resp.Body.Close()

	// A different certificate on the same host is not covered by the old
	// confirmation: the gateway asks again.
	handler := gw.Config.Handler.(*Handler)
	if handler.trust.trusted(host, "OTHER:FINGERPRINT") {
		t.Error("trust was granted to a certificate that was never confirmed")
	}
	if !handler.trust.trusted(host, fingerprint(first.Certificate())) {
		t.Error("the confirmed certificate is not trusted")
	}
}

func TestInsecureTLSSkipsTheQuestion(t *testing.T) {
	origin := tlsOrigin(t)
	host := originHost(t, origin)
	gw, client := gatewayFor(t, Options{InsecureTLS: true})

	resp, body := get(t, client, gw.URL+"/p/https/"+host+"/", map[string]string{"Accept": "text/html"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("with -insecure-tls: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "/p/https/"+host+"/inner") {
		t.Error("body was not rewritten")
	}
}

func TestSafeReturn(t *testing.T) {
	cases := []struct {
		next, gateway, want string
	}{
		{"/p/https/example.com/x", "gw.test:8080", "/p/https/example.com/x"},
		{"", "gw.test", "/"},
		{"//evil.test/x", "gw.test", "/"},
		{"https://evil.test/x", "oa.gw.test", "/"},
		{"http://oa-corp-local.gw.test/portal", "other.gw.test", "http://oa-corp-local.gw.test/portal"},
		{"javascript:alert(1)", "gw.test", "/"},
	}
	for _, tc := range cases {
		if got := safeReturn(tc.next, tc.gateway); got != tc.want {
			t.Errorf("safeReturn(%q, %q) = %q, want %q", tc.next, tc.gateway, got, tc.want)
		}
	}
}
