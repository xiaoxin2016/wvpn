package webvpn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
