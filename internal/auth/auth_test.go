package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/xiaoxin2016/wvpn/internal/store"
)

func newStore(t *testing.T, cfg store.Config) *store.Store {
	t.Helper()
	s, err := store.LoadStore(filepath.Join(t.TempDir(), "cfg.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// captureMailer records what would have been sent.
type captureMailer struct{ ch chan [3]string }

func (m captureMailer) Send(to, subject, body string) error {
	m.ch <- [3]string{to, subject, body}
	return nil
}

var codeRe = regexp.MustCompile(`\b(\d{6})\b`)

func newManager(t *testing.T, cfg store.Config) (*Manager, captureMailer) {
	t.Helper()
	mailer := captureMailer{ch: make(chan [3]string, 4)}
	m, err := New(Options{
		Store:  newStore(t, cfg),
		Mailer: mailer,
		Logger: log.New(os.Stderr, "test ", 0),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, mailer
}

func newServer(t *testing.T, m *Manager) (*httptest.Server, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	m.Routes(mux)
	mux.Handle("/", m.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, _ := m.SessionFor(r)
		w.Write([]byte("hello " + s.Email))
	})))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, newClient()
}

// newClient is a browser with its own cookie jar.
func newClient() *http.Client {
	return &http.Client{
		Jar:           &simpleJar{},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func postJSON(t *testing.T, c *http.Client, url string, body any) (int, map[string]any) {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Post(url, "application/json", strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestSignInFlow(t *testing.T) {
	m, mailer := newManager(t, store.Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
	srv, client := newServer(t, m)

	// Unauthenticated browsers are sent to the sign-in page.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/secret", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?next=") {
		t.Fatalf("guard sent %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	status, out := postJSON(t, client, srv.URL+"/auth/code", map[string]string{"email": "alice"})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("code request: %d %v", status, out)
	}
	sent := <-mailer.ch
	if sent[0] != "alice@test.com" {
		t.Fatalf("code went to %q", sent[0])
	}
	if strings.Contains(sent[1]+sent[2], "WebVPN") {
		t.Errorf("mail names the product: %q / %q", sent[1], sent[2])
	}
	code := codeRe.FindStringSubmatch(sent[2])
	if code == nil {
		t.Fatalf("no code in mail body: %q", sent[2])
	}

	// A wrong code is rejected without disclosing anything.
	status, out = postJSON(t, client, srv.URL+"/auth/verify", map[string]string{"email": "alice", "code": "000000"})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong code accepted: %d %v", status, out)
	}

	status, out = postJSON(t, client, srv.URL+"/auth/verify", map[string]string{"email": "alice", "code": code[1], "next": "/secret"})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("verify: %d %v", status, out)
	}
	if out["redirect"] != "/secret" {
		t.Errorf("redirect = %v", out["redirect"])
	}

	resp, err = client.Get(srv.URL + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("signed-in request: %d", resp.StatusCode)
	}

	// The code is single use.
	status, _ = postJSON(t, client, srv.URL+"/auth/verify", map[string]string{"email": "alice", "code": code[1]})
	if status == http.StatusOK {
		t.Error("code was accepted twice")
	}
}

func TestUnlistedAccountGetsNoCode(t *testing.T) {
	m, mailer := newManager(t, store.Config{DefaultDomain: "test.com", AllowedUsers: []string{"alice@test.com"}})
	srv, client := newServer(t, m)

	status, out := postJSON(t, client, srv.URL+"/auth/code", map[string]string{"email": "mallory"})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("response differs for an unlisted account: %d %v", status, out)
	}
	select {
	case sent := <-mailer.ch:
		t.Fatalf("mail was sent to an unlisted account: %v", sent)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestResendIsThrottled(t *testing.T) {
	m, mailer := newManager(t, store.Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
	srv, client := newServer(t, m)

	postJSON(t, client, srv.URL+"/auth/code", map[string]string{"email": "alice"})
	<-mailer.ch
	_, out := postJSON(t, client, srv.URL+"/auth/code", map[string]string{"email": "alice"})
	if out["ok"] != true {
		t.Fatalf("throttled response should still look normal: %v", out)
	}
	select {
	case sent := <-mailer.ch:
		t.Fatalf("second code sent within the resend interval: %v", sent)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAdminAPI(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)

	signIn(t, client, srv, mailer, "root")

	resp, err := client.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin page: %d", resp.StatusCode)
	}

	status, out := postJSON(t, client, srv.URL+"/admin/api/config", store.Config{
		DefaultDomain: "corp.local",
		AllowedUsers:  []string{"*@corp.local"},
		Admins:        []string{"root@test.com"},
	})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("config update: %d %v", status, out)
	}
	if got := m.store.Get().DefaultDomain; got != "corp.local" {
		t.Errorf("default domain = %q", got)
	}

	// An admin cannot drop themselves from the admin list through the UI.
	status, out = postJSON(t, client, srv.URL+"/admin/api/config", store.Config{Admins: []string{"someone@else.com"}})
	if status == http.StatusOK {
		t.Errorf("self-lockout was allowed: %v", out)
	}
}

func TestNonAdminIsRefused(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)
	signIn(t, client, srv, mailer, "alice")

	resp, err := client.Get(srv.URL + "/admin")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("admin page for a normal user: %d", resp.StatusCode)
	}
	status, _ := postJSON(t, client, srv.URL+"/admin/api/config", store.Config{})
	if status != http.StatusForbidden {
		t.Fatalf("admin API for a normal user: %d", status)
	}
}

func TestCrossOriginPostIsRefused(t *testing.T) {
	m, _ := newManager(t, store.Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
	srv, client := newServer(t, m)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/auth/code", strings.NewReader(`{"email":"alice"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://evil.test")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin post: %d", resp.StatusCode)
	}
}

func signIn(t *testing.T, client *http.Client, srv *httptest.Server, mailer captureMailer, local string) {
	t.Helper()
	postJSON(t, client, srv.URL+"/auth/code", map[string]string{"email": local})
	sent := <-mailer.ch
	code := codeRe.FindStringSubmatch(sent[2])
	if code == nil {
		t.Fatalf("no code in %q", sent[2])
	}
	if status, out := postJSON(t, client, srv.URL+"/auth/verify", map[string]string{"email": local, "code": code[1]}); status != http.StatusOK {
		t.Fatalf("sign-in for %s failed: %d %v", local, status, out)
	}
}

// simpleJar is a minimal cookie jar: the test server is a single host.
type simpleJar struct{ cookies []*http.Cookie }

func (j *simpleJar) SetCookies(_ *url.URL, cookies []*http.Cookie) {
	for _, c := range cookies {
		replaced := false
		for i, existing := range j.cookies {
			if existing.Name == c.Name {
				j.cookies[i] = c
				replaced = true
			}
		}
		if !replaced {
			j.cookies = append(j.cookies, c)
		}
	}
}

func (j *simpleJar) Cookies(_ *url.URL) []*http.Cookie { return j.cookies }

func TestLoginRedirectAcrossHosts(t *testing.T) {
	mailer := captureMailer{ch: make(chan [3]string, 1)}
	m, err := New(Options{
		Store:       newStore(t, store.Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}}),
		Mailer:      mailer,
		Logger:      log.New(os.Stderr, "test ", 0),
		LoginOrigin: "http://gw.test:8080",
		NextDomain:  "gw.test",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)

	// A proxied host does not serve /login, so the guard has to bounce the
	// browser to the gateway's own host instead of looping on a relative path.
	req := httptest.NewRequest(http.MethodGet, "http://oa-corp-local.gw.test:8080/portal", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	m.Require(http.NotFoundHandler()).ServeHTTP(rec, req)

	loc := rec.Header().Get("Location")
	want := "http://gw.test:8080/login?next=" + url.QueryEscape("http://oa-corp-local.gw.test:8080/portal")
	if rec.Code != http.StatusFound || loc != want {
		t.Fatalf("redirect = %d %q, want 302 %q", rec.Code, loc, want)
	}

	if got := m.safeNext("http://oa-corp-local.gw.test:8080/portal"); got != "http://oa-corp-local.gw.test:8080/portal" {
		t.Errorf("safeNext dropped a gateway host: %q", got)
	}
	for _, bad := range []string{"https://evil.test/x", "//evil.test/x", "http://gw.test.evil.net/x", "javascript:alert(1)"} {
		if got := m.safeNext(bad); got != "http://gw.test:8080/" {
			t.Errorf("safeNext(%q) = %q, want the portal", bad, got)
		}
	}
	if got := m.safeNext("/secret"); got != "/secret" {
		t.Errorf("safeNext(/secret) = %q", got)
	}
}

func TestLoginPageRevealsNothing(t *testing.T) {
	m, _ := newManager(t, store.Config{
		DefaultDomain: "internal-corp.example",
		AllowedUsers:  []string{"*@internal-corp.example"},
	})
	srv, client := newServer(t, m)

	resp, err := client.Get(srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(body)

	// Neither the mail domain nor the product may be recoverable by fetching
	// the sign-in page.
	for _, leak := range []string{"internal-corp.example", "webvpn", "WebVPN", "wvpn"} {
		if strings.Contains(page, leak) {
			t.Errorf("sign-in page leaks %q", leak)
		}
	}
	if !strings.Contains(page, "user@domain.com") {
		t.Error("sign-in page lost its generic placeholder")
	}

	// Completing a bare user name still works, it is just never advertised.
	if got, err := m.store.NormalizeEmail("alice"); err != nil || got != "alice@internal-corp.example" {
		t.Fatalf("NormalizeEmail = %q, %v", got, err)
	}
}

func TestAdminEditsAccessPolicyAndBookmarks(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)
	signIn(t, client, srv, mailer, "root")

	full := store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
		Access: store.Access{
			Mode:  store.AccessDenylist,
			Sites: []string{"blocked.test", "10.0.0.0/8"},
		},
		Bookmarks: []store.Group{{
			Name:  "常用系统",
			Items: []store.Bookmark{{Name: "OA", URL: "http://oa.corp.local/", Note: "办公"}},
		}},
	}
	status, out := postJSON(t, client, srv.URL+"/admin/api/config", full)
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("saving access + bookmarks: %d %v", status, out)
	}

	got := m.store.Get()
	if got.Access.Mode != store.AccessDenylist || len(got.Access.Sites) != 2 {
		t.Errorf("access policy not stored: %+v", got.Access)
	}
	if len(got.Bookmarks) != 1 || got.Bookmarks[0].Items[0].Name != "OA" {
		t.Errorf("bookmarks not stored: %+v", got.Bookmarks)
	}
	// The policy is live: the proxy reads it through the same store.
	if got := m.store.HostVerdict("blocked.test"); got != store.Deny {
		t.Errorf("stored policy is not in force: %v", got)
	}

	// Invalid input is refused and leaves the stored policy alone.
	bad := full
	bad.Access = store.Access{Mode: store.AccessAllowlist, Sites: []string{"10.0.0.0/64"}}
	status, out = postJSON(t, client, srv.URL+"/admin/api/config", bad)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid CIDR accepted: %d %v", status, out)
	}
	if m.store.Get().Access.Mode != store.AccessDenylist {
		t.Error("a rejected save changed the stored policy")
	}

	// An empty allowlist would lock everyone out of every site.
	bad.Access = store.Access{Mode: store.AccessAllowlist}
	if status, _ = postJSON(t, client, srv.URL+"/admin/api/config", bad); status != http.StatusBadRequest {
		t.Errorf("empty allowlist accepted: %d", status)
	}
}

func TestAdminSMTPConfig(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)
	signIn(t, client, srv, mailer, "root")

	base := map[string]any{
		"default_domain": "test.com",
		"allowed_users":  []string{"*@test.com"},
		"admins":         []string{"root@test.com"},
		"access":         map[string]any{"mode": "off", "sites": []string{}},
		"bookmarks":      []any{},
	}
	post := func(smtp map[string]any) (int, map[string]any) {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body["smtp"] = smtp
		return postJSON(t, client, srv.URL+"/admin/api/config", body)
	}

	status, out := post(map[string]any{
		"addr": "smtp.example.com:587", "from": "no-reply@example.com",
		"username": "gateway", "password": "s3cret",
		"implicit_tls": false, "insecure_skip_verify": false,
		"clear_password": false, "password_set": false,
	})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("saving SMTP: %d %v", status, out)
	}
	if got := m.store.Get().SMTP.Password; got != "s3cret" {
		t.Fatalf("stored password = %q", got)
	}

	// The password must not come back out, in this response or a later read.
	if strings.Contains(fmt.Sprint(out), "s3cret") {
		t.Error("save response echoed the password")
	}
	resp, err := client.Get(srv.URL + "/admin/api/config")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "s3cret") {
		t.Errorf("GET /admin/api/config leaked the password: %s", raw)
	}
	if !strings.Contains(string(raw), `"password_set":true`) {
		t.Errorf("password_set missing from %s", raw)
	}

	// Saving with an empty password keeps the stored one.
	if status, out = post(map[string]any{
		"addr": "smtp.example.com:465", "from": "no-reply@example.com",
		"username": "gateway", "password": "", "implicit_tls": true,
		"insecure_skip_verify": false, "clear_password": false, "password_set": true,
	}); status != http.StatusOK {
		t.Fatalf("second save: %d %v", status, out)
	}
	got := m.store.Get().SMTP
	if got.Password != "s3cret" || !got.ImplicitTLS || got.Addr != "smtp.example.com:465" {
		t.Fatalf("merge lost or mangled fields: %+v", got)
	}

	// Clearing is explicit.
	if status, out = post(map[string]any{
		"addr": "smtp.example.com:465", "from": "no-reply@example.com",
		"username": "gateway", "password": "", "implicit_tls": true,
		"insecure_skip_verify": false, "clear_password": true, "password_set": true,
	}); status != http.StatusOK {
		t.Fatalf("clearing password: %d %v", status, out)
	}
	if got := m.store.Get().SMTP.Password; got != "" {
		t.Errorf("password survived an explicit clear: %q", got)
	}
}

func TestTestMailGoesOnlyToTheAdmin(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)
	signIn(t, client, srv, mailer, "root")

	status, out := postJSON(t, client, srv.URL+"/admin/api/smtp/test", map[string]any{})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("test mail: %d %v", status, out)
	}
	if out["sent_to"] != "root@test.com" {
		t.Errorf("sent_to = %v", out["sent_to"])
	}
	sent := <-mailer.ch
	if sent[0] != "root@test.com" {
		t.Errorf("test mail went to %q; the endpoint must not accept a recipient", sent[0])
	}

	// A normal user cannot reach it at all.
	other := newClient()
	signIn(t, other, srv, mailer, "alice")
	if status, _ = postJSON(t, other, srv.URL+"/admin/api/smtp/test", map[string]any{}); status != http.StatusForbidden {
		t.Errorf("non-admin test mail: %d, want 403", status)
	}
}
