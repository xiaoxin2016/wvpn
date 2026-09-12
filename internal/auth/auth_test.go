package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
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

func TestAdminEditsSSOPolicy(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)
	signIn(t, client, srv, mailer, "root")

	// Restoration is on everywhere until an operator narrows it.
	if !m.store.RestoresAddresses("anything.test") {
		t.Fatal("restoration should be on by default")
	}

	full := store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
		SSO:           store.SSO{Mode: store.RestoreHosts, Hosts: []string{"sso.corp.com"}},
	}
	status, out := postJSON(t, client, srv.URL+"/admin/api/config", full)
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("saving the SSO policy: %d %v", status, out)
	}
	if got := m.store.Get().SSO; got.Mode != store.RestoreHosts || len(got.Hosts) != 1 {
		t.Errorf("SSO policy not stored: %+v", got)
	}
	if !m.store.RestoresAddresses("sso.corp.com") || m.store.RestoresAddresses("oa.corp.com") {
		t.Error("the stored SSO policy is not in force")
	}

	// Naming no host at all would silently restore nowhere.
	bad := full
	bad.SSO = store.SSO{Mode: store.RestoreHosts}
	if status, _ = postJSON(t, client, srv.URL+"/admin/api/config", bad); status != http.StatusBadRequest {
		t.Errorf("an empty host list was accepted: %d", status)
	}
	if m.store.Get().SSO.Mode != store.RestoreHosts || len(m.store.Get().SSO.Hosts) != 1 {
		t.Error("a rejected save changed the stored policy")
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
		"tls_mode": "auto", "allow_plaintext_auth": false, "helo": "",
		"insecure_skip_verify": false, "clear_password": false, "password_set": false,
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
		"username": "gateway", "password": "", "tls_mode": "implicit",
		"allow_plaintext_auth": false, "helo": "", "insecure_skip_verify": false,
		"clear_password": false, "password_set": true,
	}); status != http.StatusOK {
		t.Fatalf("second save: %d %v", status, out)
	}
	got := m.store.Get().SMTP
	if got.Password != "s3cret" || got.Mode() != store.TLSImplicit || got.Addr != "smtp.example.com:465" {
		t.Fatalf("merge lost or mangled fields: %+v", got)
	}

	// Clearing is explicit.
	if status, out = post(map[string]any{
		"addr": "smtp.example.com:465", "from": "no-reply@example.com",
		"username": "gateway", "password": "", "tls_mode": "implicit",
		"allow_plaintext_auth": false, "helo": "", "insecure_skip_verify": false,
		"clear_password": true, "password_set": true,
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

// newSetupManager builds a gateway that has never been configured.
func newSetupManager(t *testing.T) (*Manager, captureMailer, string) {
	t.Helper()
	token, err := NewSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	mailer := captureMailer{ch: make(chan [3]string, 4)}
	m, err := New(Options{
		Store:      newStore(t, store.Config{}),
		Mailer:     mailer,
		Logger:     log.New(os.Stderr, "test ", 0),
		SetupToken: token,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	return m, mailer, token
}

func TestSetupFlow(t *testing.T) {
	m, mailer, token := newSetupManager(t)
	srv, client := newServer(t, m)

	if !m.NeedsSetup() || !m.SetupPending() {
		t.Fatal("a gateway with no administrator should need setup")
	}

	// Browsers are sent to setup rather than to a login page nobody can use.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("guard sent %d -> %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	body := map[string]any{
		"token":          "WRONG-TOKEN",
		"admin_email":    "ops@corp.example",
		"default_domain": "corp.example",
		"allowed_users":  []string{"*@corp.example"},
		"smtp": map[string]any{
			"addr": "smtp.corp.example:587", "from": "no-reply@corp.example",
			"username": "", "password": "", "tls_mode": "auto",
			"allow_plaintext_auth": false, "helo": "", "insecure_skip_verify": false,
			"clear_password": false, "password_set": false,
		},
	}
	if status, out := postJSON(t, client, srv.URL+"/setup", body); status != http.StatusForbidden {
		t.Fatalf("wrong token accepted: %d %v", status, out)
	}
	if len(m.store.Get().Admins) != 0 {
		t.Fatal("a rejected setup still wrote configuration")
	}

	body["token"] = token
	status, out := postJSON(t, client, srv.URL+"/setup", body)
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("setup: %d %v", status, out)
	}
	cfg := m.store.Get()
	if len(cfg.Admins) != 1 || cfg.Admins[0] != "ops@corp.example" {
		t.Fatalf("admins = %v", cfg.Admins)
	}
	if cfg.DefaultDomain != "corp.example" || cfg.SMTP.Addr != "smtp.corp.example:587" {
		t.Fatalf("config = %+v", cfg)
	}

	// The gateway is configured, so the login page must work — but the link
	// stays valid until someone actually gets in.
	if m.NeedsSetup() {
		t.Error("still diverting to setup after an administrator exists")
	}
	if !m.SetupPending() {
		t.Error("setup closed before anyone signed in; a broken SMTP server would lock everyone out")
	}

	signIn(t, client, srv, mailer, "ops@corp.example")
	if m.SetupPending() {
		t.Error("setup stayed open after the first administrator signed in")
	}
	if status, _ := postJSON(t, client, srv.URL+"/setup", body); status != http.StatusForbidden {
		t.Errorf("setup still accepted after completion: %d", status)
	}
}

func TestSetupIsOffWhenConfigured(t *testing.T) {
	m, _ := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	if m.SetupPending() || m.NeedsSetup() {
		t.Error("setup offered on an already configured gateway")
	}
}

func TestSetupTokensDiffer(t *testing.T) {
	a, err := NewSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewSetupToken()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("setup tokens repeat")
	}
	if len(a) != 27 { // 24 base32 characters in four groups
		t.Errorf("token %q has length %d", a, len(a))
	}
}

func TestClientIPBehindAProxy(t *testing.T) {
	m, _ := newManager(t, store.Config{})

	// nginx on the same host: the peer is loopback, so its headers are the
	// only source of the real address.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:5000"
	req.Header.Set("X-Real-IP", "203.0.113.9")
	if got := m.clientIP(req); got != "203.0.113.9" {
		t.Errorf("clientIP behind nginx = %q", got)
	}

	req.Header.Del("X-Real-IP")
	req.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	if got := m.clientIP(req); got != "203.0.113.9" {
		t.Errorf("clientIP from X-Forwarded-For = %q", got)
	}

	// A client that reaches the gateway directly cannot claim another address.
	direct := httptest.NewRequest(http.MethodGet, "/", nil)
	direct.RemoteAddr = "198.51.100.7:40000"
	direct.Header.Set("X-Real-IP", "127.0.0.1")
	if got := m.clientIP(direct); got != "198.51.100.7" {
		t.Errorf("a remote client spoofed its address: %q", got)
	}

	// Unless the operator says the headers can be believed from anywhere.
	m.opts.TrustProxyHeaders = true
	if got := m.clientIP(direct); got != "127.0.0.1" {
		t.Errorf("clientIP with -trust-proxy-headers = %q", got)
	}

	// With no headers at all, the peer stands.
	bare := httptest.NewRequest(http.MethodGet, "/", nil)
	bare.RemoteAddr = "127.0.0.1:5000"
	if got := m.clientIP(bare); got != "127.0.0.1" {
		t.Errorf("clientIP without headers = %q", got)
	}
}

func TestIdentityRoutesBelongToTheGatewayHost(t *testing.T) {
	mailer := captureMailer{ch: make(chan [3]string, 1)}
	m, err := New(Options{
		Store:  newStore(t, store.Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}}),
		Mailer: mailer,
		Logger: log.New(os.Stderr, "test ", 0),
		Site: func() SiteInfo {
			return SiteInfo{GatewayHost: "app.intra.corp.com", CookieDomain: ".app.intra.corp.com"}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)

	// Under the subdomain mode a proxied site keeps its own /login: the path
	// only belongs to the gateway on the gateway's own host.
	m.SetFallback(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "proxy")
		w.WriteHeader(http.StatusOK)
	}))

	mux := http.NewServeMux()
	m.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req := httptest.NewRequest(http.MethodGet, "http://oa-corp-local.app.intra.corp.com/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Header().Get("X-Served-By") != "proxy" {
		t.Errorf("/login on a proxied host was answered by the gateway: %d", rec.Code)
	}

	own := httptest.NewRequest(http.MethodGet, "http://app.intra.corp.com/login", nil)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, own)
	if rec.Header().Get("X-Served-By") == "proxy" {
		t.Error("/login on the gateway's own host was proxied away")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("sign-in page: %d", rec.Code)
	}

	// The session cookie follows the configured domain, which is what lets one
	// sign-in cover every proxied sub-domain.
	if got := m.cookie("x", time.Hour).Domain; got != ".app.intra.corp.com" {
		t.Errorf("cookie domain = %q", got)
	}
}

func TestAdminCertificate(t *testing.T) {
	m, mailer := newManager(t, store.Config{
		DefaultDomain: "test.com",
		AllowedUsers:  []string{"*@test.com"},
		Admins:        []string{"root@test.com"},
	})
	srv, client := newServer(t, m)
	signIn(t, client, srv, mailer, "root")

	cert, key := testKeyPair(t)
	base := map[string]any{
		"default_domain": "test.com",
		"allowed_users":  []string{"*@test.com"},
		"admins":         []string{"root@test.com"},
		"access":         map[string]any{"mode": "off", "sites": []string{}},
		"bookmarks":      []any{},
		"gateway":        map[string]any{"url_mode": "plain", "base_domain": "", "host": "", "public_port": ""},
		"smtp": map[string]any{
			"addr": "", "from": "", "username": "", "password": "", "tls_mode": "auto",
			"allow_plaintext_auth": false, "helo": "", "insecure_skip_verify": false,
			"clear_password": false, "password_set": false,
		},
	}
	post := func(tlsPart map[string]any) (int, map[string]any) {
		body := map[string]any{}
		for k, v := range base {
			body[k] = v
		}
		body["tls"] = tlsPart
		return postJSON(t, client, srv.URL+"/admin/api/config", body)
	}

	status, out := post(map[string]any{"cert": cert, "key": key, "clear": false, "key_set": false})
	if status != http.StatusOK || out["ok"] != true {
		t.Fatalf("saving the certificate: %d %v", status, out)
	}
	if got := m.store.Get().TLS; !got.Configured() {
		t.Fatal("certificate not stored")
	}

	// The key never comes back; the certificate and a summary do.
	resp, err := client.Get(srv.URL + "/admin/api/config")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Error("GET /admin/api/config leaked the private key")
	}
	for _, want := range []string{`"key_set":true`, "BEGIN CERTIFICATE", `*.intra.corp.com`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config view missing %q", want)
		}
	}

	// Saving with an empty key keeps the stored one.
	if status, out = post(map[string]any{"cert": cert, "key": "", "clear": false, "key_set": true}); status != http.StatusOK {
		t.Fatalf("second save: %d %v", status, out)
	}
	if !m.store.Get().TLS.Configured() {
		t.Error("the stored key was dropped by a save that did not mention it")
	}

	// A certificate without its matching key is refused.
	other, _ := testKeyPair(t)
	if status, _ = post(map[string]any{"cert": other, "key": key, "clear": false, "key_set": true}); status != http.StatusBadRequest {
		t.Errorf("a mismatched pair was accepted: %d", status)
	}

	// Clearing is explicit.
	if status, out = post(map[string]any{"cert": "", "key": "", "clear": true, "key_set": true}); status != http.StatusOK {
		t.Fatalf("clearing: %d %v", status, out)
	}
	if m.store.Get().TLS.Configured() {
		t.Error("the certificate survived an explicit clear")
	}
}

// testKeyPair issues a throwaway wildcard certificate.
func testKeyPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "*.intra.corp.com"},
		DNSNames:     []string{"*.intra.corp.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
