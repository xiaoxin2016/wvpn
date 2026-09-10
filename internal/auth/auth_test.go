package auth

import (
	"encoding/json"
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
)

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, email string
		want           bool
	}{
		{"*", "a@b.com", true},
		{"*@test.com", "alice@test.com", true},
		{"*@test.com", "alice@other.com", false},
		{"alice@*", "alice@test.com", true},
		{"alice@test.com", "ALICE@TEST.COM", true},
		{"a?ice@test.com", "alice@test.com", true},
		{"a?ice@test.com", "alce@test.com", false},
		{"*@*.test.com", "a@dev.test.com", true},
		{"*@test.com", "alice@test.com.evil.net", false},
		{"", "a@b.com", false},
	}
	for _, tc := range cases {
		if got := MatchPattern(tc.pattern, tc.email); got != tc.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", tc.pattern, tc.email, got, tc.want)
		}
	}
}

func newStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := LoadStore(filepath.Join(t.TempDir(), "cfg.json"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStorePersistsAndReloads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.json")
	s, err := LoadStore(path, Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("defaults were not written out: %v", err)
	}
	if err := s.Set(Config{DefaultDomain: "corp.local", AllowedUsers: []string{"ops@corp.local"}, Admins: []string{"root@corp.local"}}); err != nil {
		t.Fatal(err)
	}
	again, err := LoadStore(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	got := again.Get()
	if got.DefaultDomain != "corp.local" || len(got.AllowedUsers) != 1 || got.Admins[0] != "root@corp.local" {
		t.Fatalf("reloaded config = %+v", got)
	}
	if !again.IsAdmin("root@corp.local") || !again.Allowed("root@corp.local") {
		t.Error("admins should also be allowed to sign in")
	}
	if again.Allowed("nobody@corp.local") {
		t.Error("unlisted account was allowed")
	}
}

func TestStoreRejectsBadConfig(t *testing.T) {
	s := newStore(t, Config{})
	if err := s.Set(Config{DefaultDomain: "not a domain"}); err == nil {
		t.Error("invalid domain accepted")
	}
	if err := s.Set(Config{AllowedUsers: []string{"a b@test.com"}}); err == nil {
		t.Error("invalid pattern accepted")
	}
}

func TestNormalizeEmail(t *testing.T) {
	s := newStore(t, Config{DefaultDomain: "test.com"})
	got, err := s.NormalizeEmail("  Alice ")
	if err != nil || got != "alice@test.com" {
		t.Fatalf("NormalizeEmail = %q, %v", got, err)
	}
	if _, err := s.NormalizeEmail("bob@other.com"); err != nil {
		t.Fatalf("full address rejected: %v", err)
	}
	for _, bad := range []string{"", "a b@test.com", "no-at-sign@", "x@@y"} {
		if _, err := s.NormalizeEmail(bad); err == nil {
			t.Errorf("NormalizeEmail(%q) accepted", bad)
		}
	}

	noDomain := newStore(t, Config{})
	if _, err := noDomain.NormalizeEmail("alice"); err == nil {
		t.Error("bare local part accepted without a default domain")
	}
}

// captureMailer records what would have been sent.
type captureMailer struct{ ch chan [3]string }

func (m captureMailer) Send(to, subject, body string) error {
	m.ch <- [3]string{to, subject, body}
	return nil
}

var codeRe = regexp.MustCompile(`\b(\d{6})\b`)

func newManager(t *testing.T, cfg Config) (*Manager, captureMailer) {
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
	jar := &simpleJar{}
	return srv, &http.Client{
		Jar:           jar,
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
	m, mailer := newManager(t, Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
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
	m, mailer := newManager(t, Config{DefaultDomain: "test.com", AllowedUsers: []string{"alice@test.com"}})
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
	m, mailer := newManager(t, Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
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
	m, mailer := newManager(t, Config{
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

	status, out := postJSON(t, client, srv.URL+"/admin/api/config", Config{
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
	status, out = postJSON(t, client, srv.URL+"/admin/api/config", Config{Admins: []string{"someone@else.com"}})
	if status == http.StatusOK {
		t.Errorf("self-lockout was allowed: %v", out)
	}
}

func TestNonAdminIsRefused(t *testing.T) {
	m, mailer := newManager(t, Config{
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
	status, _ := postJSON(t, client, srv.URL+"/admin/api/config", Config{})
	if status != http.StatusForbidden {
		t.Fatalf("admin API for a normal user: %d", status)
	}
}

func TestCrossOriginPostIsRefused(t *testing.T) {
	m, _ := newManager(t, Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
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
		Store:       newStore(t, Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}}),
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
	m, _ := newManager(t, Config{
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
