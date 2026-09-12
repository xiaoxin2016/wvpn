package store

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
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
	path := filepath.Join(t.TempDir(), "cfg.json")
	s, err := LoadStore(path, Config{DefaultDomain: "test.com", AllowedUsers: []string{"*@test.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("defaults were not written out: %v", err)
	}
	err = s.Set(Config{
		DefaultDomain: "corp.local",
		AllowedUsers:  []string{"ops@corp.local"},
		Admins:        []string{"root@corp.local"},
		Access:        Access{Mode: AccessDenylist, Sites: []string{"evil.test", "10.0.0.0/8"}},
		Bookmarks: []Group{{Name: "常用", Items: []Bookmark{
			{Name: "OA", URL: "http://oa.corp.local/", Note: "办公"},
			{Name: "空条目会被丢弃", URL: ""},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}

	again, err := LoadStore(path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	got := again.Get()
	if got.DefaultDomain != "corp.local" || len(got.AllowedUsers) != 1 || got.Admins[0] != "root@corp.local" {
		t.Fatalf("reloaded identity = %+v", got)
	}
	if got.Access.Mode != AccessDenylist || len(got.Access.Sites) != 2 {
		t.Fatalf("reloaded access = %+v", got.Access)
	}
	if len(got.Bookmarks) != 1 || len(got.Bookmarks[0].Items) != 1 || got.Bookmarks[0].Items[0].Name != "OA" {
		t.Fatalf("reloaded bookmarks = %+v", got.Bookmarks)
	}
	if !again.IsAdmin("root@corp.local") || !again.Allowed("root@corp.local") {
		t.Error("admins should also be allowed to sign in")
	}
	if again.Allowed("nobody@corp.local") {
		t.Error("unlisted account was allowed")
	}
}

func TestGetReturnsACopy(t *testing.T) {
	s := newStore(t, Config{AllowedUsers: []string{"*@test.com"}, Access: Access{Mode: AccessDenylist, Sites: []string{"a.test"}}})
	got := s.Get()
	got.AllowedUsers[0] = "*@evil.test"
	got.Access.Sites[0] = "b.test"
	if s.Get().AllowedUsers[0] != "*@test.com" || s.Get().Access.Sites[0] != "a.test" {
		t.Error("Get handed out the store's own slices")
	}
}

func TestValidation(t *testing.T) {
	s := newStore(t, Config{})
	bad := []struct {
		name string
		cfg  Config
	}{
		{"domain", Config{DefaultDomain: "not a domain"}},
		{"pattern", Config{AllowedUsers: []string{"a b@test.com"}}},
		{"site", Config{Access: Access{Mode: AccessDenylist, Sites: []string{"a b c"}}}},
		{"cidr", Config{Access: Access{Mode: AccessDenylist, Sites: []string{"10.0.0.0/64"}}}},
		{"empty allowlist", Config{Access: Access{Mode: AccessAllowlist}}},
		{"bookmark scheme", Config{Bookmarks: []Group{{Name: "g", Items: []Bookmark{{Name: "x", URL: "ftp://a.test/"}}}}}},
	}
	for _, tc := range bad {
		if err := s.Set(tc.cfg); err == nil {
			t.Errorf("%s: invalid config accepted", tc.name)
		}
	}
	ok := Config{
		Access:    Access{Mode: AccessAllowlist, Sites: []string{"*.corp.local", "10.0.0.0/8", "oa.test"}},
		Bookmarks: []Group{{Name: "g", Items: []Bookmark{{Name: "x", URL: "oa.test/path"}}}},
	}
	if err := s.Set(ok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
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
	if _, err := newStore(t, Config{}).NormalizeEmail("alice"); err == nil {
		t.Error("bare local part accepted without a default domain")
	}
}

func TestSitePolicyDenylist(t *testing.T) {
	s := newStore(t, Config{Access: Access{
		Mode:  AccessDenylist,
		Sites: []string{"blocked.test", "*.ads.test", "10.0.0.0/8"},
	}})
	if !s.HasAddrRules() || s.RequiresMatch() {
		t.Fatal("denylist reported the wrong shape")
	}
	deny := []string{"blocked.test", "www.blocked.test", "x.ads.test", "10.1.2.3"}
	for _, h := range deny {
		if got := s.HostVerdict(h); got != Deny {
			t.Errorf("HostVerdict(%s) = %v, want Deny", h, got)
		}
	}
	for _, h := range []string{"ok.test", "notblocked.test", "8.8.8.8"} {
		if got := s.HostVerdict(h); got != Neutral {
			t.Errorf("HostVerdict(%s) = %v, want Neutral", h, got)
		}
	}
	// A name that resolves into a denied network is caught at dial time.
	if got := s.AddrVerdict(netip.MustParseAddr("10.4.5.6")); got != Deny {
		t.Errorf("AddrVerdict = %v, want Deny", got)
	}
	if got := s.AddrVerdict(netip.MustParseAddr("1.1.1.1")); got != Neutral {
		t.Errorf("AddrVerdict = %v, want Neutral", got)
	}
}

func TestSitePolicyAllowlist(t *testing.T) {
	s := newStore(t, Config{Access: Access{
		Mode:  AccessAllowlist,
		Sites: []string{"corp.local", "192.168.0.0/16"},
	}})
	if !s.RequiresMatch() {
		t.Fatal("allowlist not in force")
	}
	for _, h := range []string{"corp.local", "oa.corp.local", "192.168.3.4"} {
		if got := s.HostVerdict(h); got != Allow {
			t.Errorf("HostVerdict(%s) = %v, want Allow", h, got)
		}
	}
	if got := s.HostVerdict("example.com"); got != Neutral {
		t.Errorf("HostVerdict(example.com) = %v, want Neutral", got)
	}
	if got := s.AddrVerdict(netip.MustParseAddr("192.168.9.9")); got != Allow {
		t.Errorf("AddrVerdict = %v, want Allow", got)
	}
	// Port suffixes must not defeat the match.
	if got := s.HostVerdict("oa.corp.local:8443"); got != Allow {
		t.Errorf("HostVerdict with port = %v, want Allow", got)
	}
}

func TestSitePolicyOff(t *testing.T) {
	s := newStore(t, Config{Access: Access{Mode: AccessOff, Sites: []string{"blocked.test"}}})
	if got := s.HostVerdict("blocked.test"); got != Neutral {
		t.Errorf("a disabled policy still voted: %v", got)
	}
}

func TestSMTPValidation(t *testing.T) {
	s := newStore(t, Config{})
	bad := []struct {
		name string
		smtp SMTP
	}{
		{"no port", SMTP{Addr: "smtp.example.com", From: "a@b.com"}},
		{"bad port", SMTP{Addr: "smtp.example.com:0", From: "a@b.com"}},
		{"no from", SMTP{Addr: "smtp.example.com:587"}},
		{"bad from", SMTP{Addr: "smtp.example.com:587", From: "not an address"}},
		{"password without server", SMTP{Password: "x"}},
	}
	for _, tc := range bad {
		if err := s.Set(Config{SMTP: tc.smtp}); err == nil {
			t.Errorf("%s: accepted %+v", tc.name, tc.smtp)
		}
	}

	good := SMTP{Addr: "smtp.example.com:587", From: "no-reply@example.com", Username: "u", Password: "p"}
	if err := s.Set(Config{SMTP: good}); err != nil {
		t.Fatalf("valid SMTP rejected: %v", err)
	}
	if !s.Get().SMTP.Configured() {
		t.Error("Configured() = false for a complete service")
	}
	if (SMTP{Addr: "smtp.example.com:587"}).Configured() {
		t.Error("Configured() = true without a sender")
	}
	// An empty section stays valid: it just means "use the command line".
	if err := s.Set(Config{}); err != nil {
		t.Errorf("empty SMTP section rejected: %v", err)
	}
}

func TestGatewayValidation(t *testing.T) {
	s := newStore(t, Config{})
	bad := []struct {
		name string
		g    Gateway
	}{
		{"unknown mode", Gateway{URLMode: "magic"}},
		{"subdomain without a domain", Gateway{URLMode: URLSubdomain}},
		{"single label", Gateway{URLMode: URLSubdomain, BaseDomain: "gateway"}},
		{"not a domain", Gateway{URLMode: URLSubdomain, BaseDomain: "not a domain"}},
		{"bad port", Gateway{URLMode: URLPlain, PublicPort: "70000"}},
	}
	for _, tc := range bad {
		if err := s.Set(Config{Gateway: tc.g}); err == nil {
			t.Errorf("%s: accepted %+v", tc.name, tc.g)
		}
	}

	ok := Gateway{URLMode: URLSubdomain, BaseDomain: "App.Intra.Corp.com.", PublicPort: "8443"}
	if err := s.Set(Config{Gateway: ok}); err != nil {
		t.Fatalf("valid settings rejected: %v", err)
	}
	got := s.Get().Gateway
	if got.BaseDomain != "app.intra.corp.com" {
		t.Errorf("base domain not normalised: %q", got.BaseDomain)
	}
	if got.Mode() != URLSubdomain {
		t.Errorf("mode = %q", got.Mode())
	}
	// An empty mode means the default, not a broken configuration.
	if err := s.Set(Config{}); err != nil {
		t.Fatalf("empty gateway section rejected: %v", err)
	}
	if m := s.Get().Gateway.Mode(); m != URLPlain {
		t.Errorf("default mode = %q, want %q", m, URLPlain)
	}
}

func TestPortalHost(t *testing.T) {
	s := newStore(t, Config{})

	// The portal lives inside the wildcard domain, and defaults to app.<domain>.
	if err := s.Set(Config{Gateway: Gateway{URLMode: URLSubdomain, BaseDomain: "intra.corp.com"}}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get().Gateway.PortalHost(); got != "app.intra.corp.com" {
		t.Errorf("default portal host = %q", got)
	}

	if err := s.Set(Config{Gateway: Gateway{
		URLMode: URLSubdomain, BaseDomain: "intra.corp.com", Host: "webvpn.intra.corp.com",
	}}); err != nil {
		t.Fatal(err)
	}
	if got := s.Get().Gateway.PortalHost(); got != "webvpn.intra.corp.com" {
		t.Errorf("configured portal host = %q", got)
	}

	// A portal outside the wildcard domain would never be served.
	err := s.Set(Config{Gateway: Gateway{
		URLMode: URLSubdomain, BaseDomain: "intra.corp.com", Host: "portal.elsewhere.com",
	}})
	if err == nil {
		t.Error("a portal host outside the wildcard domain was accepted")
	}
}

func TestTLSValidation(t *testing.T) {
	s := newStore(t, Config{})
	cert, key := testKeyPair(t)

	for _, tc := range []struct {
		name string
		tls  TLS
	}{
		{"key only", TLS{Key: key}},
		{"cert only", TLS{Cert: cert}},
		{"not a pair", TLS{Cert: cert, Key: "-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----"}},
	} {
		if err := s.Set(Config{TLS: tc.tls}); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}

	if err := s.Set(Config{TLS: TLS{Cert: cert, Key: key}}); err != nil {
		t.Fatalf("a valid pair was rejected: %v", err)
	}
	got := s.Get().TLS
	if !got.Configured() {
		t.Fatal("Configured() = false for a stored pair")
	}
	summary, err := got.Summary()
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if len(summary.DNSNames) == 0 || summary.DNSNames[0] != "*.intra.corp.com" {
		t.Errorf("summary names = %v", summary.DNSNames)
	}
	if summary.Expired {
		t.Error("a freshly issued certificate reported as expired")
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
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "*.intra.corp.com"},
		DNSNames:     []string{"*.intra.corp.com", "intra.corp.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
}
