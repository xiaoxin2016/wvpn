// Package store holds the gateway's persisted, admin-editable configuration:
// who may sign in, which sites they may reach through the proxy, and the links
// shown on the portal. It is the single JSON file an operator has to back up,
// and the single thing the admin console writes to.
package store

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Config is the whole persisted configuration. The JSON shape is flat and
// additive, so a file written by an older build still loads.
type Config struct {
	// DefaultDomain is appended when a user types only the local part of an
	// address, e.g. "test.com" turns "alice" into "alice@test.com".
	DefaultDomain string `json:"default_domain"`
	// AllowedUsers are glob patterns ("*@test.com", "alice@*", "*"). An empty
	// list denies everyone, which is the safe default for a gateway that can
	// reach an internal network.
	AllowedUsers []string `json:"allowed_users"`
	// Admins are glob patterns matched against the signed-in address; matching
	// accounts may open /admin.
	Admins []string `json:"admins"`
	// Access is the runtime site policy applied to every proxied request.
	Access Access `json:"access"`
	// Bookmarks are the grouped links shown on the portal.
	Bookmarks []Group `json:"bookmarks"`
	// SMTP is where verification codes are sent from. It overrides the
	// command-line SMTP flags once an address is set.
	SMTP SMTP `json:"smtp"`
	// Gateway is how target addresses are expressed in the browser.
	Gateway Gateway `json:"gateway"`
	// TLS is the certificate the gateway serves to browsers.
	TLS TLS `json:"tls"`
	// SSO governs putting real addresses back into outbound requests.
	SSO SSO `json:"sso"`
}

// TLS is the gateway's own certificate and private key, both PEM encoded. A
// sub-domain deployment needs a wildcard certificate for the domain targets are
// addressed under, so it is configured here rather than only as files on disk.
//
// The key is stored as written, in the same 0600 file as everything else.
type TLS struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

// Configured reports whether both halves are present.
func (t TLS) Configured() bool { return t.Cert != "" && t.Key != "" }

// Certificate parses the pair, which is also how it is validated.
func (t TLS) Certificate() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(t.Cert), []byte(t.Key))
}

// CertSummary is what the console shows about a configured certificate: enough
// to tell whether it is the right one and whether it is still valid.
type CertSummary struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Expired   bool     `json:"expired"`
}

// Summary parses the certificate for display.
func (t TLS) Summary() (CertSummary, error) {
	pair, err := t.Certificate()
	if err != nil {
		return CertSummary{}, err
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return CertSummary{}, err
		}
	}
	now := time.Now()
	return CertSummary{
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		DNSNames:  leaf.DNSNames,
		NotBefore: leaf.NotBefore.Local().Format("2006-01-02 15:04"),
		NotAfter:  leaf.NotAfter.Local().Format("2006-01-02 15:04"),
		Expired:   now.After(leaf.NotAfter) || now.Before(leaf.NotBefore),
	}, nil
}

// URL modes. See the Codec implementations in the webvpn package.
const (
	// URLPlain keeps the target visible in the path.
	URLPlain = "plain"
	// URLWRD hides the host in an encrypted path segment.
	URLWRD = "wrd"
	// URLSubdomain gives every target its own sub-domain of BaseDomain, which
	// is the only mode where each site gets its own browser origin.
	URLSubdomain = "subdomain"
)

// Gateway is the admin-editable half of how the gateway addresses targets.
type Gateway struct {
	// URLMode is one of URLPlain, URLWRD or URLSubdomain.
	URLMode string `json:"url_mode"`
	// BaseDomain is the wildcard domain targets are addressed under, e.g.
	// "intra.corp.com" with *.intra.corp.com pointed at the gateway.
	BaseDomain string `json:"base_domain"`
	// Host is where the portal, sign-in and admin pages live. It is normally a
	// name inside BaseDomain, and defaults to "app." + BaseDomain.
	Host string `json:"host"`
	// PublicPort is the port browsers reach the gateway on, when it is not the
	// default for the scheme.
	PublicPort string `json:"public_port"`
	// PublicScheme is what browsers reach the gateway with, which is not what
	// this process serves wherever TLS is terminated in front of it. SchemeAuto
	// reads it from each request, which needs the proxy in front to pass
	// X-Forwarded-Proto; SchemeHTTPS says so outright.
	PublicScheme string `json:"public_scheme"`
}

// Public scheme settings.
const (
	// SchemeAuto reads the browser's scheme off each request.
	SchemeAuto = "auto"
	// SchemeHTTPS declares every browser leg to be TLS.
	SchemeHTTPS = "https"
)

// DefaultHostLabel is the first label of the portal's own name when none is
// configured: with a wildcard on intra.corp.com the portal is app.intra.corp.com.
const DefaultHostLabel = "app"

// PortalHost returns the name the portal answers on, which is derived from the
// wildcard domain unless it was set explicitly.
func (g Gateway) PortalHost() string {
	if g.Host != "" {
		return g.Host
	}
	if g.BaseDomain == "" {
		return ""
	}
	return DefaultHostLabel + "." + g.BaseDomain
}

// Mode returns the configured URL mode, defaulting to plain.
func (g Gateway) Mode() string {
	switch g.URLMode {
	case URLPlain, URLWRD, URLSubdomain:
		return g.URLMode
	}
	return URLPlain
}

// TLS modes for a mail submission service.
const (
	// TLSAuto upgrades with STARTTLS when the server offers it, and stays in
	// the clear when it does not. This is what an internal relay on port 25
	// usually needs.
	TLSAuto = "auto"
	// TLSRequire refuses to send unless STARTTLS succeeds.
	TLSRequire = "require"
	// TLSNone never upgrades, even if the server offers it.
	TLSNone = "none"
	// TLSImplicit dials TLS directly, as port 465 expects.
	TLSImplicit = "implicit"
)

// SMTP is the mail submission service used for verification codes.
//
// Password is stored as written, in the same 0600 JSON file as the rest of the
// configuration: there is nowhere to put a key that would make encrypting it
// meaningful on a single host. Give the gateway its own submission account or
// an app password, not a mailbox that matters.
type SMTP struct {
	// Addr is host:port, e.g. smtp.example.com:587 or an internal relay on :25.
	Addr string `json:"addr"`
	// From is the envelope sender and the From: header.
	From string `json:"from"`
	// Username and Password enable AUTH when set. An internal relay that
	// accepts mail from the gateway's address needs neither.
	Username string `json:"username"`
	Password string `json:"password"`
	// TLSMode is one of TLSAuto, TLSRequire, TLSNone or TLSImplicit.
	TLSMode string `json:"tls_mode"`
	// ImplicitTLS is the previous form of TLSMode == TLSImplicit. It is read
	// when TLSMode is empty so an older configuration file still works.
	ImplicitTLS bool `json:"implicit_tls,omitempty"`
	// AllowPlaintextAuth permits sending the password over a connection that
	// was never encrypted. Off by default, because that is what it sounds like.
	AllowPlaintextAuth bool `json:"allow_plaintext_auth"`
	// HELO overrides the name the gateway announces itself with. Some relays
	// reject the default.
	HELO string `json:"helo,omitempty"`
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// Mode returns the TLS mode to use, migrating the older implicit_tls field.
func (s SMTP) Mode() string {
	switch s.TLSMode {
	case TLSAuto, TLSRequire, TLSNone, TLSImplicit:
		return s.TLSMode
	}
	if s.ImplicitTLS {
		return TLSImplicit
	}
	return TLSAuto
}

// Configured reports whether the console has a usable SMTP service.
func (s SMTP) Configured() bool { return s.Addr != "" && s.From != "" }

// Access modes.
const (
	// AccessOff proxies anything the operator's own -allow/-deny flags and the
	// SSRF guard permit.
	AccessOff = "off"
	// AccessAllowlist proxies only what Sites matches.
	AccessAllowlist = "allowlist"
	// AccessDenylist proxies everything except what Sites matches.
	AccessDenylist = "denylist"
)

// Access is the admin-editable site policy. It is a second layer: the
// -allow/-deny flags given on the command line still apply on top of it, so an
// operator can set a hard boundary the console cannot widen.
type Access struct {
	Mode string `json:"mode"`
	// Sites holds host patterns ("oa.corp.local", "*.corp.local") and CIDR
	// blocks ("10.0.0.0/8"). Host patterns are matched against the target
	// hostname; CIDR blocks are matched against the address the resolver
	// returns, which is what makes them useful against a name that points
	// somewhere unexpected.
	Sites []string `json:"sites"`
}

// Restore modes.
const (
	// RestoreAll puts gateway addresses back into the parameters of every
	// proxied request. It is the default: a parameter naming the gateway is
	// never what an origin expects.
	RestoreAll = "all"
	// RestoreHosts restricts that to the targets Hosts matches, which is how
	// an operator confines it to the identity provider.
	RestoreHosts = "hosts"
	// RestoreOff leaves outbound parameters alone.
	RestoreOff = "off"
)

// SSO controls address restoration on the way out.
//
// Single sign-on hands the identity provider a redirect_uri saying where to
// return to, and an application derives that from where the browser is. Through
// the gateway that is the gateway's own address, which the provider compares
// against the callback registered for the real application and refuses. The
// gateway therefore reverses its own rewriting in outbound parameters, so the
// provider sees the address it has on file.
type SSO struct {
	// Mode is RestoreAll, RestoreHosts or RestoreOff.
	Mode string `json:"mode"`
	// Hosts are host patterns ("sso.corp.com", "*.corp.com") naming the
	// targets restoration applies to when Mode is RestoreHosts.
	Hosts []string `json:"hosts"`
}

// Bookmark is one link on the portal.
type Bookmark struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Note string `json:"note,omitempty"`
}

// Group is a titled set of bookmarks.
type Group struct {
	Name  string     `json:"name"`
	Items []Bookmark `json:"items"`
}

// Store holds Config and persists it as JSON. It is safe for concurrent use:
// the proxy reads the site policy on every request while an admin may be
// rewriting it.
type Store struct {
	path  string
	mu    sync.RWMutex
	cfg   Config
	rules siteRules
	// sso is the parsed form of SSO.Hosts, read on every proxied request.
	sso siteRules
}

// LoadStore reads path, falling back to def when the file does not exist yet.
// The defaults are written out so an operator has a file to edit.
func LoadStore(path string, def Config) (*Store, error) {
	s := &Store{path: path, cfg: normalizeConfig(def)}
	defer func() {
		s.rules, _ = parseSites(s.cfg.Access.Sites)
		s.sso, _ = parseSites(s.cfg.SSO.Hosts)
	}()
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("store: parsing %s: %w", path, err)
		}
		s.cfg = normalizeConfig(cfg)
	case errors.Is(err, os.ErrNotExist):
		if path != "" {
			if err := s.save(); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("store: reading %s: %w", path, err)
	}
	return s, nil
}

func normalizeConfig(c Config) Config {
	c.DefaultDomain = strings.ToLower(strings.Trim(strings.TrimSpace(c.DefaultDomain), "@"))
	c.AllowedUsers = cleanPatterns(c.AllowedUsers)
	c.Admins = cleanPatterns(c.Admins)

	switch c.Access.Mode {
	case AccessAllowlist, AccessDenylist:
	default:
		c.Access.Mode = AccessOff
	}
	c.Access.Sites = cleanPatterns(c.Access.Sites)

	switch c.SSO.Mode {
	case RestoreHosts, RestoreOff:
	default:
		c.SSO.Mode = RestoreAll
	}
	c.SSO.Hosts = cleanPatterns(c.SSO.Hosts)

	groups := make([]Group, 0, len(c.Bookmarks))
	for _, g := range c.Bookmarks {
		g.Name = strings.TrimSpace(g.Name)
		items := make([]Bookmark, 0, len(g.Items))
		for _, it := range g.Items {
			it.Name = strings.TrimSpace(it.Name)
			it.URL = strings.TrimSpace(it.URL)
			it.Note = strings.TrimSpace(it.Note)
			if it.Name != "" && it.URL != "" {
				items = append(items, it)
			}
		}
		g.Items = items
		if g.Name != "" && len(items) > 0 {
			groups = append(groups, g)
		}
	}
	c.Bookmarks = groups

	// Not coerced to a default here: an unrecognised mode is a typo worth
	// rejecting, and Mode() supplies the default when the field is empty.
	c.Gateway.URLMode = strings.ToLower(strings.TrimSpace(c.Gateway.URLMode))
	c.Gateway.BaseDomain = strings.ToLower(strings.Trim(strings.TrimSpace(c.Gateway.BaseDomain), "."))
	c.Gateway.Host = strings.ToLower(strings.Trim(strings.TrimSpace(c.Gateway.Host), "."))
	c.Gateway.PublicPort = strings.TrimSpace(c.Gateway.PublicPort)
	switch strings.ToLower(strings.TrimSpace(c.Gateway.PublicScheme)) {
	case SchemeHTTPS:
		c.Gateway.PublicScheme = SchemeHTTPS
	default:
		c.Gateway.PublicScheme = SchemeAuto
	}

	c.TLS.Cert = strings.TrimSpace(c.TLS.Cert)
	c.TLS.Key = strings.TrimSpace(c.TLS.Key)

	c.SMTP.Addr = strings.TrimSpace(c.SMTP.Addr)
	c.SMTP.From = strings.TrimSpace(c.SMTP.From)
	c.SMTP.Username = strings.TrimSpace(c.SMTP.Username)
	c.SMTP.HELO = strings.TrimSpace(c.SMTP.HELO)
	// Collapse the legacy flag into the mode, so there is one source of truth.
	c.SMTP.TLSMode = c.SMTP.Mode()
	c.SMTP.ImplicitTLS = false
	return c
}

func cleanPatterns(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, p := range in {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// Get returns a copy of the current configuration.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.clone()
}

// clone returns a deep copy, so a caller cannot mutate what the store holds.
func (c Config) clone() Config {
	c.AllowedUsers = append([]string(nil), c.AllowedUsers...)
	c.Admins = append([]string(nil), c.Admins...)
	c.Access.Sites = append([]string(nil), c.Access.Sites...)
	c.SSO.Hosts = append([]string(nil), c.SSO.Hosts...)
	groups := make([]Group, len(c.Bookmarks))
	copy(groups, c.Bookmarks)
	for i := range groups {
		groups[i].Items = append([]Bookmark(nil), groups[i].Items...)
	}
	c.Bookmarks = groups

	// Not coerced to a default here: an unrecognised mode is a typo worth
	// rejecting, and Mode() supplies the default when the field is empty.
	c.Gateway.URLMode = strings.ToLower(strings.TrimSpace(c.Gateway.URLMode))
	c.Gateway.BaseDomain = strings.ToLower(strings.Trim(strings.TrimSpace(c.Gateway.BaseDomain), "."))
	c.Gateway.Host = strings.ToLower(strings.Trim(strings.TrimSpace(c.Gateway.Host), "."))
	c.Gateway.PublicPort = strings.TrimSpace(c.Gateway.PublicPort)
	switch strings.ToLower(strings.TrimSpace(c.Gateway.PublicScheme)) {
	case SchemeHTTPS:
		c.Gateway.PublicScheme = SchemeHTTPS
	default:
		c.Gateway.PublicScheme = SchemeAuto
	}

	c.TLS.Cert = strings.TrimSpace(c.TLS.Cert)
	c.TLS.Key = strings.TrimSpace(c.TLS.Key)

	c.SMTP.Addr = strings.TrimSpace(c.SMTP.Addr)
	c.SMTP.From = strings.TrimSpace(c.SMTP.From)
	c.SMTP.Username = strings.TrimSpace(c.SMTP.Username)
	c.SMTP.HELO = strings.TrimSpace(c.SMTP.HELO)
	// Collapse the legacy flag into the mode, so there is one source of truth.
	c.SMTP.TLSMode = c.SMTP.Mode()
	c.SMTP.ImplicitTLS = false
	return c
}

// Set validates, applies and persists a new configuration.
func (s *Store) Set(c Config) error {
	c = normalizeConfig(c)
	if err := Validate(c); err != nil {
		return err
	}
	rules, err := parseSites(c.Access.Sites)
	if err != nil {
		return err
	}
	sso, err := parseSites(c.SSO.Hosts)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.rules, s.sso = c, rules, sso
	return s.save()
}

// Validate reports the first problem with a configuration.
func Validate(c Config) error {
	if c.DefaultDomain != "" && !domainRe.MatchString(c.DefaultDomain) {
		return fmt.Errorf("%q 不是合法的域名", c.DefaultDomain)
	}
	for _, p := range append(append([]string{}, c.AllowedUsers...), c.Admins...) {
		if !patternRe.MatchString(p) {
			return fmt.Errorf("%q 不是合法的账号匹配式", p)
		}
	}
	if _, err := parseSites(c.Access.Sites); err != nil {
		return err
	}
	if c.Access.Mode == AccessAllowlist && len(c.Access.Sites) == 0 {
		return fmt.Errorf("白名单模式下站点清单不能为空，否则将无法访问任何站点")
	}
	if _, err := parseSites(c.SSO.Hosts); err != nil {
		return err
	}
	if c.SSO.Mode == RestoreHosts && len(c.SSO.Hosts) == 0 {
		return fmt.Errorf("按域名生效时 SSO 域名清单不能为空")
	}
	for _, g := range c.Bookmarks {
		for _, it := range g.Items {
			if err := validateBookmarkURL(it.URL); err != nil {
				return fmt.Errorf("书签 %q: %w", it.Name, err)
			}
		}
	}
	if err := validateGateway(c.Gateway); err != nil {
		return err
	}
	if err := validateTLS(c.TLS); err != nil {
		return err
	}
	return validateSMTP(c.SMTP)
}

func validateGateway(g Gateway) error {
	switch g.URLMode {
	case "", URLPlain, URLWRD, URLSubdomain:
	default:
		return fmt.Errorf("未知的 URL 模式 %q", g.URLMode)
	}
	if g.BaseDomain != "" {
		if !domainRe.MatchString(g.BaseDomain) {
			return fmt.Errorf("网关域名 %q 不是合法的域名", g.BaseDomain)
		}
		if !strings.Contains(g.BaseDomain, ".") {
			return fmt.Errorf("网关域名需要是完整域名，例如 app.intra.corp.com")
		}
	}
	if g.Host != "" {
		if !domainRe.MatchString(g.Host) || !strings.Contains(g.Host, ".") {
			return fmt.Errorf("门户主机名 %q 不是合法的域名", g.Host)
		}
		if g.BaseDomain != "" && g.Host != g.BaseDomain && !strings.HasSuffix(g.Host, "."+g.BaseDomain) {
			return fmt.Errorf("门户主机名 %q 需要位于泛域名 %q 之内", g.Host, g.BaseDomain)
		}
	}
	if g.Mode() == URLSubdomain && g.BaseDomain == "" {
		return fmt.Errorf("子域名模式需要填写泛域名（并把 *.该域名 解析到网关）")
	}
	if g.PublicPort != "" {
		n, err := strconv.Atoi(g.PublicPort)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("对外端口 %q 不合法", g.PublicPort)
		}
	}
	return nil
}

func validateTLS(t TLS) error {
	switch {
	case t.Cert == "" && t.Key == "":
		return nil
	case t.Cert == "":
		return fmt.Errorf("只填写了私钥，还需要证书")
	case t.Key == "":
		return fmt.Errorf("只填写了证书，还需要私钥")
	}
	if _, err := t.Certificate(); err != nil {
		return fmt.Errorf("证书与私钥不可用: %w", err)
	}
	return nil
}

func validateSMTP(s SMTP) error {
	if s.Addr == "" && s.From == "" && s.Username == "" && s.Password == "" {
		return nil
	}
	if s.Addr == "" {
		return fmt.Errorf("SMTP 服务器地址不能为空")
	}
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("SMTP 服务器需要写成 host:port，例如 smtp.example.com:587")
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("SMTP 端口 %q 不合法", port)
	}
	switch s.TLSMode {
	case "", TLSAuto, TLSRequire, TLSNone, TLSImplicit:
	default:
		return fmt.Errorf("未知的 TLS 模式 %q", s.TLSMode)
	}
	if s.From == "" {
		return fmt.Errorf("发件人地址不能为空")
	}
	if addr, err := mail.ParseAddress(s.From); err != nil || addr.Address != s.From {
		return fmt.Errorf("发件人地址 %q 格式不正确", s.From)
	}
	return nil
}

func validateBookmarkURL(raw string) error {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q 不是合法的地址", raw)
	}
	switch u.Scheme {
	case "http", "https":
		return nil
	}
	return fmt.Errorf("%q 只支持 http 或 https", raw)
}

// save writes the config atomically. The caller holds the lock.
func (s *Store) save() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if dir := filepath.Dir(s.path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := s.path + ".tmp"
	// 0600: the file names everyone who may enter the network behind the gateway.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

var (
	domainRe  = regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$`)
	patternRe = regexp.MustCompile(`^[a-z0-9!#$%&'*+/=?^_` + "`" + `{|}~.\-@\[\]]+$`)
)

// NormalizeEmail turns what the user typed into a full address, applying the
// configured default domain to a bare local part.
func (s *Store) NormalizeEmail(input string) (string, error) {
	return s.NormalizeEmailWith(input, s.Get().DefaultDomain)
}

// NormalizeEmailWith is NormalizeEmail against a domain that is not (yet) the
// stored one, which the first-run setup form needs.
func (s *Store) NormalizeEmailWith(input, domain string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(input))
	if v == "" {
		return "", errors.New("请输入邮箱地址")
	}
	if !strings.Contains(v, "@") {
		domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "@"))
		if domain == "" {
			return "", errors.New("请输入完整邮箱地址")
		}
		v += "@" + domain
	}
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Address != v || len(v) > 254 {
		return "", errors.New("邮箱地址格式不正确")
	}
	return v, nil
}

// MatchPattern reports whether a glob pattern matches an address. "*" matches
// any run of characters and "?" a single one; matching is case-insensitive and
// anchored at both ends.
func MatchPattern(pattern, email string) bool {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	email = strings.ToLower(strings.TrimSpace(email))
	if pattern == "" || email == "" {
		return false
	}
	return globMatch(pattern, email)
}

// globMatch is an iterative wildcard matcher: linear in the common case and
// without the backtracking blowup a naive regexp translation invites.
func globMatch(pattern, s string) bool {
	var pi, si, star, mark int
	star = -1
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, mark = pi, si
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func matchAny(patterns []string, email string) bool {
	for _, p := range patterns {
		if MatchPattern(p, email) {
			return true
		}
	}
	return false
}

// Allowed reports whether an address may sign in.
func (s *Store) Allowed(email string) bool {
	c := s.Get()
	return matchAny(c.AllowedUsers, email) || matchAny(c.Admins, email)
}

// IsAdmin reports whether an address may open the admin page.
func (s *Store) IsAdmin(email string) bool {
	return matchAny(s.Get().Admins, email)
}

// ------------------------------------------------------------- site policy ---

// Verdict is what the site policy has to say about a target.
type Verdict int

const (
	// Neutral means the policy has no opinion yet: under a denylist that is a
	// pass, under an allowlist the decision moves to the resolved address.
	Neutral Verdict = iota
	// Allow means this target satisfies an allowlist.
	Allow
	// Deny means the target is refused outright.
	Deny
)

// siteRules is the parsed form of Access.Sites.
type siteRules struct {
	hosts []string
	nets  []netip.Prefix
}

func (r siteRules) empty() bool { return len(r.hosts) == 0 && len(r.nets) == 0 }

// parseSites splits the admin-entered list into host patterns and CIDR blocks,
// rejecting anything that is neither.
func parseSites(sites []string) (siteRules, error) {
	var r siteRules
	for _, raw := range sites {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			p, err := netip.ParsePrefix(entry)
			if err != nil {
				return siteRules{}, fmt.Errorf("%q 既不是主机匹配式也不是合法网段", raw)
			}
			r.nets = append(r.nets, p.Masked())
			continue
		}
		// A host pattern may carry wildcards; everything else must look like a
		// hostname or an IP literal.
		if !sitePatternRe.MatchString(entry) {
			return siteRules{}, fmt.Errorf("%q 不是合法的主机匹配式", raw)
		}
		r.hosts = append(r.hosts, entry)
	}
	return r, nil
}

var sitePatternRe = regexp.MustCompile(`^[a-z0-9*?._:\[\]-]+$`)

// hostMatchesSite reports whether a hostname matches one of the host patterns.
// A bare "example.com" also covers its sub-domains, which is what an operator
// means when they type a domain into the list.
func (r siteRules) matchHost(host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSuffix(host, "."), "[]"))
	for _, p := range r.hosts {
		if globMatch(p, host) {
			return true
		}
		if !strings.ContainsAny(p, "*?") && strings.HasSuffix(host, "."+strings.TrimPrefix(p, ".")) {
			return true
		}
	}
	// A literal IP target is settled by the CIDR entries.
	if addr, err := netip.ParseAddr(host); err == nil {
		return r.matchAddr(addr)
	}
	return false
}

func (r siteRules) matchAddr(addr netip.Addr) bool {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	for _, p := range r.nets {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// snapshot returns the mode and parsed rules under one lock.
func (s *Store) snapshot() (string, siteRules) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Access.Mode, s.rules
}

// RequiresMatch reports whether a target has to match the site list to be
// proxied at all, i.e. whether the allowlist is in force.
func (s *Store) RequiresMatch() bool {
	mode, _ := s.snapshot()
	return mode == AccessAllowlist
}

// HasAddrRules reports whether the site list contains CIDR entries.
func (s *Store) HasAddrRules() bool {
	_, rules := s.snapshot()
	return len(rules.nets) > 0
}

// HostVerdict applies the site policy to a target host, before DNS.
func (s *Store) HostVerdict(host string) Verdict {
	mode, rules := s.snapshot()
	if mode == AccessOff || rules.empty() {
		return Neutral
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	matched := rules.matchHost(host)
	switch {
	case mode == AccessDenylist && matched:
		return Deny
	case mode == AccessAllowlist && matched:
		return Allow
	}
	return Neutral
}

// AddrVerdict applies the site policy to an address the resolver returned. This
// is what makes a CIDR entry meaningful: the hostname alone cannot tell you
// which network it lands in.
func (s *Store) AddrVerdict(addr netip.Addr) Verdict {
	mode, rules := s.snapshot()
	if mode == AccessOff || len(rules.nets) == 0 {
		return Neutral
	}
	matched := rules.matchAddr(addr)
	switch {
	case mode == AccessDenylist && matched:
		return Deny
	case mode == AccessAllowlist && matched:
		return Allow
	}
	return Neutral
}

// RestoresAddresses reports whether outbound parameters aimed at this target
// should have gateway addresses put back to the real ones.
func (s *Store) RestoresAddresses(host string) bool {
	s.mu.RLock()
	mode, rules := s.cfg.SSO.Mode, s.sso
	s.mu.RUnlock()

	switch mode {
	case RestoreOff:
		return false
	case RestoreHosts:
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		return rules.matchHost(host)
	default:
		return true
	}
}

// PublicHTTPS reports whether browsers are declared to reach the gateway over
// https regardless of what this process itself serves.
func (s *Store) PublicHTTPS() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.Gateway.PublicScheme == SchemeHTTPS
}

// MatchAny reports whether any pattern matches the address.
func MatchAny(patterns []string, email string) bool { return matchAny(patterns, email) }

// CleanPatterns trims, lower-cases and de-duplicates a pattern list.
func CleanPatterns(in []string) []string { return cleanPatterns(in) }
