// Package store holds the gateway's persisted, admin-editable configuration:
// who may sign in, which sites they may reach through the proxy, and the links
// shown on the portal. It is the single JSON file an operator has to back up,
// and the single thing the admin console writes to.
package store

import (
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
	"strings"
	"sync"
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
}

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
}

// LoadStore reads path, falling back to def when the file does not exist yet.
// The defaults are written out so an operator has a file to edit.
func LoadStore(path string, def Config) (*Store, error) {
	s := &Store{path: path, cfg: normalizeConfig(def)}
	defer func() { s.rules, _ = parseSites(s.cfg.Access.Sites) }()
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
	groups := make([]Group, len(c.Bookmarks))
	copy(groups, c.Bookmarks)
	for i := range groups {
		groups[i].Items = append([]Bookmark(nil), groups[i].Items...)
	}
	c.Bookmarks = groups
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg, s.rules = c, rules
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
	for _, g := range c.Bookmarks {
		for _, it := range g.Items {
			if err := validateBookmarkURL(it.URL); err != nil {
				return fmt.Errorf("书签 %q: %w", it.Name, err)
			}
		}
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
	v := strings.ToLower(strings.TrimSpace(input))
	if v == "" {
		return "", errors.New("请输入邮箱地址")
	}
	if !strings.Contains(v, "@") {
		domain := s.Get().DefaultDomain
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

// MatchAny reports whether any pattern matches the address.
func MatchAny(patterns []string, email string) bool { return matchAny(patterns, email) }

// CleanPatterns trims, lower-cases and de-duplicates a pattern list.
func CleanPatterns(in []string) []string { return cleanPatterns(in) }
