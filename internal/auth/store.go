// Package auth provides the gateway's identity layer: e-mail one-time-code
// login, server-side sessions, and a small admin surface for the default
// e-mail domain and the list of accounts allowed to sign in.
package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Config is the persisted, admin-editable part of the identity layer.
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
}

// Store holds Config and persists it as JSON.
type Store struct {
	path string
	mu   sync.RWMutex
	cfg  Config
}

// LoadStore reads path, falling back to def when the file does not exist yet.
// The defaults are written out so an operator has a file to edit.
func LoadStore(path string, def Config) (*Store, error) {
	s := &Store{path: path, cfg: normalizeConfig(def)}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var cfg Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("auth: parsing %s: %w", path, err)
		}
		s.cfg = normalizeConfig(cfg)
	case errors.Is(err, os.ErrNotExist):
		if path != "" {
			if err := s.save(); err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("auth: reading %s: %w", path, err)
	}
	return s, nil
}

func normalizeConfig(c Config) Config {
	c.DefaultDomain = strings.ToLower(strings.Trim(strings.TrimSpace(c.DefaultDomain), "@"))
	c.AllowedUsers = cleanPatterns(c.AllowedUsers)
	c.Admins = cleanPatterns(c.Admins)
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
	c := s.cfg
	c.AllowedUsers = append([]string(nil), c.AllowedUsers...)
	c.Admins = append([]string(nil), c.Admins...)
	return c
}

// Set validates, applies and persists a new configuration.
func (s *Store) Set(c Config) error {
	c = normalizeConfig(c)
	if c.DefaultDomain != "" && !domainRe.MatchString(c.DefaultDomain) {
		return fmt.Errorf("auth: %q is not a valid domain", c.DefaultDomain)
	}
	for _, p := range append(append([]string{}, c.AllowedUsers...), c.Admins...) {
		if !patternRe.MatchString(p) {
			return fmt.Errorf("auth: %q is not a valid address pattern", p)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg = c
	return s.save()
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
