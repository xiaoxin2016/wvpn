package webvpn

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

// Single sign-on works by setting one cookie for a whole domain — the identity
// provider sets it for .corp.example, and every site in that domain reads it
// back. The gateway serves all of those sites from one browser origin, where a
// domain attribute has nothing to widen to: path scoping is what keeps two
// proxied sites out of each other's cookies, and paths are per-site.
//
// So domain-scoped cookies are kept here instead of in the browser: one jar per
// signed-in browser, replayed to whichever proxied host the cookie's own domain
// rule covers. That is what makes a login at sso.corp.example count when the
// browser lands back on app.corp.example.

const (
	// jarIdleTTL discards a jar whose browser has not been seen for a while.
	jarIdleTTL = 12 * time.Hour
	// maxJars bounds the memory a busy gateway can accumulate.
	maxJars = 20000
)

type jarEntry struct {
	jar     *cookiejar.Jar
	touched time.Time
}

// sessionJars holds one cookie jar per signed-in browser.
type sessionJars struct {
	mu   sync.Mutex
	jars map[string]*jarEntry
	now  func() time.Time
}

func newSessionJars() *sessionJars {
	return &sessionJars{jars: map[string]*jarEntry{}, now: time.Now}
}

// jarKey derives a stable, non-reversible key from a session token, so the
// gateway does not keep a second copy of the token itself.
func jarKey(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:16])
}

// get returns the jar for a browser, creating it on first use.
func (s *sessionJars) get(key string) *cookiejar.Jar {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if e, ok := s.jars[key]; ok {
		e.touched = now
		return e.jar
	}
	s.sweepLocked(now)
	if len(s.jars) >= maxJars {
		return nil
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil
	}
	s.jars[key] = &jarEntry{jar: jar, touched: now}
	return jar
}

// lookup returns an existing jar without creating one.
func (s *sessionJars) lookup(key string) *cookiejar.Jar {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.jars[key]
	if !ok {
		return nil
	}
	e.touched = s.now()
	return e.jar
}

func (s *sessionJars) sweepLocked(now time.Time) {
	for k, e := range s.jars {
		if now.Sub(e.touched) > jarIdleTTL {
			delete(s.jars, k)
		}
	}
}

// pairs returns the cookies the jar holds for a target, as raw name=value text.
// Serialising by hand keeps values that Go's own cookie writer would mangle.
func jarPairs(jar *cookiejar.Jar, target *url.URL, taken map[string]bool) []string {
	if jar == nil {
		return nil
	}
	u := *target
	u.Scheme = httpScheme(target.Scheme)
	var pairs []string
	for _, c := range jar.Cookies(&u) {
		if taken[c.Name] {
			continue // the browser already sent one under this name
		}
		pairs = append(pairs, c.Name+"="+c.Value)
	}
	return pairs
}

// storeShared puts a domain-scoped cookie into the browser's jar.
func storeShared(jar *cookiejar.Jar, target *url.URL, cookies []*http.Cookie) {
	if jar == nil || len(cookies) == 0 {
		return
	}
	u := *target
	u.Scheme = httpScheme(target.Scheme)
	jar.SetCookies(&u, cookies)
}

// sessionKey reads the gateway's own session cookie out of a request and
// reduces it to a jar key.
func (h *Handler) sessionKey(r *http.Request) string {
	name := h.opts.SessionCookie
	if name == "" {
		return ""
	}
	for _, pair := range strings.Split(r.Header.Get("Cookie"), ";") {
		n, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if ok && strings.TrimSpace(n) == name {
			return jarKey(v)
		}
	}
	return ""
}
