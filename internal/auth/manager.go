package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// sessionCookie is deliberately anonymous: the sign-in surface should not name
// the product behind it.
const sessionCookie = "wvsid"

// Options configures a Manager. Zero values fall back to the defaults below.
type Options struct {
	Store  *Store
	Mailer Mailer

	MailSubject string
	// MailBody is a text/template rendered with .Code, .Minutes and .Email.
	MailBody string

	SessionTTL     time.Duration // default 12h
	CodeTTL        time.Duration // default 5m
	ResendInterval time.Duration // default 60s
	MaxAttempts    int           // default 5

	// Secure marks the session cookie Secure; set it when the gateway is
	// served over TLS.
	Secure bool
	// CookieDomain widens the session cookie to a wildcard domain, which the
	// subdomain URL mode needs. Leave empty for host-only cookies.
	CookieDomain string
	// LoginOrigin is the absolute origin serving the sign-in page, e.g.
	// "https://webvpn.example.com". Set it when the gateway answers on more
	// than one host — under the subdomain URL mode a relative redirect would
	// send the browser to /login on a proxied host, where the route does not
	// exist, and the guard would bounce it forever.
	LoginOrigin string
	// NextDomain is the domain whose sub-domains may appear in an absolute
	// ?next= parameter. Everything else falls back to the portal.
	NextDomain string
	// TrustForwardedFor makes rate limiting read X-Forwarded-For. Only enable
	// it behind a reverse proxy you control.
	TrustForwardedFor bool

	Logger *log.Logger
	// Now is overridable for tests.
	Now func() time.Time
}

// Session is a signed-in browser.
type Session struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Admin     bool      `json:"admin"`
	Created   time.Time `json:"created"`
	Expires   time.Time `json:"expires"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`

	token string
}

type codeState struct {
	hash     [32]byte
	expires  time.Time
	sentAt   time.Time
	attempts int
}

// Manager owns sessions, pending codes and the HTTP surface for both.
type Manager struct {
	opts  Options
	store *Store
	log   *log.Logger

	mu       sync.Mutex
	sessions map[string]*Session // token -> session
	codes    map[string]*codeState
	ipHits   map[string][]time.Time

	tmplLogin *template.Template
	tmplAdmin *template.Template

	stop chan struct{}
	once sync.Once
}

// New builds a Manager and starts its janitor.
func New(opts Options) (*Manager, error) {
	if opts.Store == nil {
		return nil, errors.New("auth: Store is required")
	}
	if opts.Mailer == nil {
		return nil, errors.New("auth: Mailer is required")
	}
	if opts.SessionTTL <= 0 {
		opts.SessionTTL = 12 * time.Hour
	}
	if opts.CodeTTL <= 0 {
		opts.CodeTTL = 5 * time.Minute
	}
	if opts.ResendInterval <= 0 {
		opts.ResendInterval = 60 * time.Second
	}
	if opts.MaxAttempts <= 0 {
		opts.MaxAttempts = 5
	}
	if opts.MailSubject == "" {
		opts.MailSubject = "登录验证码 / Login verification code"
	}
	if opts.MailBody == "" {
		opts.MailBody = defaultMailBody
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	login, err := template.ParseFS(assetsFS, "assets/login.html")
	if err != nil {
		return nil, err
	}
	admin, err := template.ParseFS(assetsFS, "assets/admin.html")
	if err != nil {
		return nil, err
	}

	m := &Manager{
		opts:      opts,
		store:     opts.Store,
		log:       opts.Logger,
		sessions:  map[string]*Session{},
		codes:     map[string]*codeState{},
		ipHits:    map[string][]time.Time{},
		tmplLogin: login,
		tmplAdmin: admin,
		stop:      make(chan struct{}),
	}
	go m.janitor()
	return m, nil
}

const defaultMailBody = `验证码：{{.Code}}

有效期 {{.Minutes}} 分钟，请勿向任何人转发。
如果这不是您本人的操作，请忽略本邮件。

Your verification code is {{.Code}}. It expires in {{.Minutes}} minutes.
`

// Close stops the janitor.
func (m *Manager) Close() { m.once.Do(func() { close(m.stop) }) }

func (m *Manager) now() time.Time { return m.opts.Now() }

func (m *Manager) janitor() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-t.C:
			m.sweep()
		}
	}
}

func (m *Manager) sweep() {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for tok, s := range m.sessions {
		if now.After(s.Expires) {
			delete(m.sessions, tok)
		}
	}
	for email, c := range m.codes {
		if now.After(c.expires) {
			delete(m.codes, email)
		}
	}
	for ip, hits := range m.ipHits {
		if kept := trimHits(hits, now.Add(-rateWindow)); len(kept) == 0 {
			delete(m.ipHits, ip)
		} else {
			m.ipHits[ip] = kept
		}
	}
}

// CookieName is the name of the session cookie, which the proxy must strip from
// upstream requests.
func (m *Manager) CookieName() string { return sessionCookie }

// Routes registers the identity endpoints. Everything else is expected to be
// wrapped in Require.
//
// hosts scopes the routes to specific Host header values. Leave it empty for a
// single-host deployment; pass the gateway's own names under the subdomain URL
// mode, where an unscoped /login would shadow the /login page of every proxied
// site.
func (m *Manager) Routes(mux *http.ServeMux, hosts ...string) {
	if len(hosts) == 0 {
		hosts = []string{""}
	}
	for _, host := range hosts {
		mux.HandleFunc("GET "+host+"/login", m.handleLoginPage)
		mux.HandleFunc("POST "+host+"/auth/code", m.handleRequestCode)
		mux.HandleFunc("POST "+host+"/auth/verify", m.handleVerify)
		mux.HandleFunc(host+"/logout", m.handleLogout)
		mux.HandleFunc("GET "+host+"/admin", m.handleAdminPage)
		mux.HandleFunc("GET "+host+"/admin/api/config", m.requireAdminAPI(m.handleGetConfig))
		mux.HandleFunc("POST "+host+"/admin/api/config", m.requireAdminAPI(m.handleSetConfig))
		mux.HandleFunc("GET "+host+"/admin/api/sessions", m.requireAdminAPI(m.handleListSessions))
		mux.HandleFunc("POST "+host+"/admin/api/sessions/revoke", m.requireAdminAPI(m.handleRevokeSession))
	}
}

// Require rejects unauthenticated requests: browsers are sent to the sign-in
// page, everything else gets a 401.
func (m *Manager) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := m.SessionFor(r); ok {
			next.ServeHTTP(w, r)
			return
		}
		if wantsHTML(r) {
			http.Redirect(w, r, m.loginURL(r), http.StatusFound)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthenticated"})
	})
}

func wantsHTML(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		return dest == "document" || dest == "iframe" || dest == "frame"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// SessionFor returns the session attached to a request, if any. Several cookies
// may carry the session name — a proxied origin is free to set one — so every
// candidate is tried.
func (m *Manager) SessionFor(r *http.Request) (*Session, bool) {
	now := m.now()
	for _, c := range r.Cookies() {
		if c.Name != sessionCookie || c.Value == "" {
			continue
		}
		m.mu.Lock()
		s, ok := m.sessions[c.Value]
		if ok && now.After(s.Expires) {
			delete(m.sessions, c.Value)
			ok = false
		}
		if ok {
			// Sliding expiry: an active browser is not logged out mid-session.
			if remaining := s.Expires.Sub(now); remaining < m.opts.SessionTTL/2 {
				s.Expires = now.Add(m.opts.SessionTTL)
			}
			s.Admin = m.store.IsAdmin(s.Email)
			cp := *s
			m.mu.Unlock()
			return &cp, true
		}
		m.mu.Unlock()
	}
	return nil, false
}

// ---------------------------------------------------------------- sign-in ---

// loginPageData deliberately carries no configuration. The sign-in page names
// neither the product nor the default e-mail domain, so scanning it tells an
// outsider nothing about the organisation behind the gateway.
type loginPageData struct {
	Next string
}

func (m *Manager) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.SessionFor(r); ok {
		http.Redirect(w, r, m.safeNext(r.URL.Query().Get("next")), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	data := loginPageData{Next: m.safeNext(r.URL.Query().Get("next"))}
	if err := m.tmplLogin.Execute(w, data); err != nil {
		m.log.Printf("auth: rendering login page: %v", err)
	}
}

// loginURL builds the redirect that sends an unauthenticated browser to the
// sign-in page, remembering where it was headed.
func (m *Manager) loginURL(r *http.Request) string {
	if m.opts.LoginOrigin == "" {
		return "/login?next=" + url.QueryEscape(r.URL.RequestURI())
	}
	scheme := "http"
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		scheme = "https"
	}
	here := scheme + "://" + r.Host + r.URL.RequestURI()
	return m.opts.LoginOrigin + "/login?next=" + url.QueryEscape(here)
}

// safeNext keeps post-login redirects inside the gateway. Relative paths are
// always fine; an absolute URL is only honoured on the configured domain, which
// is what lets the subdomain URL mode send a user back to the proxied host they
// came from.
func (m *Manager) safeNext(next string) string {
	home := "/"
	if m.opts.LoginOrigin != "" {
		home = m.opts.LoginOrigin + "/"
	}
	if next == "" || strings.HasPrefix(next, "//") {
		return home
	}
	if strings.HasPrefix(next, "/") {
		if u, err := url.Parse(next); err == nil && u.Host == "" && u.Scheme == "" {
			return next
		}
		return home
	}
	if m.opts.NextDomain == "" {
		return home
	}
	u, err := url.Parse(next)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return home
	}
	host := u.Hostname()
	if host == m.opts.NextDomain || strings.HasSuffix(host, "."+m.opts.NextDomain) {
		return next
	}
	return home
}

const (
	rateWindow = 15 * time.Minute
	rateBurst  = 30
)

func trimHits(hits []time.Time, cutoff time.Time) []time.Time {
	out := hits[:0]
	for _, h := range hits {
		if h.After(cutoff) {
			out = append(out, h)
		}
	}
	return out
}

// rateLimited records one hit for ip and reports whether it is over budget.
func (m *Manager) rateLimited(ip string) bool {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	hits := trimHits(m.ipHits[ip], now.Add(-rateWindow))
	if len(hits) >= rateBurst {
		m.ipHits[ip] = hits
		return true
	}
	m.ipHits[ip] = append(hits, now)
	return false
}

func (m *Manager) clientIP(r *http.Request) string {
	if m.opts.TrustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if first, _, _ := strings.Cut(xff, ","); strings.TrimSpace(first) != "" {
				return strings.TrimSpace(first)
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type codeRequest struct {
	Email string `json:"email"`
}

type verifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
	Next  string `json:"next"`
}

func (m *Manager) handleRequestCode(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "bad origin"})
		return
	}
	var req codeRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	if m.rateLimited(m.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "请求过于频繁，请稍后再试"})
		return
	}
	email, err := m.store.NormalizeEmail(req.Email)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	now := m.now()
	m.mu.Lock()
	if c, ok := m.codes[email]; ok && now.Sub(c.sentAt) < m.opts.ResendInterval {
		wait := int((m.opts.ResendInterval - now.Sub(c.sentAt)).Seconds())
		m.mu.Unlock()
		// Same shape as the success response: whether an address exists must not
		// be observable from here.
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "resend_after": wait})
		return
	}
	m.mu.Unlock()

	allowed := m.store.Allowed(email)
	if allowed {
		code, err := newCode()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "服务暂时不可用"})
			return
		}
		m.mu.Lock()
		m.codes[email] = &codeState{
			hash:    hashCode(email, code),
			expires: now.Add(m.opts.CodeTTL),
			sentAt:  now,
		}
		m.mu.Unlock()
		// Delivery can be slow; doing it off the request also keeps the response
		// time from telling an attacker whether mail was actually sent.
		go m.deliver(email, code)
	} else {
		m.log.Printf("auth: rejected sign-in attempt for %s from %s", email, m.clientIP(r))
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"resend_after": int(m.opts.ResendInterval.Seconds()),
		"expires_in":   int(m.opts.CodeTTL.Seconds()),
	})
}

func (m *Manager) deliver(email, code string) {
	body, err := renderMailBody(m.opts.MailBody, email, code, int(m.opts.CodeTTL.Minutes()))
	if err != nil {
		m.log.Printf("auth: rendering mail body: %v", err)
		return
	}
	if err := m.opts.Mailer.Send(email, m.opts.MailSubject, body); err != nil {
		m.log.Printf("auth: sending code to %s: %v", email, err)
	}
}

func (m *Manager) handleVerify(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "bad origin"})
		return
	}
	var req verifyRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	if m.rateLimited(m.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "请求过于频繁，请稍后再试"})
		return
	}
	email, err := m.store.NormalizeEmail(req.Email)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	code := strings.TrimSpace(req.Code)

	now := m.now()
	m.mu.Lock()
	c, ok := m.codes[email]
	switch {
	case !ok || now.After(c.expires):
		delete(m.codes, email)
		m.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "验证码不正确或已过期"})
		return
	case c.attempts >= m.opts.MaxAttempts:
		delete(m.codes, email)
		m.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "尝试次数过多，请重新获取验证码"})
		return
	}
	got := hashCode(email, code)
	if subtle.ConstantTimeCompare(c.hash[:], got[:]) != 1 {
		c.attempts++
		m.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "验证码不正确或已过期"})
		return
	}
	delete(m.codes, email)
	m.mu.Unlock()

	// The allowlist may have changed while the code was in flight.
	if !m.store.Allowed(email) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "该账号无权登录"})
		return
	}

	s, err := m.newSession(email, r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "服务暂时不可用"})
		return
	}
	http.SetCookie(w, m.cookie(s.token, m.opts.SessionTTL))
	m.log.Printf("auth: %s signed in from %s", email, m.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": m.safeNext(req.Next), "admin": s.Admin})
}

func (m *Manager) newSession(email string, r *http.Request) (*Session, error) {
	token, err := randomToken(32)
	if err != nil {
		return nil, err
	}
	id, err := randomToken(8)
	if err != nil {
		return nil, err
	}
	now := m.now()
	s := &Session{
		ID:        id,
		Email:     email,
		Admin:     m.store.IsAdmin(email),
		Created:   now,
		Expires:   now.Add(m.opts.SessionTTL),
		IP:        m.clientIP(r),
		UserAgent: truncate(r.UserAgent(), 200),
		token:     token,
	}
	m.mu.Lock()
	m.sessions[token] = s
	m.mu.Unlock()
	return s, nil
}

func (m *Manager) cookie(value string, ttl time.Duration) *http.Cookie {
	c := &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		Domain:   m.opts.CookieDomain,
		HttpOnly: true,
		Secure:   m.opts.Secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
	if ttl <= 0 {
		c.MaxAge = -1
	}
	return c
}

func (m *Manager) handleLogout(w http.ResponseWriter, r *http.Request) {
	for _, c := range r.Cookies() {
		if c.Name == sessionCookie {
			m.mu.Lock()
			delete(m.sessions, c.Value)
			m.mu.Unlock()
		}
	}
	http.SetCookie(w, m.cookie("", -1))
	http.Redirect(w, r, "/login", http.StatusFound)
}

// ------------------------------------------------------------------ admin ---

func (m *Manager) handleAdminPage(w http.ResponseWriter, r *http.Request) {
	s, ok := m.SessionFor(r)
	if !ok {
		http.Redirect(w, r, m.loginURL(r), http.StatusFound)
		return
	}
	if !s.Admin {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := m.tmplAdmin.Execute(w, map[string]any{"Email": s.Email}); err != nil {
		m.log.Printf("auth: rendering admin page: %v", err)
	}
}

func (m *Manager) requireAdminAPI(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := m.SessionFor(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthenticated"})
			return
		}
		if !s.Admin {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "forbidden"})
			return
		}
		if r.Method == http.MethodPost && !sameOrigin(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "bad origin"})
			return
		}
		next(w, r)
	}
}

func (m *Manager) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": m.store.Get()})
}

func (m *Manager) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var cfg Config
	if err := decodeBody(r, &cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	s, _ := m.SessionFor(r)
	if s != nil && !matchAny(cleanPatterns(cfg.Admins), s.Email) {
		// Locking yourself out of the admin page is not a recoverable mistake
		// through this UI.
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "管理员列表必须仍然包含你自己（" + s.Email + "）"})
		return
	}
	if err := m.store.Set(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	m.log.Printf("auth: configuration updated by %s", s.Email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": m.store.Get()})
}

func (m *Manager) handleListSessions(w http.ResponseWriter, r *http.Request) {
	now := m.now()
	m.mu.Lock()
	out := make([]Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		if now.After(s.Expires) {
			continue
		}
		out = append(out, *s)
	}
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sessions": out})
}

func (m *Manager) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeBody(r, &req); err != nil || req.ID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	m.mu.Lock()
	for tok, s := range m.sessions {
		if s.ID == req.ID {
			delete(m.sessions, tok)
		}
	}
	m.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ----------------------------------------------------------------- helpers ---

func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func hashCode(email, code string) [32]byte {
	return sha256.Sum256([]byte(email + ":" + code))
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	if n <= 8 {
		return hex.EncodeToString(b), nil
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// sameOrigin is a lightweight CSRF check: a cross-site form post carries an
// Origin that does not match the gateway's own host.
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || origin == "null" {
		// No Origin on a same-origin fetch from older browsers; SameSite=Lax
		// already blocks cross-site cookie replay for these.
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

func decodeBody(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
