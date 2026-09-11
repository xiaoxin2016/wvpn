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
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/xiaoxin2016/wvpn/internal/store"
)

// sessionCookie is deliberately anonymous: the sign-in surface should not name
// the product behind it.
const sessionCookie = "wvsid"

// Options configures a Manager. Zero values fall back to the defaults below.
type Options struct {
	Store  *store.Store
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
	// TrustProxyHeaders makes the gateway believe X-Real-IP and
	// X-Forwarded-For from any peer. Without it the headers are still read,
	// but only when the connection comes from a loopback address — which is
	// where a reverse proxy on the same host sits, and which a remote client
	// cannot forge.
	TrustProxyHeaders bool
	// AdminNotice is shown on the admin page's access section. The gateway uses
	// it to spell out the command-line limits the console cannot widen.
	AdminNotice string
	// MailNotice is shown on the admin page's mail section, for when the
	// command line overrides what the console configures.
	MailNotice string
	// SetupToken enables the first-run setup page while the configuration has
	// no administrator. The gateway prints it to its own log, so holding it
	// means having read the console.
	SetupToken string

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
	store *store.Store
	log   *log.Logger

	mu       sync.Mutex
	sessions map[string]*Session // token -> session
	codes    map[string]*codeState
	ipHits   map[string][]time.Time

	tmplLogin *template.Template
	tmplAdmin *template.Template
	tmplSetup *template.Template

	// setupOpen is true while the gateway still needs an administrator, and
	// until one has actually signed in.
	setupOpen bool

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
	setup, err := template.ParseFS(assetsFS, "assets/setup.html")
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
		tmplSetup: setup,
		setupOpen: opts.SetupToken != "" && len(opts.Store.Get().Admins) == 0,
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
		mux.HandleFunc("GET "+host+"/setup", m.handleSetupPage)
		mux.HandleFunc("POST "+host+"/setup", m.handleSetup)
		mux.HandleFunc("POST "+host+"/setup/test", m.handleSetupTest)
		mux.HandleFunc("GET "+host+"/login", m.handleLoginPage)
		mux.HandleFunc("POST "+host+"/auth/code", m.handleRequestCode)
		mux.HandleFunc("POST "+host+"/auth/verify", m.handleVerify)
		mux.HandleFunc(host+"/logout", m.handleLogout)
		mux.HandleFunc("GET "+host+"/admin", m.handleAdminPage)
		mux.HandleFunc("GET "+host+"/admin/api/config", m.requireAdminAPI(m.handleGetConfig))
		mux.HandleFunc("POST "+host+"/admin/api/config", m.requireAdminAPI(m.handleSetConfig))
		mux.HandleFunc("GET "+host+"/admin/api/sessions", m.requireAdminAPI(m.handleListSessions))
		mux.HandleFunc("POST "+host+"/admin/api/sessions/revoke", m.requireAdminAPI(m.handleRevokeSession))
		mux.HandleFunc("POST "+host+"/admin/api/smtp/test", m.requireAdminAPI(m.handleTestMail))
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
		if m.NeedsSetup() && wantsHTML(r) {
			// Nobody can sign in yet; point the browser at the thing that fixes
			// that rather than at a login page that cannot work.
			http.Redirect(w, r, "/setup", http.StatusFound)
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
	if m.NeedsSetup() {
		// Nobody can sign in yet, so the login form would be a dead end.
		http.Redirect(w, r, "/setup", http.StatusFound)
		return
	}
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

// clientIP reports who the request is really from.
//
// Behind nginx every connection arrives from 127.0.0.1, which makes both the
// session list and the rate limiter useless. The forwarding headers are
// therefore honoured when the immediate peer is loopback — a local reverse
// proxy — or when the operator has said to trust them outright. A client that
// reaches the gateway directly cannot talk its way into a different address.
func (m *Manager) clientIP(r *http.Request) string {
	peer := peerIP(r)
	if !m.opts.TrustProxyHeaders && !isLoopbackAddr(peer) {
		return peer
	}
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// The left-most entry is the original client; the rest are proxies.
		if first, _, _ := strings.Cut(xff, ","); strings.TrimSpace(first) != "" {
			return strings.TrimSpace(first)
		}
	}
	return peer
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isLoopbackAddr(host string) bool {
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return addr.IsLoopback()
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
	if s.Admin {
		// The gateway has now been shown to work end to end, so the one-time
		// setup link can stop working.
		m.closeSetup()
	}
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
	data := map[string]any{
		"Email":      s.Email,
		"Notice":     m.opts.AdminNotice,
		"MailNotice": m.opts.MailNotice,
	}
	if err := m.tmplAdmin.Execute(w, data); err != nil {
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

// adminConfig is the wire shape of /admin/api/config. It is deliberately not
// store.Config: the SMTP password goes in through this struct but never comes
// back out of it.
type adminConfig struct {
	DefaultDomain string        `json:"default_domain"`
	AllowedUsers  []string      `json:"allowed_users"`
	Admins        []string      `json:"admins"`
	Access        store.Access  `json:"access"`
	Bookmarks     []store.Group `json:"bookmarks"`
	SMTP          adminSMTP     `json:"smtp"`
}

type adminSMTP struct {
	Addr     string `json:"addr"`
	From     string `json:"from"`
	Username string `json:"username"`
	// TLSMode is one of store.TLSAuto, TLSRequire, TLSNone, TLSImplicit.
	TLSMode string `json:"tls_mode"`
	// AllowPlaintext permits AUTH on a connection with no encryption, which an
	// internal relay on port 25 may be the only way to use.
	AllowPlaintext bool   `json:"allow_plaintext_auth"`
	HELO           string `json:"helo"`
	Insecure       bool   `json:"insecure_skip_verify"`
	// Password is write-only. Empty means "keep the stored one", which is what
	// lets the page save the section without ever holding the secret.
	Password string `json:"password"`
	// ClearPassword removes the stored password.
	ClearPassword bool `json:"clear_password"`
	// PasswordSet is read-only: whether a password is stored at all.
	PasswordSet bool `json:"password_set"`
}

// viewOf builds the response shape, with the password reduced to a flag.
func viewOf(c store.Config) adminConfig {
	return adminConfig{
		DefaultDomain: c.DefaultDomain,
		AllowedUsers:  c.AllowedUsers,
		Admins:        c.Admins,
		Access:        c.Access,
		Bookmarks:     c.Bookmarks,
		SMTP: adminSMTP{
			Addr:           c.SMTP.Addr,
			From:           c.SMTP.From,
			Username:       c.SMTP.Username,
			TLSMode:        c.SMTP.Mode(),
			AllowPlaintext: c.SMTP.AllowPlaintextAuth,
			HELO:           c.SMTP.HELO,
			Insecure:       c.SMTP.InsecureSkipVerify,
			PasswordSet:    c.SMTP.Password != "",
		},
	}
}

// merge folds a submitted configuration onto the stored one, carrying the
// existing SMTP password over unless the request replaces or clears it.
func merge(in adminConfig, current store.Config) store.Config {
	out := store.Config{
		DefaultDomain: in.DefaultDomain,
		AllowedUsers:  in.AllowedUsers,
		Admins:        in.Admins,
		Access:        in.Access,
		Bookmarks:     in.Bookmarks,
		SMTP: store.SMTP{
			Addr:               in.SMTP.Addr,
			From:               in.SMTP.From,
			Username:           in.SMTP.Username,
			TLSMode:            in.SMTP.TLSMode,
			AllowPlaintextAuth: in.SMTP.AllowPlaintext,
			HELO:               in.SMTP.HELO,
			InsecureSkipVerify: in.SMTP.Insecure,
			Password:           in.SMTP.Password,
		},
	}
	switch {
	case in.SMTP.ClearPassword:
		out.SMTP.Password = ""
	case in.SMTP.Password == "":
		out.SMTP.Password = current.SMTP.Password
	}
	return out
}

func (m *Manager) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": viewOf(m.store.Get())})
}

func (m *Manager) handleSetConfig(w http.ResponseWriter, r *http.Request) {
	var in adminConfig
	if err := decodeBody(r, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	s, _ := m.SessionFor(r)
	if s != nil && !store.MatchAny(store.CleanPatterns(in.Admins), s.Email) {
		// Locking yourself out of the admin page is not a recoverable mistake
		// through this UI.
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "管理员列表必须仍然包含你自己（" + s.Email + "）"})
		return
	}
	if err := m.store.Set(merge(in, m.store.Get())); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	m.log.Printf("auth: configuration updated by %s", s.Email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "config": viewOf(m.store.Get())})
}

// handleTestMail sends a message through whatever path a verification code
// would take. The recipient is always the signed-in administrator: a form that
// mails an arbitrary address would turn the console into a relay.
func (m *Manager) handleTestMail(w http.ResponseWriter, r *http.Request) {
	s, _ := m.SessionFor(r)
	if s == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "unauthenticated"})
		return
	}
	if m.rateLimited(m.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "请求过于频繁，请稍后再试"})
		return
	}
	body := "这是一封测试邮件，说明网关的邮件发送配置可用。\n\nThis is a test message from your gateway."
	if err := m.opts.Mailer.Send(s.Email, m.opts.MailSubject, body); err != nil {
		m.log.Printf("auth: test mail to %s failed: %v", s.Email, err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "发送失败：" + err.Error()})
		return
	}
	m.log.Printf("auth: test mail sent to %s", s.Email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sent_to": s.Email})
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
