package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"net/http"
	"strings"

	"github.com/xiaoxin2016/wvpn/internal/store"
)

// A gateway with no administrator in its configuration cannot be signed into at
// all, so the first run has to bootstrap one. Letting the first visitor claim
// that role would hand the gateway to whoever finds the port first, so setup is
// gated on a token printed to the process log: proving you can read the
// gateway's console is the only credential available before any account exists.
//
// The token configures the gateway; it does not grant access to it. Signing in
// still requires receiving a code at the administrator's mailbox, which is why
// setup stays open until that first sign-in actually succeeds — a mistyped SMTP
// server is then still fixable through the same link.

// NewSetupToken returns a token in five-character groups, short enough to
// retype from a terminal.
func NewSetupToken() (string, error) {
	b := make([]byte, 15) // 120 bits -> 24 base32 characters
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	var groups []string
	for i := 0; i < len(raw); i += 6 {
		groups = append(groups, raw[i:i+6])
	}
	return strings.Join(groups, "-"), nil
}

// SetupPending reports whether the setup link still works. It stays true after
// the form is submitted, until an administrator has actually signed in, so a
// mistyped SMTP server can be corrected through the same link.
func (m *Manager) SetupPending() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.setupOpen
}

// NeedsSetup reports whether the gateway has nobody who can sign in yet, which
// is the only state that should divert a browser away from the login page.
func (m *Manager) NeedsSetup() bool {
	return m.SetupPending() && len(m.store.Get().Admins) == 0
}

// closeSetup ends setup mode. It runs when an administrator signs in, which is
// the first moment the gateway is known to be usable.
func (m *Manager) closeSetup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.setupOpen {
		m.setupOpen = false
		m.log.Print("auth: setup complete, the initialisation link is now invalid")
	}
}

// validToken reports whether the request carries the setup token.
func (m *Manager) validToken(got string) bool {
	m.mu.Lock()
	want := m.opts.SetupToken
	m.mu.Unlock()
	if want == "" || got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(got)), []byte(want)) == 1
}

type setupPageData struct {
	Token      string
	MailNotice string
}

func (m *Manager) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")

	if !m.SetupPending() {
		// Nothing to configure: send a browser somewhere useful rather than
		// confirming anything about the gateway's state.
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	data := setupPageData{MailNotice: m.opts.MailNotice}
	if token := r.URL.Query().Get("token"); m.validToken(token) {
		data.Token = token
	}
	if err := m.tmplSetup.Execute(w, data); err != nil {
		m.log.Printf("auth: rendering setup page: %v", err)
	}
}

type setupRequest struct {
	Token         string    `json:"token"`
	AdminEmail    string    `json:"admin_email"`
	DefaultDomain string    `json:"default_domain"`
	AllowedUsers  []string  `json:"allowed_users"`
	SMTP          adminSMTP `json:"smtp"`
}

// guardSetup rejects anything that is not a token-carrying setup request.
func (m *Manager) guardSetup(w http.ResponseWriter, r *http.Request, token string) bool {
	if !sameOrigin(r) {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "bad origin"})
		return false
	}
	if !m.SetupPending() {
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "网关已完成初始化"})
		return false
	}
	if m.rateLimited(m.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "请求过于频繁，请稍后再试"})
		return false
	}
	if !m.validToken(token) {
		m.log.Printf("auth: rejected setup attempt from %s", m.clientIP(r))
		writeJSON(w, http.StatusForbidden, map[string]any{"ok": false, "error": "初始化令牌不正确"})
		return false
	}
	return true
}

func (m *Manager) handleSetup(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	if !m.guardSetup(w, r, req.Token) {
		return
	}

	cfg, admin, err := m.setupConfig(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	if err := m.store.Set(cfg); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	m.log.Printf("auth: initialised with administrator %s", admin)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "admin": admin, "redirect": "/login"})
}

// setupConfig turns the form into a configuration, keeping whatever the command
// line already seeded.
func (m *Manager) setupConfig(req setupRequest) (store.Config, string, error) {
	cfg := m.store.Get()
	if d := strings.TrimSpace(req.DefaultDomain); d != "" {
		cfg.DefaultDomain = d
	}

	admin, err := m.store.NormalizeEmailWith(req.AdminEmail, cfg.DefaultDomain)
	if err != nil {
		return cfg, "", err
	}
	cfg.Admins = append(store.CleanPatterns(cfg.Admins), admin)

	if users := store.CleanPatterns(req.AllowedUsers); len(users) > 0 {
		cfg.AllowedUsers = users
	}

	cfg.SMTP = store.SMTP{
		Addr:               strings.TrimSpace(req.SMTP.Addr),
		From:               strings.TrimSpace(req.SMTP.From),
		Username:           strings.TrimSpace(req.SMTP.Username),
		Password:           req.SMTP.Password,
		TLSMode:            req.SMTP.TLSMode,
		AllowPlaintextAuth: req.SMTP.AllowPlaintext,
		HELO:               strings.TrimSpace(req.SMTP.HELO),
		InsecureSkipVerify: req.SMTP.Insecure,
	}
	return cfg, admin, nil
}

// handleSetupTest sends a test message with the settings currently in the form,
// so a typo in the SMTP server is found before it locks anyone out.
func (m *Manager) handleSetupTest(w http.ResponseWriter, r *http.Request) {
	var req setupRequest
	if err := decodeBody(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "请求格式不正确"})
		return
	}
	if !m.guardSetup(w, r, req.Token) {
		return
	}

	domain := strings.TrimSpace(req.DefaultDomain)
	if domain == "" {
		domain = m.store.Get().DefaultDomain
	}
	to, err := m.store.NormalizeEmailWith(req.AdminEmail, domain)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
		return
	}

	var mailer Mailer = m.opts.Mailer
	if s := req.SMTP; strings.TrimSpace(s.Addr) != "" {
		// Test what is on screen, not what is stored: nothing is saved yet.
		mailer = SMTPMailer{
			Addr:               strings.TrimSpace(s.Addr),
			From:               strings.TrimSpace(s.From),
			Username:           strings.TrimSpace(s.Username),
			Password:           s.Password,
			TLSMode:            s.TLSMode,
			AllowPlaintextAuth: s.AllowPlaintext,
			HELO:               strings.TrimSpace(s.HELO),
			InsecureSkipVerify: s.Insecure,
		}
	}
	body := "这是一封测试邮件，说明网关的邮件发送配置可用。\n\nThis is a test message from your gateway."
	if err := mailer.Send(to, m.opts.MailSubject, body); err != nil {
		m.log.Printf("auth: setup test mail to %s failed: %v", to, err)
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "发送失败：" + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "sent_to": to})
}
