package auth

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/xiaoxin2016/wvpn/internal/store"
)

// Mailer delivers a one-time code to an address.
type Mailer interface {
	Send(to, subject, body string) error
}

// StoreMailer sends through the SMTP service configured in the admin console,
// re-reading it on every send so a corrected setting takes effect immediately.
// Fallback covers the case where the console has none — typically the service
// given on the command line, or the console mailer during bootstrap.
type StoreMailer struct {
	Store    *store.Store
	Fallback Mailer
}

func (m StoreMailer) Send(to, subject, body string) error {
	cfg := m.Store.Get().SMTP
	if !cfg.Configured() {
		if m.Fallback == nil {
			return errors.New("auth: 尚未配置邮件发送服务")
		}
		return m.Fallback.Send(to, subject, body)
	}
	return SMTPMailer{
		Addr:               cfg.Addr,
		From:               cfg.From,
		Username:           cfg.Username,
		Password:           cfg.Password,
		TLSMode:            cfg.Mode(),
		AllowPlaintextAuth: cfg.AllowPlaintextAuth,
		HELO:               cfg.HELO,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}.Send(to, subject, body)
}

// ConsoleMailer is what -ignore-email installs: codes go to the process log
// instead of a mailbox. Useful for development, and a wide-open back door in
// production — the command line says so on startup.
type ConsoleMailer struct {
	Logger *log.Logger
	Out    io.Writer
}

func (m ConsoleMailer) Send(to, subject, body string) error {
	line := fmt.Sprintf("[mail:console] to=%s subject=%q\n%s", to, subject, body)
	if m.Out != nil {
		_, err := io.WriteString(m.Out, line+"\n")
		return err
	}
	logger := m.Logger
	if logger == nil {
		logger = log.Default()
	}
	logger.Print(line)
	return nil
}

// SMTPMailer sends through an SMTP submission service.
//
// net/smtp's own SendMail is not used because it refuses to authenticate over
// an unencrypted connection, with an error ("unencrypted connection") that says
// nothing about what to do. That refusal is a good default and a bad absolute:
// an internal relay on port 25 with no STARTTLS is ordinary, and so is one that
// only offers AUTH LOGIN. The conversation is therefore driven here, where the
// policy is explicit and the errors say which knob to turn.
type SMTPMailer struct {
	// Addr is host:port, e.g. smtp.example.com:587 or a relay on :25.
	Addr string
	// From is the envelope sender and the From: header.
	From string
	// Username/Password enable AUTH when set.
	Username, Password string
	// TLSMode is one of store.TLSAuto, TLSRequire, TLSNone or TLSImplicit.
	TLSMode string
	// AllowPlaintextAuth permits AUTH over a connection that was never
	// encrypted. Without it, such an attempt is refused before the password
	// leaves the process.
	AllowPlaintextAuth bool
	// HELO overrides the name announced to the server.
	HELO string
	// InsecureSkipVerify disables certificate verification.
	InsecureSkipVerify bool
	Timeout            time.Duration
}

func (m SMTPMailer) mode() string {
	switch m.TLSMode {
	case store.TLSAuto, store.TLSRequire, store.TLSNone, store.TLSImplicit:
		return m.TLSMode
	}
	return store.TLSAuto
}

func (m SMTPMailer) Send(to, subject, body string) error {
	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return fmt.Errorf("SMTP 服务器地址 %q 需要写成 host:port", m.Addr)
	}
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tlsCfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: m.InsecureSkipVerify,
	}

	var conn net.Conn
	if m.mode() == store.TLSImplicit {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", m.Addr, tlsCfg)
	} else {
		conn, err = net.DialTimeout("tcp", m.Addr, timeout)
	}
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器失败: %w", err)
	}
	defer conn.Close()
	// One deadline covers the whole exchange; a wedged relay must not wedge the
	// sign-in it is serving.
	_ = conn.SetDeadline(time.Now().Add(timeout))

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP 握手失败: %w", err)
	}
	defer c.Close()

	if m.HELO != "" {
		if err := c.Hello(m.HELO); err != nil {
			return fmt.Errorf("EHLO %s 被拒绝: %w", m.HELO, err)
		}
	}

	switch m.mode() {
	case store.TLSAuto, store.TLSRequire:
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("STARTTLS 失败: %w", err)
			}
		} else if m.mode() == store.TLSRequire {
			return errors.New("TLS 模式为“必须加密”，但该服务器未提供 STARTTLS")
		}
	}

	if m.Username != "" || m.Password != "" {
		auth, err := m.pickAuth(c)
		if err != nil {
			return err
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}

	if err := c.Mail(m.From); err != nil {
		return fmt.Errorf("发件人 %s 被拒绝: %w", m.From, err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("收件人 %s 被拒绝: %w", to, err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA 被拒绝: %w", err)
	}
	if _, err := w.Write(buildMessage(m.From, to, subject, body)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("邮件被拒绝: %w", err)
	}
	return c.Quit()
}

// pickAuth chooses a mechanism the server offers, and refuses to hand over a
// password in the clear unless that was asked for explicitly.
func (m SMTPMailer) pickAuth(c *smtp.Client) (smtp.Auth, error) {
	ok, params := c.Extension("AUTH")
	if !ok {
		return nil, errors.New("该 SMTP 服务器不支持认证（未通告 AUTH）；若是内网无认证中继，请清空用户名与密码")
	}
	mechs := strings.Fields(strings.ToUpper(params))
	offers := func(name string) bool {
		for _, mech := range mechs {
			if mech == name {
				return true
			}
		}
		return false
	}
	_, encrypted := c.TLSConnectionState()

	// CRAM-MD5 is a challenge-response: the password itself never crosses the
	// wire, so it is worth preferring on a connection that is not encrypted.
	if !encrypted && offers("CRAM-MD5") {
		return smtp.CRAMMD5Auth(m.Username, m.Password), nil
	}
	if !encrypted && !m.AllowPlaintextAuth {
		return nil, errors.New("连接未加密（服务器未提供 STARTTLS），默认不会在明文连接上发送账号密码。" +
			"请改用 587/STARTTLS 或 465/直接 TLS；若确实要在可信内网中明文认证，请勾选“允许明文认证”")
	}
	switch {
	case offers("PLAIN"):
		return plainAuth{username: m.Username, password: m.Password}, nil
	case offers("LOGIN"):
		return &loginAuth{username: m.Username, password: m.Password}, nil
	case offers("CRAM-MD5"):
		return smtp.CRAMMD5Auth(m.Username, m.Password), nil
	}
	return nil, fmt.Errorf("该服务器只支持 %s 认证，网关暂不支持", strings.Join(mechs, " / "))
}

// plainAuth is AUTH PLAIN without net/smtp's own encryption check, which has
// already been made in pickAuth.
type plainAuth struct{ username, password string }

func (a plainAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	return "PLAIN", []byte("\x00" + a.username + "\x00" + a.password), nil
}

func (a plainAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		return nil, fmt.Errorf("auth: unexpected PLAIN challenge %q", fromServer)
	}
	return nil, nil
}

// loginAuth is AUTH LOGIN, which net/smtp does not implement and which older
// relays — Exchange in particular — often offer as the only mechanism. The
// prompts are answered by position: their wording is not standardised.
type loginAuth struct {
	username, password string
	step               int
}

func (a *loginAuth) Start(*smtp.ServerInfo) (string, []byte, error) {
	a.step = 0
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	a.step++
	switch a.step {
	case 1:
		return []byte(a.username), nil
	case 2:
		return []byte(a.password), nil
	}
	return nil, fmt.Errorf("auth: unexpected LOGIN challenge %q", fromServer)
}

// buildMessage assembles a minimal UTF-8 text/plain message.
func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	b.WriteString("\r\n")
	return []byte(b.String())
}
