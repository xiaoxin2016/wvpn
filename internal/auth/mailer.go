package auth

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// Mailer delivers a one-time code to an address.
type Mailer interface {
	Send(to, subject, body string) error
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

// SMTPMailer sends through a normal SMTP submission service.
type SMTPMailer struct {
	// Addr is host:port, e.g. smtp.example.com:587.
	Addr string
	// From is the envelope sender and the From: header.
	From string
	// Username/Password enable AUTH when set.
	Username, Password string
	// ImplicitTLS dials TLS directly (port 465) instead of STARTTLS (587).
	ImplicitTLS bool
	// InsecureSkipVerify disables certificate verification. Off by default.
	InsecureSkipVerify bool
	Timeout            time.Duration
}

func (m SMTPMailer) auth(host string) smtp.Auth {
	if m.Username == "" && m.Password == "" {
		return nil
	}
	return smtp.PlainAuth("", m.Username, m.Password, host)
}

func (m SMTPMailer) Send(to, subject, body string) error {
	host, _, err := net.SplitHostPort(m.Addr)
	if err != nil {
		return fmt.Errorf("auth: bad smtp address %q: %w", m.Addr, err)
	}
	msg := buildMessage(m.From, to, subject, body)
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	tlsCfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: m.InsecureSkipVerify}

	if !m.ImplicitTLS {
		// smtp.SendMail negotiates STARTTLS when the server advertises it.
		return smtp.SendMail(m.Addr, m.auth(host), m.From, []string{to}, msg)
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", m.Addr, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return err
	}
	defer c.Quit()
	if a := m.auth(host); a != nil {
		if err := c.Auth(a); err != nil {
			return err
		}
	}
	if err := c.Mail(m.From); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	return w.Close()
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
