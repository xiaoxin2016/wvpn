package auth

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/xiaoxin2016/wvpn/internal/store"
)

// fakeSMTP is a minimal submission service: enough of the protocol to observe
// what the mailer does, and nothing more. It never offers STARTTLS, which is
// exactly the internal relay on port 25 that this is about.
type fakeSMTP struct {
	ln    net.Listener
	mechs string // AUTH mechanisms to advertise; empty advertises none

	mu       sync.Mutex
	authLine string
	answers  []string
	body     strings.Builder
	from, to string
}

func newFakeSMTP(t *testing.T, mechs string) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTP{ln: ln, mechs: mechs}
	go s.serve()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *fakeSMTP) addr() string { return s.ln.Addr().String() }

func (s *fakeSMTP) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	say := func(format string, args ...any) {
		fmt.Fprintf(w, format+"\r\n", args...)
		w.Flush()
	}

	say("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		upper := strings.ToUpper(line)

		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			if s.mechs == "" {
				say("250 fake")
				continue
			}
			say("250-fake")
			say("250 AUTH %s", s.mechs)

		case strings.HasPrefix(upper, "AUTH"):
			s.mu.Lock()
			s.authLine = line
			s.mu.Unlock()
			if strings.Contains(upper, "LOGIN") && len(strings.Fields(line)) == 2 {
				say("334 %s", base64.StdEncoding.EncodeToString([]byte("Username:")))
				user, _ := r.ReadString('\n')
				say("334 %s", base64.StdEncoding.EncodeToString([]byte("Password:")))
				pass, _ := r.ReadString('\n')
				s.mu.Lock()
				s.answers = []string{strings.TrimSpace(user), strings.TrimSpace(pass)}
				s.mu.Unlock()
			}
			say("235 ok")

		case strings.HasPrefix(upper, "MAIL FROM"):
			s.mu.Lock()
			s.from = line
			s.mu.Unlock()
			say("250 ok")

		case strings.HasPrefix(upper, "RCPT TO"):
			s.mu.Lock()
			s.to = line
			s.mu.Unlock()
			say("250 ok")

		case strings.HasPrefix(upper, "DATA"):
			say("354 go ahead")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
				s.mu.Lock()
				s.body.WriteString(l)
				s.mu.Unlock()
			}
			say("250 queued")

		case strings.HasPrefix(upper, "QUIT"):
			say("221 bye")
			return

		default:
			say("250 ok")
		}
	}
}

func (s *fakeSMTP) seen() (auth string, answers []string, body, from, to string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authLine, s.answers, s.body.String(), s.from, s.to
}

// An internal relay on port 25 that wants no credentials is the simplest case,
// and the one that must work with no options at all.
func TestSendOverPlaintextWithoutAuth(t *testing.T) {
	srv := newFakeSMTP(t, "")
	m := SMTPMailer{Addr: srv.addr(), From: "gw@corp.local"}
	if err := m.Send("ops@corp.local", "验证码", "123456"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	auth, _, body, from, to := srv.seen()
	if auth != "" {
		t.Errorf("authenticated when no credentials were configured: %q", auth)
	}
	if !strings.Contains(from, "gw@corp.local") || !strings.Contains(to, "ops@corp.local") {
		t.Errorf("envelope = %q -> %q", from, to)
	}
	if !strings.Contains(body, "123456") {
		t.Errorf("body did not arrive: %q", body)
	}
}

// Sending credentials in the clear is refused by default — but the error has to
// say which switch turns it on, which is the whole point of not using
// net/smtp's own "unencrypted connection".
func TestPlaintextAuthIsRefusedByDefault(t *testing.T) {
	srv := newFakeSMTP(t, "PLAIN LOGIN")
	m := SMTPMailer{Addr: srv.addr(), From: "gw@corp.local", Username: "gw", Password: "pw"}
	err := m.Send("ops@corp.local", "s", "b")
	if err == nil {
		t.Fatal("credentials were sent over an unencrypted connection")
	}
	if !strings.Contains(err.Error(), "允许明文认证") {
		t.Errorf("error does not point at the setting: %v", err)
	}
	if auth, _, _, _, _ := srv.seen(); auth != "" {
		t.Errorf("an AUTH command was sent anyway: %q", auth)
	}
}

func TestPlaintextAuthWhenAllowed(t *testing.T) {
	srv := newFakeSMTP(t, "PLAIN")
	m := SMTPMailer{
		Addr: srv.addr(), From: "gw@corp.local",
		Username: "gw", Password: "pw", AllowPlaintextAuth: true,
	}
	if err := m.Send("ops@corp.local", "s", "b"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	auth, _, _, _, _ := srv.seen()
	if !strings.HasPrefix(strings.ToUpper(auth), "AUTH PLAIN") {
		t.Fatalf("AUTH line = %q", auth)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Fields(auth)[2])
	if err != nil {
		t.Fatalf("decoding credentials: %v", err)
	}
	if string(raw) != "\x00gw\x00pw" {
		t.Errorf("credentials = %q", raw)
	}
}

// AUTH LOGIN is all some relays offer, and net/smtp does not implement it.
func TestLoginMechanism(t *testing.T) {
	srv := newFakeSMTP(t, "LOGIN")
	m := SMTPMailer{
		Addr: srv.addr(), From: "gw@corp.local",
		Username: "gw", Password: "pw", AllowPlaintextAuth: true,
	}
	if err := m.Send("ops@corp.local", "s", "b"); err != nil {
		t.Fatalf("Send: %v", err)
	}
	auth, answers, _, _, _ := srv.seen()
	if !strings.HasPrefix(strings.ToUpper(auth), "AUTH LOGIN") {
		t.Fatalf("AUTH line = %q", auth)
	}
	if len(answers) != 2 {
		t.Fatalf("answers = %v", answers)
	}
	user, _ := base64.StdEncoding.DecodeString(answers[0])
	pass, _ := base64.StdEncoding.DecodeString(answers[1])
	if string(user) != "gw" || string(pass) != "pw" {
		t.Errorf("LOGIN sent %q / %q", user, pass)
	}
}

// CRAM-MD5 never puts the password on the wire, so it is preferred over a
// plaintext mechanism even when plaintext auth has been allowed.
func TestCramMD5PreferredWithoutTLS(t *testing.T) {
	srv := newFakeSMTP(t, "CRAM-MD5 PLAIN")
	m := SMTPMailer{
		Addr: srv.addr(), From: "gw@corp.local",
		Username: "gw", Password: "pw", AllowPlaintextAuth: true,
	}
	// The fake server answers 235 without issuing a challenge, which is enough
	// to observe which mechanism was chosen.
	_ = m.Send("ops@corp.local", "s", "b")
	if auth, _, _, _, _ := srv.seen(); !strings.Contains(strings.ToUpper(auth), "CRAM-MD5") {
		t.Errorf("AUTH line = %q, want CRAM-MD5", auth)
	}
}

func TestRequireTLSRefusesPlaintextServer(t *testing.T) {
	srv := newFakeSMTP(t, "")
	m := SMTPMailer{Addr: srv.addr(), From: "gw@corp.local", TLSMode: store.TLSRequire}
	err := m.Send("ops@corp.local", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err = %v, want a STARTTLS complaint", err)
	}
}

func TestHELOOverride(t *testing.T) {
	srv := newFakeSMTP(t, "")
	m := SMTPMailer{Addr: srv.addr(), From: "gw@corp.local", HELO: "gateway.corp.local"}
	if err := m.Send("ops@corp.local", "s", "b"); err != nil {
		t.Fatalf("Send: %v", err)
	}
}

func TestAuthWithoutServerSupport(t *testing.T) {
	srv := newFakeSMTP(t, "")
	m := SMTPMailer{Addr: srv.addr(), From: "gw@corp.local", Username: "gw", Password: "pw"}
	err := m.Send("ops@corp.local", "s", "b")
	if err == nil || !strings.Contains(err.Error(), "AUTH") {
		t.Fatalf("err = %v, want a complaint about AUTH", err)
	}
}
