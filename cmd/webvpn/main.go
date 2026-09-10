// Command webvpn runs a WebVPN gateway: a browser signs in with an e-mail
// one-time code, then reaches http/https sites through this process, which
// rewrites every response so the browser never talks to the origin directly.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/xiaoxin2016/wvpn/internal/auth"
	"github.com/xiaoxin2016/wvpn/internal/webvpn"
)

type config struct {
	addr     string
	tlsCert  string
	tlsKey   string
	portal   string
	resource string

	urlMode    string
	urlKey     string
	baseDomain string
	publicPort string

	allowHosts   string
	denyHosts    string
	allowPrivate bool
	insecureTLS  bool
	maxRewrite   int64
	dialTimeout  time.Duration
	respTimeout  time.Duration

	noAuth        bool
	configPath    string
	defaultDomain string
	allowUsers    string
	admins        string
	sessionTTL    time.Duration
	codeTTL       time.Duration

	ignoreEmail  bool
	smtpAddr     string
	smtpUser     string
	smtpPass     string
	smtpFrom     string
	smtpImplicit bool
	smtpInsecure bool
	mailSubject  string

	trustForwarded bool
}

func main() {
	var c config
	flag.StringVar(&c.addr, "addr", ":8080", "listen address")
	flag.StringVar(&c.tlsCert, "tls-cert", "", "TLS certificate file; serves HTTPS when set together with -tls-key")
	flag.StringVar(&c.tlsKey, "tls-key", "", "TLS private key file")
	flag.StringVar(&c.portal, "name", "WebVPN", "name shown on the portal page (never on the sign-in page)")
	flag.StringVar(&c.resource, "bookmarks", "", "JSON file with the portal's curated links")

	flag.StringVar(&c.urlMode, "url-mode", "plain", "target encoding: plain | wrd | subdomain")
	flag.StringVar(&c.urlKey, "url-key", webvpn.DefaultWRDKey, "AES key for -url-mode wrd (16, 24 or 32 bytes)")
	flag.StringVar(&c.baseDomain, "base-domain", "", "wildcard domain for -url-mode subdomain, e.g. webvpn.example.com")
	flag.StringVar(&c.publicPort, "public-port", "", "port browsers reach the gateway on, for -url-mode subdomain")

	flag.StringVar(&c.allowHosts, "allow", "", "comma-separated allowlist of target hosts (suffix match); empty means any")
	flag.StringVar(&c.denyHosts, "deny", "", "comma-separated denylist of target hosts (suffix match)")
	flag.BoolVar(&c.allowPrivate, "allow-private", false, "allow targets that resolve to loopback/private/link-local addresses")
	flag.BoolVar(&c.insecureTLS, "insecure-tls", false, "skip certificate verification for upstream HTTPS")
	flag.Int64Var(&c.maxRewrite, "max-rewrite-bytes", 8<<20, "largest response body that gets rewritten")
	flag.DurationVar(&c.dialTimeout, "dial-timeout", 10*time.Second, "upstream dial timeout")
	flag.DurationVar(&c.respTimeout, "response-timeout", 30*time.Second, "upstream response header timeout")

	flag.BoolVar(&c.noAuth, "no-auth", false, "disable sign-in entirely (development only)")
	flag.StringVar(&c.configPath, "config", "webvpn-config.json", "file holding the admin-editable access policy")
	flag.StringVar(&c.defaultDomain, "default-domain", "", "initial default e-mail domain, e.g. test.com")
	flag.StringVar(&c.allowUsers, "allow-user", "", "initial comma-separated allowlist of accounts, e.g. \"*@test.com\"")
	flag.StringVar(&c.admins, "admin", "", "initial comma-separated admin accounts")
	flag.DurationVar(&c.sessionTTL, "session-ttl", 12*time.Hour, "how long a sign-in lasts")
	flag.DurationVar(&c.codeTTL, "code-ttl", 5*time.Minute, "how long a verification code stays valid")

	flag.BoolVar(&c.ignoreEmail, "ignore-email", false, "print verification codes to the console instead of mailing them")
	flag.StringVar(&c.smtpAddr, "smtp-addr", "", "SMTP submission service, host:port")
	flag.StringVar(&c.smtpUser, "smtp-user", "", "SMTP username")
	flag.StringVar(&c.smtpPass, "smtp-pass", "", "SMTP password; prefer WEBVPN_SMTP_PASS")
	flag.StringVar(&c.smtpFrom, "smtp-from", "", "envelope sender address")
	flag.BoolVar(&c.smtpImplicit, "smtp-implicit-tls", false, "dial SMTP over TLS directly (port 465) instead of STARTTLS")
	flag.BoolVar(&c.smtpInsecure, "smtp-insecure", false, "skip SMTP certificate verification")
	flag.StringVar(&c.mailSubject, "mail-subject", "", "subject line of the code e-mail")

	flag.BoolVar(&c.trustForwarded, "trust-forwarded-for", false, "read the client IP from X-Forwarded-For (only behind your own proxy)")
	flag.Parse()

	if v := os.Getenv("WEBVPN_SMTP_PASS"); v != "" {
		c.smtpPass = v
	}

	logger := log.New(os.Stderr, "", log.LstdFlags|log.Lmsgprefix)
	if err := run(c, logger); err != nil {
		logger.Fatalf("fatal: %v", err)
	}
}

func run(c config, logger *log.Logger) error {
	serveTLS := c.tlsCert != "" && c.tlsKey != ""

	codec, err := buildCodec(c, serveTLS)
	if err != nil {
		return err
	}

	gateway := webvpn.New(webvpn.Options{
		Codec:                 codec,
		Guard:                 webvpn.NewGuard(c.allowHosts, c.denyHosts, c.allowPrivate),
		MaxRewriteBytes:       c.maxRewrite,
		DialTimeout:           c.dialTimeout,
		ResponseHeaderTimeout: c.respTimeout,
		InsecureTLS:           c.insecureTLS,
		Portal:                webvpn.Portal{Name: c.portal},
		Logger:                logger,
	})

	if c.resource != "" {
		cats, err := webvpn.LoadCategories(c.resource)
		if err != nil {
			return err
		}
		gateway.SetCategories(cats)
	}

	mux := http.NewServeMux()
	var handler http.Handler = gateway

	if c.noAuth {
		logger.Print("warning: -no-auth is set; anyone who can reach this port can use the gateway")
	} else {
		manager, err := buildAuth(c, serveTLS, logger)
		if err != nil {
			return err
		}
		defer manager.Close()
		gateway.SetIdentity(identity{manager}, manager.CookieName())
		manager.Routes(mux, gatewayHosts(c)...)
		handler = manager.Require(gateway)
	}
	mux.Handle("/", handler)

	warn(c, logger)

	srv := &http.Server{
		Addr:              c.addr,
		Handler:           mux,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          logger,
		// No WriteTimeout on purpose: it would cut off streaming responses and
		// long-lived websocket connections.
	}

	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	scheme := "http"
	if serveTLS {
		scheme = "https"
	}
	logger.Printf("listening on %s://%s (url-mode=%s)", scheme, ln.Addr(), codec.Name())

	errc := make(chan error, 1)
	go func() {
		if serveTLS {
			errc <- srv.ServeTLS(ln, c.tlsCert, c.tlsKey)
			return
		}
		errc <- srv.Serve(ln)
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	select {
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case sig := <-stop:
		logger.Printf("%s received, shutting down", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
	return nil
}

func buildCodec(c config, serveTLS bool) (webvpn.Codec, error) {
	switch c.urlMode {
	case "plain", "":
		return webvpn.PlainCodec{}, nil
	case "wrd":
		return webvpn.NewWRDCodec(c.urlKey)
	case "subdomain":
		return webvpn.NewHostCodec(c.baseDomain, c.publicPort, serveTLS)
	default:
		return nil, fmt.Errorf("unknown -url-mode %q (want plain, wrd or subdomain)", c.urlMode)
	}
}

// gatewayHosts lists the Host values the sign-in and admin pages answer on. It
// is empty — meaning "any host" — unless the subdomain codec is in use, where
// scoping keeps /login from shadowing a proxied site's own /login.
func gatewayHosts(c config) []string {
	if c.urlMode != "subdomain" || c.baseDomain == "" {
		return nil
	}
	hosts := []string{c.baseDomain}
	if c.publicPort != "" {
		hosts = append(hosts, net.JoinHostPort(c.baseDomain, c.publicPort))
	}
	return hosts
}

func buildAuth(c config, serveTLS bool, logger *log.Logger) (*auth.Manager, error) {
	store, err := auth.LoadStore(c.configPath, auth.Config{
		DefaultDomain: c.defaultDomain,
		AllowedUsers:  splitCSV(c.allowUsers),
		Admins:        splitCSV(c.admins),
	})
	if err != nil {
		return nil, err
	}

	var mailer auth.Mailer
	switch {
	case c.ignoreEmail:
		mailer = auth.ConsoleMailer{Logger: logger}
	case c.smtpAddr != "":
		from := c.smtpFrom
		if from == "" {
			from = c.smtpUser
		}
		if from == "" {
			return nil, errors.New("-smtp-from is required when sending mail")
		}
		mailer = auth.SMTPMailer{
			Addr:               c.smtpAddr,
			From:               from,
			Username:           c.smtpUser,
			Password:           c.smtpPass,
			ImplicitTLS:        c.smtpImplicit,
			InsecureSkipVerify: c.smtpInsecure,
		}
	default:
		return nil, errors.New("no way to deliver codes: set -smtp-addr, or -ignore-email for local testing")
	}

	cookieDomain, loginOrigin, nextDomain := "", "", ""
	if c.urlMode == "subdomain" && c.baseDomain != "" {
		// One session across every proxied subdomain, and sign-in redirects
		// that point back at the gateway's own host rather than at /login on a
		// proxied one, where that route does not exist.
		cookieDomain = "." + c.baseDomain
		nextDomain = c.baseDomain
		scheme := "http"
		if serveTLS {
			scheme = "https"
		}
		host := c.baseDomain
		if c.publicPort != "" {
			host = net.JoinHostPort(host, c.publicPort)
		}
		loginOrigin = scheme + "://" + host
	}

	return auth.New(auth.Options{
		Store:             store,
		Mailer:            mailer,
		MailSubject:       c.mailSubject,
		SessionTTL:        c.sessionTTL,
		CodeTTL:           c.codeTTL,
		Secure:            serveTLS,
		CookieDomain:      cookieDomain,
		LoginOrigin:       loginOrigin,
		NextDomain:        nextDomain,
		TrustForwardedFor: c.trustForwarded,
		Logger:            logger,
	})
}

func warn(c config, logger *log.Logger) {
	if c.ignoreEmail {
		logger.Print("warning: -ignore-email prints login codes to this console; never use it in production")
	}
	if c.allowPrivate {
		logger.Print("warning: -allow-private lets the gateway reach loopback and RFC1918 addresses")
	}
	if c.insecureTLS {
		logger.Print("warning: -insecure-tls disables upstream certificate verification")
	}
	if c.urlMode == "wrd" && c.urlKey == webvpn.DefaultWRDKey {
		logger.Print("warning: -url-mode wrd is using the well-known default key; target hostnames are readable by anyone")
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// identity adapts the auth manager to what the gateway needs to know.
type identity struct{ m *auth.Manager }

func (i identity) User(r *http.Request) (string, bool, bool) {
	s, ok := i.m.SessionFor(r)
	if !ok {
		return "", false, false
	}
	return s.Email, s.Admin, true
}
