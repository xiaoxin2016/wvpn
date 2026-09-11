// Command webvpn runs a WebVPN gateway: a browser signs in with an e-mail
// one-time code, then reaches http/https sites through this process, which
// rewrites every response so the browser never talks to the origin directly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/xiaoxin2016/wvpn/internal/auth"
	"github.com/xiaoxin2016/wvpn/internal/store"
	"github.com/xiaoxin2016/wvpn/internal/webvpn"
)

// Build information, injected with -ldflags by the release workflow.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
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
	smtpTLSMode  string
	smtpPlain    bool
	smtpHELO     string
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
	flag.StringVar(&c.resource, "bookmarks", "", "JSON file of portal links, imported once on first run; afterwards the admin console owns them")

	flag.StringVar(&c.urlMode, "url-mode", "plain", "target encoding: plain | wrd | subdomain")
	flag.StringVar(&c.urlKey, "url-key", webvpn.DefaultWRDKey, "AES key for -url-mode wrd (16, 24 or 32 bytes)")
	flag.StringVar(&c.baseDomain, "base-domain", "", "wildcard domain for -url-mode subdomain, e.g. webvpn.example.com")
	flag.StringVar(&c.publicPort, "public-port", "", "port browsers reach the gateway on, for -url-mode subdomain")

	flag.StringVar(&c.allowHosts, "allow", "", "hard allowlist of target hosts (suffix match), applied on top of the console's site policy; empty means any")
	flag.StringVar(&c.denyHosts, "deny", "", "hard denylist of target hosts (suffix match), applied on top of the console's site policy")
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
	flag.StringVar(&c.smtpTLSMode, "smtp-tls-mode", store.TLSAuto,
		"SMTP transport security: auto (STARTTLS when offered) | require | none | implicit (direct TLS, port 465)")
	flag.BoolVar(&c.smtpPlain, "smtp-allow-plaintext-auth", false,
		"allow SMTP AUTH over an unencrypted connection, as an internal relay on port 25 may require")
	flag.StringVar(&c.smtpHELO, "smtp-helo", "", "name announced in EHLO; some relays reject the default")
	flag.BoolVar(&c.smtpInsecure, "smtp-insecure", false, "skip SMTP certificate verification")
	flag.StringVar(&c.mailSubject, "mail-subject", "", "subject line of the code e-mail")

	flag.BoolVar(&c.trustForwarded, "trust-proxy-headers", false,
		"believe X-Real-IP / X-Forwarded-For from any peer; they are honoured from loopback peers regardless")
	flag.BoolVar(&c.trustForwarded, "trust-forwarded-for", false, "deprecated alias of -trust-proxy-headers")
	showVersion := flag.Bool("version", false, "print build information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("webvpn %s (commit %s, built %s, %s)\n", version, commit, buildDate, runtime.Version())
		return
	}

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

	switch c.smtpTLSMode {
	case store.TLSAuto, store.TLSRequire, store.TLSNone, store.TLSImplicit:
	default:
		return fmt.Errorf("unknown -smtp-tls-mode %q (want auto, require, none or implicit)", c.smtpTLSMode)
	}

	codec, err := buildCodec(c, serveTLS)
	if err != nil {
		return err
	}

	// One JSON file holds everything an admin can change at runtime: who may
	// sign in, which sites are reachable, and the portal's bookmarks.
	cfg, err := store.LoadStore(c.configPath, store.Config{
		DefaultDomain: c.defaultDomain,
		AllowedUsers:  splitCSV(c.allowUsers),
		Admins:        splitCSV(c.admins),
	})
	if err != nil {
		return err
	}
	if err := seedBookmarks(cfg, c.resource, logger); err != nil {
		return err
	}

	// The command-line lists stay the operator's hard boundary; the store is
	// the layer the admin console edits. Both are consulted.
	guard := webvpn.NewGuard(c.allowHosts, c.denyHosts, c.allowPrivate)
	guard.Site = sitePolicy{cfg}

	gateway := webvpn.New(webvpn.Options{
		Codec:                 codec,
		Guard:                 guard,
		MaxRewriteBytes:       c.maxRewrite,
		DialTimeout:           c.dialTimeout,
		ResponseHeaderTimeout: c.respTimeout,
		InsecureTLS:           c.insecureTLS,
		Portal: webvpn.Portal{
			Name:      c.portal,
			Bookmarks: func() []webvpn.Category { return categories(cfg) },
		},
		Logger: logger,
	})

	mux := http.NewServeMux()
	var handler http.Handler = gateway

	// With no administrator configured, nobody can sign in and nobody can fix
	// that from inside the product — so the first run is bootstrapped through a
	// setup page gated on a token printed below.
	setupToken := ""
	if !c.noAuth && len(cfg.Get().Admins) == 0 {
		setupToken, err = auth.NewSetupToken()
		if err != nil {
			return err
		}
	}

	if c.noAuth {
		logger.Print("warning: -no-auth is set; anyone who can reach this port can use the gateway")
	} else {
		manager, err := buildAuth(c, cfg, setupToken, serveTLS, logger)
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
	logger.Printf("webvpn %s listening on %s://%s (url-mode=%s)", version, scheme, ln.Addr(), codec.Name())
	if setupToken != "" {
		logger.Print(setupBanner(scheme, ln.Addr().String(), setupToken))
	}

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

func buildAuth(c config, cfg *store.Store, setupToken string, serveTLS bool, logger *log.Logger) (*auth.Manager, error) {
	mailer, err := buildMailer(c, cfg, setupToken != "", logger)
	if err != nil {
		return nil, err
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
		Store:             cfg,
		Mailer:            mailer,
		MailSubject:       c.mailSubject,
		MailNotice:        mailNotice(c, cfg),
		SetupToken:        setupToken,
		SessionTTL:        c.sessionTTL,
		CodeTTL:           c.codeTTL,
		Secure:            serveTLS,
		CookieDomain:      cookieDomain,
		LoginOrigin:       loginOrigin,
		NextDomain:        nextDomain,
		TrustProxyHeaders: c.trustForwarded,
		AdminNotice:       adminNotice(c),
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
	if c.smtpPlain {
		logger.Print("warning: -smtp-allow-plaintext-auth sends the SMTP password over an unencrypted connection")
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

// sitePolicy adapts the configuration store to what the gateway's guard needs.
// The two packages stay independent of each other; only this file knows both.
type sitePolicy struct{ s *store.Store }

func (p sitePolicy) RequiresMatch() bool { return p.s.RequiresMatch() }
func (p sitePolicy) HasAddrRules() bool  { return p.s.HasAddrRules() }

func (p sitePolicy) HostVerdict(host string) webvpn.Verdict {
	return verdict(p.s.HostVerdict(host))
}

func (p sitePolicy) AddrVerdict(addr netip.Addr) webvpn.Verdict {
	return verdict(p.s.AddrVerdict(addr))
}

func verdict(v store.Verdict) webvpn.Verdict {
	switch v {
	case store.Allow:
		return webvpn.VerdictAllow
	case store.Deny:
		return webvpn.VerdictDeny
	}
	return webvpn.VerdictNeutral
}

// categories converts the stored bookmarks into the portal's own shape.
func categories(s *store.Store) []webvpn.Category {
	groups := s.Get().Bookmarks
	out := make([]webvpn.Category, 0, len(groups))
	for _, g := range groups {
		items := make([]webvpn.Bookmark, 0, len(g.Items))
		for _, it := range g.Items {
			items = append(items, webvpn.Bookmark{Name: it.Name, URL: it.URL, Note: it.Note})
		}
		out = append(out, webvpn.Category{Name: g.Name, Items: items})
	}
	return out
}

// seedBookmarks imports a bookmark file the first time the gateway runs. After
// that the admin console owns the list, and the file is ignored.
func seedBookmarks(s *store.Store, path string, logger *log.Logger) error {
	if path == "" {
		return nil
	}
	if len(s.Get().Bookmarks) > 0 {
		logger.Printf("bookmarks already configured; ignoring %s", path)
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var groups []store.Group
	if err := json.Unmarshal(data, &groups); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	cfg := s.Get()
	cfg.Bookmarks = groups
	if err := s.Set(cfg); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	logger.Printf("imported %d bookmark groups from %s", len(groups), path)
	return nil
}

// adminNotice tells admins about the limits the console cannot widen, so a
// puzzling "目标被网关策略拒绝" has an explanation on the page that seems to
// control it.
func adminNotice(c config) string {
	var parts []string
	if c.allowHosts != "" {
		parts = append(parts, "仅允许 "+c.allowHosts)
	}
	if c.denyHosts != "" {
		parts = append(parts, "禁止 "+c.denyHosts)
	}
	if !c.allowPrivate {
		parts = append(parts, "拒绝环回与内网地址")
	}
	if len(parts) == 0 {
		return ""
	}
	return "启动参数已设定的硬性边界（本页无法放宽）：" + strings.Join(parts, "；") + "。"
}

// buildMailer picks how verification codes leave the process. The admin console
// wins when it has a service configured; the command line is the fallback, and
// -ignore-email overrides both so a developer never depends on real mail.
func buildMailer(c config, cfg *store.Store, awaitingSetup bool, logger *log.Logger) (auth.Mailer, error) {
	if c.ignoreEmail {
		return auth.ConsoleMailer{Logger: logger}, nil
	}

	var fallback auth.Mailer
	if c.smtpAddr != "" {
		from := c.smtpFrom
		if from == "" {
			from = c.smtpUser
		}
		if from == "" {
			return nil, errors.New("-smtp-from is required when sending mail")
		}
		fallback = auth.SMTPMailer{
			Addr:               c.smtpAddr,
			From:               from,
			Username:           c.smtpUser,
			Password:           c.smtpPass,
			TLSMode:            c.smtpTLSMode,
			AllowPlaintextAuth: c.smtpPlain,
			HELO:               c.smtpHELO,
			InsecureSkipVerify: c.smtpInsecure,
		}
	}

	if fallback == nil && !cfg.Get().SMTP.Configured() && !awaitingSetup {
		// Not fatal during first-run setup: configuring SMTP is part of it.
		return nil, errors.New("no way to deliver codes: configure SMTP in the admin console, " +
			"pass -smtp-addr, or use -ignore-email for local testing")
	}
	return auth.StoreMailer{Store: cfg, Fallback: fallback}, nil
}

// mailNotice explains on the admin page when the command line overrides, or
// stands in for, what the console configures.
func mailNotice(c config, cfg *store.Store) string {
	switch {
	case c.ignoreEmail:
		return "当前以 -ignore-email 启动：验证码只会打印到进程日志，本节配置不会生效。"
	case c.smtpAddr != "" && !cfg.Get().SMTP.Configured():
		return "当前使用启动参数 -smtp-addr 指定的服务（" + c.smtpAddr + "）；在此填写并保存后将改用本页配置。"
	}
	return ""
}

// setupBanner is printed once, on a gateway that has no administrator yet. The
// token is the only credential that exists at that point, and reading the
// process log is what proves you are the operator.
func setupBanner(scheme, addr, token string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		host, port = addr, ""
	}
	switch host {
	case "", "::", "0.0.0.0", "[::]":
		// Listening on every interface says nothing about how to reach it.
		host = "localhost"
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	line := strings.Repeat("─", 66)
	return "\n" + line + "\n" +
		"  首次启动：尚未配置管理员\n" +
		"  请在浏览器中打开以下链接完成初始化：\n\n" +
		"    " + scheme + "://" + host + "/setup?token=" + token + "\n\n" +
		"  该令牌仅在本次进程内有效，管理员首次登录成功后即失效。\n" +
		"  若网关对外使用其他域名，请把上面的主机名换成对应地址。\n" +
		line
}
