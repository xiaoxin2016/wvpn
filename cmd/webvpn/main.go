// Command webvpn runs a WebVPN gateway: a browser signs in with an e-mail
// one-time code, then reaches http/https sites through this process, which
// rewrites every response so the browser never talks to the origin directly.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
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
	portalHost string
	publicPort string

	allowHosts   string
	denyHosts    string
	allowPrivate bool
	insecureTLS  bool
	jsRewrite    string
	maxRewrite   int64
	dialTimeout  time.Duration
	respTimeout  time.Duration

	noAuth        bool
	configPath    string
	defaultDomain string
	allowUsers    string
	admins        string
	sessionTTL    time.Duration
	logHeaders    bool
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

	flag.StringVar(&c.urlMode, "url-mode", "", "initial target encoding: plain | wrd | subdomain; the console owns it afterwards")
	flag.StringVar(&c.urlKey, "url-key", webvpn.DefaultWRDKey, "AES key for -url-mode wrd (16, 24 or 32 bytes)")
	flag.StringVar(&c.baseDomain, "base-domain", "", "initial wildcard domain targets are addressed under, e.g. intra.corp.com")
	flag.StringVar(&c.portalHost, "portal-host", "", "initial name for the portal itself; defaults to app.<base-domain>")
	flag.StringVar(&c.publicPort, "public-port", "", "initial port browsers reach the gateway on, when not the scheme default")

	flag.StringVar(&c.allowHosts, "allow", "", "hard allowlist of target hosts (suffix match), applied on top of the console's site policy; empty means any")
	flag.StringVar(&c.denyHosts, "deny", "", "hard denylist of target hosts (suffix match), applied on top of the console's site policy")
	flag.BoolVar(&c.allowPrivate, "allow-private", false, "allow targets that resolve to loopback/private/link-local addresses")
	flag.BoolVar(&c.insecureTLS, "insecure-tls", false, "skip certificate verification for upstream HTTPS")
	flag.StringVar(&c.jsRewrite, "js-rewrite", "related",
		"rewrite absolute URLs inside scripts and JSON: off | related (same registrable domain) | all")
	flag.Int64Var(&c.maxRewrite, "max-rewrite-bytes", 8<<20, "largest response body that gets rewritten")
	flag.DurationVar(&c.dialTimeout, "dial-timeout", 10*time.Second, "upstream dial timeout")
	flag.DurationVar(&c.respTimeout, "response-timeout", 30*time.Second, "upstream response header timeout")

	flag.BoolVar(&c.noAuth, "no-auth", false, "disable sign-in entirely (development only)")
	flag.StringVar(&c.configPath, "config", "webvpn-config.json", "file holding the admin-editable access policy")
	flag.StringVar(&c.defaultDomain, "default-domain", "", "initial default e-mail domain, e.g. test.com")
	flag.StringVar(&c.allowUsers, "allow-user", "", "initial comma-separated allowlist of accounts, e.g. \"*@test.com\"")
	flag.StringVar(&c.admins, "admin", "", "initial comma-separated admin accounts")
	flag.BoolVar(&c.logHeaders, "log-headers", false,
		"log every proxied request's outbound headers and every Set-Cookie, to compare with what a browser sends directly; writes cookies and tokens in clear")
	flag.DurationVar(&c.sessionTTL, "session-ttl", time.Hour,
		"how long a sign-in survives without use; the console can change it afterwards")
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

	switch c.smtpTLSMode {
	case store.TLSAuto, store.TLSRequire, store.TLSNone, store.TLSImplicit:
	default:
		return fmt.Errorf("unknown -smtp-tls-mode %q (want auto, require, none or implicit)", c.smtpTLSMode)
	}

	jsScope, err := webvpn.ParseJSScope(c.jsRewrite)
	if err != nil {
		return err
	}

	// One JSON file holds everything an admin can change at runtime: who may
	// sign in, which sites are reachable, how targets are addressed, and the
	// portal's bookmarks.
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
	if err := seedGateway(cfg, c, logger); err != nil {
		return err
	}

	// TLS material comes from the console unless files were named on the
	// command line. Whether the port speaks TLS is settled here, at startup: a
	// plain listener cannot start negotiating TLS later. The certificate behind
	// it is read per handshake, so a renewal needs no restart.
	certs, err := newCertSource(cfg, c.tlsCert, c.tlsKey, logger)
	if err != nil {
		return err
	}
	serveTLS := certs.active()

	// The addressing scheme is read per request, so switching URL mode in the
	// console takes effect without a restart.
	codecs := &codecCache{store: cfg, wrdKey: c.urlKey, tls: serveTLS, logger: logger}
	if _, err := codecs.build(cfg.Get().Gateway); err != nil {
		return err
	}

	// The command-line lists stay the operator's hard boundary; the store is
	// the layer the admin console edits. Both are consulted.
	guard := webvpn.NewGuard(c.allowHosts, c.denyHosts, c.allowPrivate)
	guard.Site = sitePolicy{cfg}

	gateway := webvpn.New(webvpn.Options{
		CodecFor:              codecs.get,
		Guard:                 guard,
		MaxRewriteBytes:       c.maxRewrite,
		DialTimeout:           c.dialTimeout,
		ResponseHeaderTimeout: c.respTimeout,
		InsecureTLS:           c.insecureTLS,
		JSScope:               jsScope,
		RestoreFor: func(target *url.URL) bool {
			return cfg.RestoresAddresses(target.Host)
		},
		ForceSecure: cfg.PublicHTTPS,
		ForwardFor:  cfg.ForwardsFor,
		LogHeaders:  c.logHeaders,
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
		gateway.SetClientIP(manager.ClientIP)
		handler = manager.Require(gateway)
		manager.SetFallback(handler)
		manager.Routes(mux)
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
	logger.Printf("webvpn %s listening on %s://%s (url-mode=%s)", version, scheme, ln.Addr(), codecs.get().Name())
	if setupToken != "" {
		logger.Print(setupBanner(scheme, ln.Addr().String(), setupToken))
	}

	if serveTLS {
		ln = tls.NewListener(ln, &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: certs.get,
		})
	}

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

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

// codecCache builds the addressing scheme from the stored settings, rebuilding
// only when they change: a request reads it on every hop.
type codecCache struct {
	store  *store.Store
	wrdKey string
	tls    bool
	logger *log.Logger

	mu     sync.Mutex
	key    store.Gateway
	codec  webvpn.Codec
	warned bool
}

func (c *codecCache) get() webvpn.Codec {
	g := c.store.Get().Gateway
	c.mu.Lock()
	if c.codec != nil && c.key == g {
		defer c.mu.Unlock()
		return c.codec
	}
	c.mu.Unlock()

	codec, err := c.build(g)
	if err != nil {
		// Keep serving rather than failing every request; the console is how
		// the operator fixes this, and the console lives behind this handler.
		c.mu.Lock()
		if !c.warned {
			c.logger.Printf("warning: unusable URL settings (%v); falling back to the plain path form", err)
			c.warned = true
		}
		c.mu.Unlock()
		return webvpn.PlainCodec{}
	}
	return codec
}

// build makes the codec for a set of settings and caches it.
func (c *codecCache) build(g store.Gateway) (webvpn.Codec, error) {
	var (
		codec webvpn.Codec
		err   error
	)
	switch g.Mode() {
	case store.URLWRD:
		codec, err = webvpn.NewWRDCodec(c.wrdKey)
	case store.URLSubdomain:
		codec, err = webvpn.NewHostCodec(g.BaseDomain, g.PortalHost(), g.PublicPort, c.tls)
	default:
		codec = webvpn.PlainCodec{}
	}
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.key, c.codec, c.warned = g, codec, false
	c.mu.Unlock()
	return codec, nil
}

// siteInfo tells the identity layer where the gateway itself lives, which only
// differs from "everywhere" under the subdomain URL mode.
func siteInfo(cfg *store.Store, serveTLS bool) auth.SiteInfo {
	g := cfg.Get().Gateway
	if g.Mode() != store.URLSubdomain || g.BaseDomain == "" {
		return auth.SiteInfo{}
	}
	portal := g.PortalHost()
	host := portal
	if g.PublicPort != "" {
		host = net.JoinHostPort(host, g.PublicPort)
	}
	scheme := "http"
	if serveTLS {
		scheme = "https"
	}
	return auth.SiteInfo{
		GatewayHost: portal,
		// One sign-in covers the portal and every target sub-domain, which all
		// live under the wildcard domain.
		CookieDomain: "." + g.BaseDomain,
		LoginOrigin:  scheme + "://" + host,
		NextDomain:   g.BaseDomain,
	}
}

// seedGateway writes the URL settings given on the command line the first time
// the gateway runs. After that the console owns them.
func seedGateway(cfg *store.Store, c config, logger *log.Logger) error {
	if c.urlMode == "" && c.baseDomain == "" && c.portalHost == "" && c.publicPort == "" {
		return nil
	}
	current := cfg.Get()
	if current.Gateway.URLMode != "" {
		logger.Printf("URL settings already configured (mode=%s); ignoring the command-line values",
			current.Gateway.Mode())
		return nil
	}
	current.Gateway = store.Gateway{
		URLMode:    c.urlMode,
		BaseDomain: c.baseDomain,
		Host:       c.portalHost,
		PublicPort: c.publicPort,
	}
	if err := cfg.Set(current); err != nil {
		return err
	}
	logger.Printf("URL settings seeded from the command line (mode=%s)", current.Gateway.Mode())
	return nil
}

func buildAuth(c config, cfg *store.Store, setupToken string, serveTLS bool, logger *log.Logger) (*auth.Manager, error) {
	mailer, err := buildMailer(c, cfg, setupToken != "", logger)
	if err != nil {
		return nil, err
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
		Site:              func() auth.SiteInfo { return siteInfo(cfg, serveTLS) },
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
	if c.logHeaders {
		logger.Print("warning: -log-headers writes session cookies and tokens to this log in clear; turn it off once the problem is understood")
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

// certSource supplies the gateway's own certificate. Files named on the command
// line win; otherwise it comes from the console, and is re-read on every
// handshake so a renewal takes effect without a restart.
type certSource struct {
	store    *store.Store
	fileCert *tls.Certificate
	logger   *log.Logger

	mu     sync.Mutex
	cached *tls.Certificate
	from   store.TLS
}

func newCertSource(cfg *store.Store, certFile, keyFile string, logger *log.Logger) (*certSource, error) {
	c := &certSource{store: cfg, logger: logger}
	switch {
	case certFile != "" && keyFile != "":
		pair, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", certFile, err)
		}
		c.fileCert = &pair
		if cfg.Get().TLS.Configured() {
			logger.Print("a certificate is configured in the console, but -tls-cert/-tls-key take precedence")
		}
	case certFile != "" || keyFile != "":
		return nil, errors.New("-tls-cert and -tls-key must be given together")
	}
	if c.fileCert == nil && cfg.Get().TLS.Configured() {
		// Fail fast on a certificate the console cannot have validated, e.g.
		// one hand-edited into the file.
		if _, err := cfg.Get().TLS.Certificate(); err != nil {
			return nil, fmt.Errorf("the stored certificate is unusable: %w", err)
		}
	}
	return c, nil
}

// active reports whether the listener should speak TLS at all. This is decided
// once, at startup: a plain listener cannot start negotiating TLS later.
func (c *certSource) active() bool {
	return c.fileCert != nil || c.store.Get().TLS.Configured()
}

func (c *certSource) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.fileCert != nil {
		return c.fileCert, nil
	}
	current := c.store.Get().TLS
	if !current.Configured() {
		return nil, errors.New("no certificate is configured")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cached != nil && c.from == current {
		return c.cached, nil
	}
	pair, err := current.Certificate()
	if err != nil {
		return nil, err
	}
	c.cached, c.from = &pair, current
	c.logger.Print("loaded the certificate configured in the console")
	return c.cached, nil
}
