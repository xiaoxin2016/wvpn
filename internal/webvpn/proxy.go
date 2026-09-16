package webvpn

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Identity reports who is behind a request. It is satisfied by the auth
// package; the gateway only needs the answer, not the mechanism.
type Identity interface {
	User(r *http.Request) (email string, admin bool, ok bool)
}

// Options configures a gateway Handler.
type Options struct {
	// Codec encodes targets into gateway references. Defaults to PlainCodec.
	Codec Codec
	// CodecFor, when set, is consulted on every request instead of Codec, so
	// the admin console can change how targets are addressed without a
	// restart.
	CodecFor func() Codec
	Guard    *Guard

	// MaxRewriteBytes caps how much of a response body is buffered for
	// rewriting; larger bodies stream through untouched.
	MaxRewriteBytes int64
	// DialTimeout and ResponseHeaderTimeout bound the upstream fetch.
	DialTimeout           time.Duration
	ResponseHeaderTimeout time.Duration
	// InsecureTLS disables upstream certificate verification.
	InsecureTLS bool
	// JSScope bounds the rewriting of absolute URLs inside scripts and JSON.
	JSScope JSScope

	// LogHeaders writes every proxied request's outbound headers and every
	// response's Set-Cookie to the log. It is a debugging aid for working out
	// how a request the gateway sends differs from the one a browser would have
	// sent directly, and it writes session cookies and tokens in clear.
	LogHeaders bool

	// ForwardFor reports whether the browser's address is passed on to the
	// target in X-Forwarded-For. Nil withholds it, which is the default: a
	// gateway is partly there so the target does not learn who is behind it.
	ForwardFor func() bool
	// ClientIP is the address the gateway holds this request's browser at.
	ClientIP func(r *http.Request) string

	// ForceSecure declares that browsers reach this gateway over https even
	// though this process serves plain http — TLS terminated in front of it.
	// Without it the scheme is read from the request, which needs the proxy to
	// pass X-Forwarded-Proto.
	ForceSecure func() bool

	// RestoreFor reports whether outbound parameters aimed at a target should
	// have gateway addresses put back to the addresses they stand for, which
	// is what makes single sign-on work. Nil restores for every target.
	RestoreFor func(target *url.URL) bool

	// SessionCookie names the gateway's own session cookie, which must never
	// be forwarded to a proxied origin.
	SessionCookie string
	Identity      Identity
	// Portal is the content of the landing page.
	Portal Portal

	Logger *log.Logger
}

// Handler is the gateway: landing page, client shim, and proxied traffic.
type Handler struct {
	opts  Options
	plain PlainCodec
	rp    *httputil.ReverseProxy
	log   *log.Logger
	// trust holds the upstream certificates a user has confirmed by hand.
	trust *trustStore
	// jars hold the domain-scoped cookies that single sign-on depends on.
	jars *sessionJars
	// pages remember where each browser is, for requests that carry the
	// gateway's bare origin and no Referer to explain it.
	pages *pageMemory
}

type ctxKey struct{}

// reqInfo travels with the outbound request so ModifyResponse knows what was
// asked for and how the browser leg is secured.
type reqInfo struct {
	target *url.URL
	secure bool
	// site carries the name-phase site-policy result into the dial-time check.
	site SiteCheck
	// jarKey identifies the browser's server-side cookie jar.
	jarKey string
	// page is the real address of the document this request belongs to, as far
	// as the gateway can tell. It is what the gateway's bare origin stands for.
	page *url.URL
	// browserHost is the gateway host the browser asked, which is the only way
	// to name the gateway in an address a script will hold on to.
	browserHost string
	// clientIP is where the browser is, for the targets that are told.
	clientIP string
}

func withInfo(ctx context.Context, info *reqInfo) context.Context {
	return context.WithValue(ctx, ctxKey{}, info)
}

func infoFrom(ctx context.Context) *reqInfo {
	info, _ := ctx.Value(ctxKey{}).(*reqInfo)
	return info
}

// siteCheckFrom reports the name-phase site result carried by a request.
func siteCheckFrom(ctx context.Context) SiteCheck {
	if info := infoFrom(ctx); info != nil {
		return info.site
	}
	return SiteCheck{}
}

const (
	shimPath    = "/_wv/shim.js"
	gotoPath    = "/_wv/go"
	trustPath   = "/_wv/trust"
	cookieRoute = "/_wv/cookie"
	assetPath   = "/_wv/"
	portalPath  = "/"
)

// New builds a gateway Handler.
func New(opts Options) *Handler {
	if opts.Codec == nil {
		opts.Codec = PlainCodec{}
	}
	if opts.Guard == nil {
		opts.Guard = &Guard{}
	}
	if opts.MaxRewriteBytes <= 0 {
		opts.MaxRewriteBytes = 8 << 20
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.ResponseHeaderTimeout <= 0 {
		opts.ResponseHeaderTimeout = 30 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = log.Default()
	}

	h := &Handler{
		opts:  opts,
		log:   opts.Logger,
		trust: newTrustStore(),
		jars:  newSessionJars(),
		pages: newPageMemory(),
	}

	dialer := &net.Dialer{
		Timeout:        opts.DialTimeout,
		KeepAlive:      30 * time.Second,
		ControlContext: opts.Guard.DialControl(siteCheckFrom),
	}
	transport := &http.Transport{
		Proxy:       http.ProxyFromEnvironment,
		DialContext: dialer.DialContext,
		// TLS is dialed by hand so an unverifiable certificate becomes a
		// question for the user instead of a dead end.
		DialTLSContext:        h.dialTLS(dialer),
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		// Content coding is negotiated explicitly in rewriteRequest so the
		// rewriter only ever has to undo gzip.
		DisableCompression: true,
	}

	h.rp = &httputil.ReverseProxy{
		Transport:      transport,
		Rewrite:        h.rewriteRequest,
		ModifyResponse: h.modifyResponse,
		ErrorHandler:   h.handleError,
		ErrorLog:       opts.Logger,
	}
	return h
}

// codec returns the addressing scheme in force right now. It is read per
// request so that switching URL mode in the console takes effect immediately.
func (h *Handler) codec() Codec {
	if h.opts.CodecFor != nil {
		if c := h.opts.CodecFor(); c != nil {
			return c
		}
	}
	if h.opts.Codec != nil {
		return h.opts.Codec
	}
	return h.plain
}

// restores reports whether outbound parameters aimed at target are restored.
func (h *Handler) restores(target *url.URL) bool {
	if h.opts.RestoreFor == nil {
		return true
	}
	return h.opts.RestoreFor(target)
}

// codecSecure returns the addressing scheme in force, told whether the browser's
// leg is TLS. See codecFor for why that is not this process's own scheme.
func (h *Handler) codecSecure(secure bool) Codec {
	c := h.codec()
	if hc, ok := c.(*HostCodec); ok && hc.TLS != secure {
		clone := *hc
		clone.TLS = secure
		return &clone
	}
	return c
}

// codecFor returns the addressing scheme in force, told how the browser reached
// the gateway.
//
// The sub-domain codec writes absolute addresses, and their scheme has to be the
// one the browser is using. Reading it off this process is wrong wherever TLS is
// terminated in front of the gateway: the page arrives over https and every
// address written into it says http, which is a different origin to the browser
// — mixed content, a preflight on every request, and a redirect back to https
// that a preflight is not allowed to follow.
func (h *Handler) codecFor(info *reqInfo) Codec {
	return h.codecSecure(info != nil && info.secure)
}

// isSecure reports whether the browser's leg to the gateway is TLS.
func (h *Handler) isSecure(r *http.Request) bool {
	if h.opts.ForceSecure != nil && h.opts.ForceSecure() {
		return true
	}
	return isSecureRequest(r)
}

// rewriter builds a rewriter for the codec currently in force. info carries the
// gateway origin the browser is using, which scripts are rewritten against; it
// may be nil where no request is in hand.
func (h *Handler) rewriter(info *reqInfo) Rewriter {
	return Rewriter{Codec: h.codecFor(info), Scope: h.opts.JSScope, Origin: info.gatewayOrigin()}
}

// gatewayOrigin is the gateway as this browser reaches it, or "" when it is not
// known.
func (info *reqInfo) gatewayOrigin() string {
	if info == nil || info.browserHost == "" {
		return ""
	}
	scheme := "http"
	if info.secure {
		scheme = "https"
	}
	return scheme + "://" + info.browserHost
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.EscapedPath()
	switch {
	// Gateway assets come first: under the subdomain codec every path on a
	// proxied host would otherwise be forwarded upstream, shim included.
	case path == shimPath:
		serveShim(w, r)
	case path == gotoPath:
		h.serveGoto(w, r)
	case path == trustPath:
		h.serveTrust(w, r)
	case path == cookieRoute:
		h.serveCookie(w, r)
	case strings.HasPrefix(path, assetPath):
		http.NotFound(w, r)
	case h.plain.Match(r.Host, path):
		h.serveProxy(w, r, h.plain)
	case h.codec().Match(r.Host, path):
		h.serveProxy(w, r, h.codec())
	case path == portalPath || path == "/index.html":
		h.servePortal(w, r)
	default:
		h.serveStray(w, r)
	}
}

// serveGoto turns a URL typed into the portal into a redirect into the proxy.
func (h *Handler) serveGoto(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("url")
	if raw == "" && r.Method == http.MethodPost {
		_ = r.ParseForm()
		raw = r.PostFormValue("url")
	}
	target, err := ParseUserInput(raw)
	if err != nil {
		http.Error(w, "请输入合法的 http/https 地址", http.StatusBadRequest)
		return
	}
	if _, err := h.opts.Guard.CheckTarget(target.Host, h.siteExempt(r)); err != nil {
		http.Error(w, "目标被网关策略拒绝: "+err.Error(), http.StatusForbidden)
		return
	}
	ref := h.codecSecure(h.isSecure(r)).Encode(target)
	if ref == "" {
		http.Error(w, "无法编码该目标地址", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, ref, http.StatusFound)
}

// serveStray catches requests that escaped rewriting — a URL a script built
// from location.origin, or a root-relative one the shim did not cover. Under
// the path codec the gateway has nothing at such a path, and answering 404 is
// what a page reports as "failed to load"; it is nearly always a request meant
// for the site the browser is reading.
func (h *Handler) serveStray(w http.ResponseWriter, r *http.Request) {
	base := h.strayBase(r)
	if base == nil {
		http.NotFound(w, r)
		return
	}
	target, err := base.Parse(r.URL.RequestURI())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if enc := h.codecSecure(h.isSecure(r)).Encode(target); enc != "" {
		h.log.Printf("stray %s %s -> %s", r.Method, r.URL.RequestURI(), target)
		http.Redirect(w, r, enc, http.StatusTemporaryRedirect)
		return
	}
	http.NotFound(w, r)
}

// strayBase works out which site a stray request was meant for. The Referer
// names the page exactly and is tried first; a browser whose site suppresses it
// is attributed to the document that browser is currently on.
func (h *Handler) strayBase(r *http.Request) *url.URL {
	if ref, err := url.Parse(r.Header.Get("Referer")); err == nil && ref.Host != "" {
		if base, err := h.decode(ref.Host, ref.EscapedPath(), ref.RawQuery); err == nil {
			return base
		}
	}
	return h.pages.current(h.browserKey(r))
}

// serveCookie takes a cookie a page wrote through document.cookie and, when it
// names a domain, keeps it in that browser's jar — the same place a Set-Cookie
// header with a Domain attribute goes. The page keeps its own copy for the site
// it is on; this is what carries the cookie to the other hosts in the domain,
// which behind one origin the browser cannot do.
func (h *Handler) serveCookie(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "只接受 POST", http.StatusMethodNotAllowed)
		return
	}
	var in struct {
		Target string `json:"t"`
		Cookie string `json:"c"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<10)).Decode(&in); err != nil {
		http.Error(w, "无法解析请求", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(in.Target)
	if err != nil || target.Host == "" || !SchemeSupported(target.Scheme) {
		http.Error(w, "目标地址无效", http.StatusBadRequest)
		return
	}
	if _, err := h.opts.Guard.CheckTarget(target.Host, h.siteExempt(r)); err != nil {
		http.Error(w, "目标被网关策略拒绝", http.StatusForbidden)
		return
	}

	// Nothing below is an error the page can act on: a cookie the jar will not
	// take is simply one the browser's own copy has to carry.
	w.WriteHeader(http.StatusNoContent)

	sc, ok := parseSetCookie(in.Cookie)
	if !ok || sc.Name == h.opts.SessionCookie {
		return
	}
	// Only a cookie the target itself could have set is accepted, which is the
	// rule a browser applies to a Domain attribute.
	if toJar, _ := sc.domainScope(target); !toJar {
		return
	}
	key := h.sessionKey(r)
	if key == "" {
		return // no signed-in browser to attach a jar to
	}
	storeShared(h.jars.get(key), target, []*http.Cookie{sc.toHTTPCookie()})
}

// unwrapTarget repairs a target whose path carries a gateway reference of its
// own.
//
// A page that builds addresses out of where it currently is — "my base path,
// plus the path I am on" — reads location.pathname, and under the path codecs
// that carries the gateway's prefix. What comes back is /base/p/https/site/rest:
// the site asked for a path with the gateway folded into the middle of it, and
// every relative address on the page that follows is measured from there.
//
// Nothing can stop a page reading its own address — location is unforgeable —
// but the embedded reference names the path the page meant all along, so splice
// it back out: /base + /rest. Only a reference to the target's own host counts,
// which is what keeps a site that really does serve such a path from being
// rewritten out from under itself.
func (h *Handler) unwrapTarget(t *url.URL) *url.URL {
	out := t
	for hop := 0; hop < 4; hop++ {
		path := out.EscapedPath()
		var next *url.URL
		for i := 1; i < len(path) && next == nil; i++ {
			if path[i] != '/' {
				continue
			}
			inner, err := h.decode(out.Host, path[i:], out.RawQuery)
			if err != nil || !strings.EqualFold(inner.Host, out.Host) {
				continue
			}
			joined, err := url.Parse(path[:i] + inner.EscapedPath())
			if err != nil {
				continue
			}
			spliced := *out
			spliced.Path, spliced.RawPath = joined.Path, joined.RawPath
			next = &spliced
		}
		if next == nil {
			break
		}
		out = next
	}
	return out
}

// decode resolves an inbound request with whichever codec claims it.
func (h *Handler) decode(host, path, query string) (*url.URL, error) {
	if h.plain.Match(host, path) {
		return h.plain.Decode(host, path, query)
	}
	return h.codec().Decode(host, path, query)
}

func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, codec Codec) {
	target, err := codec.Decode(r.Host, r.URL.EscapedPath(), r.URL.RawQuery)
	if err != nil {
		http.Error(w, "无法解析目标地址", http.StatusBadRequest)
		return
	}
	// A page that folded the gateway into an address of its own is sent to the
	// address it meant, so that what it reads back about where it is — and
	// every relative reference measured from there — is the site's own.
	if fixed := h.unwrapTarget(target); fixed.String() != target.String() {
		if enc := h.codecSecure(h.isSecure(r)).Encode(fixed); enc != "" {
			h.log.Printf("unwrapped %s -> %s", target, fixed)
			code := http.StatusFound
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				code = http.StatusTemporaryRedirect
			}
			http.Redirect(w, r, enc, code)
			return
		}
	}

	check, err := h.opts.Guard.CheckTarget(target.Host, h.siteExempt(r))
	if err != nil {
		http.Error(w, "目标被网关策略拒绝: "+err.Error(), http.StatusForbidden)
		return
	}
	info := &reqInfo{
		target:      target,
		secure:      h.isSecure(r),
		site:        check,
		jarKey:      h.sessionKey(r),
		browserHost: r.Host,
	}
	if h.opts.ForwardFor != nil && h.opts.ForwardFor() && h.opts.ClientIP != nil {
		info.clientIP = h.opts.ClientIP(r)
	}
	info.page = h.pages.record(h.browserKey(r), target, isDocumentRequest(r))
	h.rp.ServeHTTP(w, r.WithContext(withInfo(r.Context(), info)))
}

// siteExempt reports whether this requester is exempt from the admin-editable
// site policy. Administrators are: the console they control must not be able to
// lock them out of the network they administer. The operator's own -allow/-deny
// lists and the internal-address guard still apply to them.
func (h *Handler) siteExempt(r *http.Request) bool {
	if h.opts.Identity == nil {
		return false
	}
	_, admin, ok := h.opts.Identity.User(r)
	return ok && admin
}

func isSecureRequest(r *http.Request) bool {
	return r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (h *Handler) rewriteRequest(pr *httputil.ProxyRequest) {
	info := infoFrom(pr.In.Context())
	if info == nil {
		return
	}
	target := info.target

	u := *target
	u.Scheme = httpScheme(target.Scheme)
	pr.Out.URL = &u
	pr.Out.Host = target.Host

	// The rewriter can only undo gzip, so do not let the browser negotiate br
	// or zstd on our behalf.
	pr.Out.Header.Set("Accept-Encoding", "gzip")

	// An address the browser carries in a parameter — a redirect_uri, a
	// service, a RelayState — is the gateway's, and the origin expects the
	// real one. This undoes the gateway's own rewriting for the trip out.
	if h.restores(target) {
		page := h.browserPage(info, pr.In)
		pr.Out.URL.RawQuery = h.restoreQuery(pr.Out.URL.RawQuery, page, pr.In.Host)
		h.restoreBody(pr.Out, page, pr.In.Host)
	}

	// Cookies are edited as text: parsing them into http.Cookie and writing
	// them back mangles or drops values the origin is entitled to send.
	header := pr.Out.Header.Get("Cookie")
	if name := h.opts.SessionCookie; name != "" {
		// The gateway's own session cookie must not reach the origin.
		header = filterCookieHeader(header, name)
	}
	jar := h.jars.lookup(info.jarKey)
	if jar != nil {
		header = appendCookiePairs(header, jarPairs(jar, target, cookieHeaderNames(header)))
	}
	// A name the browser holds twice is a cookie the site replaced and the
	// browser kept both of, because the gateway had to narrow the new one's
	// scope. Forward the one the site actually set.
	if cleaned, shadowed := resolveShadowedCookies(header, jarValues(jar, target)); len(shadowed) > 0 {
		h.log.Printf("cookie %s arrived more than once for %s; forwarded the value the site last set "+
			"(a copy from outside the tunnel is shadowing it — see docs/compatibility.md)",
			strings.Join(shadowed, ", "), target.Host)
		header = cleaned
	}
	if header == "" {
		pr.Out.Header.Del("Cookie")
	} else {
		pr.Out.Header.Set("Cookie", header)
	}

	// Referer and Origin must be expressed in the target's own terms, otherwise
	// origin-side same-site checks see the gateway and reject the request.
	if ref := pr.Out.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			if t, err := h.decode(u.Host, u.EscapedPath(), u.RawQuery); err == nil {
				pr.Out.Header.Set("Referer", t.String())
			} else {
				pr.Out.Header.Del("Referer")
			}
		} else {
			pr.Out.Header.Del("Referer")
		}
	}
	if o := pr.Out.Header.Get("Origin"); o != "" && o != "null" {
		// The browser names the gateway; the origin wants the site the page is
		// really on. Under the sub-domain codec that is recoverable, and has to
		// be: a cross-site request answered with Access-Control-Allow-Origin
		// naming the wrong site is refused by the browser. Under the path
		// codecs every page shares one origin and nothing can be recovered from
		// it, so the target's own is used, which is what a same-site request
		// would have carried anyway.
		real := target.Scheme + "://" + target.Host
		if u, err := url.Parse(o); err == nil && u.Host != "" {
			if t, err := h.decode(u.Host, "/", ""); err == nil {
				real = t.Scheme + "://" + t.Host
			}
		}
		pr.Out.Header.Set("Origin", real)
	}

	defer h.logRequest(pr)
	h.traceUpstream(pr)

	// Do not advertise the gateway to the origin: a forwarded host or scheme
	// would describe the gateway, not the site, and the site would believe it.
	pr.Out.Header.Del("X-Forwarded-Host")
	pr.Out.Header.Del("X-Forwarded-Proto")
	// Who is behind the gateway is the operator's call. What is forwarded is the
	// address the gateway itself settled on, not the chain the browser arrived
	// with — that chain is whatever a client cared to claim.
	if info.clientIP != "" {
		pr.Out.Header.Set("X-Forwarded-For", info.clientIP)
	} else {
		pr.Out.Header.Del("X-Forwarded-For")
	}
}

// traceUpstream reports which upstream address each request actually reached.
// A site behind a load balancer may keep its session on one node, and a session
// that works in a browser but not through the gateway is often a request that
// landed somewhere else.
func (h *Handler) traceUpstream(pr *httputil.ProxyRequest) {
	if !h.opts.LogHeaders {
		return
	}
	url := pr.Out.URL.String()
	trace := &httptrace.ClientTrace{
		GotConn: func(ci httptrace.GotConnInfo) {
			h.log.Printf("upstream conn %s -> %s (reused=%v)", url, ci.Conn.RemoteAddr(), ci.Reused)
		},
	}
	pr.Out = pr.Out.WithContext(httptrace.WithClientTrace(pr.Out.Context(), trace))
}

// logRequest records what the gateway is about to send upstream, next to what
// the browser asked for, so the two can be compared header by header.
func (h *Handler) logRequest(pr *httputil.ProxyRequest) {
	if !h.opts.LogHeaders {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "upstream %s %s\n", pr.Out.Method, pr.Out.URL)
	fmt.Fprintf(&b, "  Host: %s\n", pr.Out.Host)
	for _, k := range sortedKeys(pr.Out.Header) {
		for _, v := range pr.Out.Header[k] {
			fmt.Fprintf(&b, "  %s: %s\n", k, v)
		}
	}
	// What the browser sent, for the headers the gateway changed or dropped.
	for _, k := range sortedKeys(pr.In.Header) {
		if _, kept := pr.Out.Header[k]; !kept {
			for _, v := range pr.In.Header[k] {
				fmt.Fprintf(&b, "  (dropped) %s: %s\n", k, v)
			}
		}
	}
	h.log.Print(b.String())
}

// logResponse records what the origin set on the way back.
func (h *Handler) logResponse(resp *http.Response, raws []string) {
	if !h.opts.LogHeaders {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "origin %d %s\n", resp.StatusCode, resp.Request.URL)
	for _, raw := range raws {
		fmt.Fprintf(&b, "  (origin) Set-Cookie: %s\n", raw)
	}
	for _, v := range resp.Header.Values("Set-Cookie") {
		fmt.Fprintf(&b, "  (browser) Set-Cookie: %s\n", v)
	}
	h.log.Print(b.String())
}

func sortedKeys(h http.Header) []string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// strippedResponseHeaders would either pin the browser to the gateway origin or
// stop the rewritten page from loading its own resources.
var strippedResponseHeaders = []string{
	"Content-Security-Policy",
	"Content-Security-Policy-Report-Only",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"Public-Key-Pins",
	"Public-Key-Pins-Report-Only",
	"Cross-Origin-Opener-Policy",
	"Cross-Origin-Embedder-Policy",
	"Cross-Origin-Resource-Policy",
	"Clear-Site-Data",
	"Alt-Svc",
	"Report-To",
	"Reporting-Endpoints",
}

var linkURLRe = regexp.MustCompile(`<([^>]*)>`)

func (h *Handler) modifyResponse(resp *http.Response) error {
	info := infoFrom(resp.Request.Context())
	if info == nil {
		return nil
	}
	target := info.target

	for _, k := range strippedResponseHeaders {
		resp.Header.Del(k)
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		if u, err := target.Parse(strings.TrimSpace(loc)); err == nil {
			if enc := h.codecFor(info).Encode(u); enc != "" {
				resp.Header.Set("Location", enc)
			}
		}
	}

	// A site that answers a cross-site request names the origin it is willing
	// to serve. The browser compares that against the address bar, which is the
	// gateway's, so the name has to be translated the same way the address was.
	if acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin")); acao != "" &&
		acao != "*" && !strings.EqualFold(acao, "null") {
		if u, err := url.Parse(acao); err == nil && u.Host != "" {
			if br := h.browserOrigin(info, u); br != "" {
				resp.Header.Set("Access-Control-Allow-Origin", br)
			}
		}
	}

	if link := resp.Header.Get("Link"); link != "" {
		resp.Header.Set("Link", linkURLRe.ReplaceAllStringFunc(link, func(m string) string {
			if r := h.rewriter(info).Ref(m[1:len(m)-1], target); r != "" {
				return "<" + r + ">"
			}
			return m
		}))
	}

	h.rewriteCookies(resp, info)

	// A 101 has no body to rewrite: the connection is now a websocket.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		return nil
	}
	return h.rewriteBody(resp, info)
}

// rewriteCookies re-scopes Set-Cookie onto the gateway. Under the path codecs,
// path scoping is what keeps two proxied origins out of each other's cookies;
// under the subdomain codec the browser's own origin separation does that job
// and the path is left alone. Domain-scoped cookies go to the server-side jar
// instead, because the gateway has no second domain to put them on.
func (h *Handler) rewriteCookies(resp *http.Response, info *reqInfo) {
	raws := resp.Header.Values("Set-Cookie")
	defer h.logResponse(resp, raws)
	if len(raws) == 0 {
		return
	}
	resp.Header.Del("Set-Cookie")

	var shared []*http.Cookie
	for _, raw := range raws {
		sc, ok := parseSetCookie(raw)
		if !ok {
			continue
		}
		if sc.Name == h.opts.SessionCookie {
			continue // never let an origin overwrite the gateway session
		}
		toJar, toBrowser := sc.domainScope(info.target)
		if toJar && info.jarKey != "" {
			shared = append(shared, sc.toHTTPCookie())
		} else if toJar {
			// No signed-in browser to attach a jar to; the browser copy is
			// then the only copy there can be.
			toBrowser = true
		}
		if toBrowser {
			resp.Header.Add("Set-Cookie", sc.rewrite(h.cookiePath(info, sc.originPath()), info.secure))
		}
	}
	if len(shared) > 0 {
		storeShared(h.jars.get(info.jarKey), info.target, shared)
	}
}

// browserOrigin is the address bar's origin for a site behind the gateway: its
// own gateway host under the sub-domain codec, and the gateway's own origin
// under the path codecs, where every site shares one.
func (h *Handler) browserOrigin(info *reqInfo, origin *url.URL) string {
	enc := h.codecFor(info).Encode(&url.URL{Scheme: origin.Scheme, Host: origin.Host})
	if enc != "" && !strings.HasPrefix(enc, "/") {
		if u, err := url.Parse(enc); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return info.gatewayOrigin()
}

// cookiePath maps an origin cookie path into the gateway's path space by asking
// the codec where that path lives.
func (h *Handler) cookiePath(info *reqInfo, path string) string {
	scoped := *info.target
	scoped.Path, scoped.RawPath, scoped.RawQuery, scoped.Fragment = path, "", "", ""
	enc := h.codecFor(info).Encode(&scoped)
	if enc == "" {
		return "/"
	}
	if strings.HasPrefix(enc, "/") {
		return enc
	}
	if u, err := url.Parse(enc); err == nil && u.Path != "" {
		return u.Path // subdomain codec: the path is the origin's own
	}
	return "/"
}

func (h *Handler) rewriteBody(resp *http.Response, info *reqInfo) error {
	target := info.target
	kind := bodyKind(resp.Header.Get("Content-Type"))
	if kind == bodyScript && h.opts.JSScope == JSOff {
		kind = bodyOther
	}
	if kind == bodyOther || resp.Body == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if resp.ContentLength > h.opts.MaxRewriteBytes {
		return nil
	}

	body := resp.Body
	var src io.Reader = body
	gzipped := strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip")
	if gzipped {
		zr, err := gzip.NewReader(body)
		if err != nil {
			return nil // not gzip after all; leave the body alone
		}
		src = zr
	}

	buf, err := io.ReadAll(io.LimitReader(src, h.opts.MaxRewriteBytes+1))
	if err != nil {
		body.Close()
		return err
	}
	if int64(len(buf)) > h.opts.MaxRewriteBytes {
		// Too large to rewrite: stream what was read plus the rest, untouched.
		resp.Body = joinedBody{Reader: io.MultiReader(bytes.NewReader(buf), src), Closer: body}
		if gzipped {
			resp.Header.Del("Content-Encoding")
		}
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		return nil
	}
	body.Close()

	var out []byte
	switch kind {
	case bodyHTML:
		out = h.rewriter(info).HTML(buf, target, h.inject(info))
	case bodyCSS:
		out = []byte(h.rewriter(info).CSS(string(buf), target))
	case bodyScript:
		out = []byte(h.rewriter(info).JS(string(buf), target))
	}

	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.ContentLength = int64(len(out))
	return nil
}

// inject builds the <head> snippet that boots the client-side shim. The shim
// needs to know how this gateway addresses targets, or it would wrap an address
// that is already a gateway address.
func (h *Handler) inject(info *reqInfo) string {
	conf := map[string]string{"p": PlainPrefix, "t": info.target.String(), "m": h.codec().Name()}
	if name := h.opts.SessionCookie; name != "" {
		conf["c"] = name
	}
	if hc, ok := h.codec().(*HostCodec); ok {
		conf["b"] = hc.Base
		conf["port"] = hc.Port
		// The scheme the shim builds addresses with is the one the browser is
		// using, not the one this process listens on.
		if info.secure {
			conf["s"] = "1"
		}
	}
	cfg, err := json.Marshal(conf)
	if err != nil {
		return ""
	}
	return `<script>window.__WV__=` + string(cfg) + `;</script><script src="` + shimPath + `"></script>`
}

type joinedBody struct {
	io.Reader
	io.Closer
}

type bodyType int

const (
	bodyOther bodyType = iota
	bodyHTML
	bodyCSS
	bodyScript
)

func bodyKind(contentType string) bodyType {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	}
	switch mt {
	case "text/html", "application/xhtml+xml":
		return bodyHTML
	case "text/css":
		return bodyCSS
	case "application/javascript", "text/javascript", "application/x-javascript",
		"module", "application/json", "text/json":
		return bodyScript
	}
	if strings.HasSuffix(mt, "+json") {
		return bodyScript
	}
	return bodyOther
}

func (h *Handler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	var ce *certError
	if errors.As(err, &ce) {
		h.serveUntrusted(w, r, ce)
		return
	}
	target := "?"
	if info := infoFrom(r.Context()); info != nil {
		target = info.target.String()
	}
	h.log.Printf("webvpn: upstream error for %s: %v", target, err)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadGateway)
	_, _ = io.WriteString(w, "上游请求失败 (upstream request failed): "+err.Error()+"\n")
}
