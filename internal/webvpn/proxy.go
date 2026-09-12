package webvpn

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
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
	shimPath   = "/_wv/shim.js"
	gotoPath   = "/_wv/go"
	trustPath  = "/_wv/trust"
	assetPath  = "/_wv/"
	portalPath = "/"
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

// rewriter builds a rewriter for the codec currently in force.
func (h *Handler) rewriter() Rewriter {
	return Rewriter{Codec: h.codec(), Scope: h.opts.JSScope}
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
	ref := h.codec().Encode(target)
	if ref == "" {
		http.Error(w, "无法编码该目标地址", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, ref, http.StatusFound)
}

// serveStray catches requests that escaped rewriting — typically a root-relative
// URL built by a script the shim did not cover. The Referer still points into
// the gateway, which is enough to work out where the request was headed.
func (h *Handler) serveStray(w http.ResponseWriter, r *http.Request) {
	ref, err := url.Parse(r.Header.Get("Referer"))
	if err != nil || ref.Path == "" {
		http.NotFound(w, r)
		return
	}
	base, err := h.decode(ref.Host, ref.EscapedPath(), ref.RawQuery)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	target, err := base.Parse(r.URL.RequestURI())
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if enc := h.codec().Encode(target); enc != "" {
		http.Redirect(w, r, enc, http.StatusTemporaryRedirect)
		return
	}
	http.NotFound(w, r)
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
	check, err := h.opts.Guard.CheckTarget(target.Host, h.siteExempt(r))
	if err != nil {
		http.Error(w, "目标被网关策略拒绝: "+err.Error(), http.StatusForbidden)
		return
	}
	info := &reqInfo{
		target: target,
		secure: isSecureRequest(r),
		site:   check,
		jarKey: h.sessionKey(r),
	}
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
	if jar := h.jars.lookup(info.jarKey); jar != nil {
		header = appendCookiePairs(header, jarPairs(jar, target, cookieHeaderNames(header)))
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
		pr.Out.Header.Set("Origin", target.Scheme+"://"+target.Host)
	}

	// Do not advertise the gateway or its client to the origin.
	pr.Out.Header.Del("X-Forwarded-For")
	pr.Out.Header.Del("X-Forwarded-Host")
	pr.Out.Header.Del("X-Forwarded-Proto")
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
			if enc := h.codec().Encode(u); enc != "" {
				resp.Header.Set("Location", enc)
			}
		}
	}

	if link := resp.Header.Get("Link"); link != "" {
		resp.Header.Set("Link", linkURLRe.ReplaceAllStringFunc(link, func(m string) string {
			if r := h.rewriter().Ref(m[1:len(m)-1], target); r != "" {
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
	return h.rewriteBody(resp, target)
}

// rewriteCookies re-scopes Set-Cookie onto the gateway. Under the path codecs,
// path scoping is what keeps two proxied origins out of each other's cookies;
// under the subdomain codec the browser's own origin separation does that job
// and the path is left alone. Domain-scoped cookies go to the server-side jar
// instead, because the gateway has no second domain to put them on.
func (h *Handler) rewriteCookies(resp *http.Response, info *reqInfo) {
	raws := resp.Header.Values("Set-Cookie")
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
			resp.Header.Add("Set-Cookie", sc.rewrite(h.cookiePath(info.target, sc.originPath()), info.secure))
		}
	}
	if len(shared) > 0 {
		storeShared(h.jars.get(info.jarKey), info.target, shared)
	}
}

// cookiePath maps an origin cookie path into the gateway's path space by asking
// the codec where that path lives.
func (h *Handler) cookiePath(target *url.URL, path string) string {
	scoped := *target
	scoped.Path, scoped.RawPath, scoped.RawQuery, scoped.Fragment = path, "", "", ""
	enc := h.codec().Encode(&scoped)
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

func (h *Handler) rewriteBody(resp *http.Response, target *url.URL) error {
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
		out = h.rewriter().HTML(buf, target, h.inject(target))
	case bodyCSS:
		out = []byte(h.rewriter().CSS(string(buf), target))
	case bodyScript:
		out = []byte(h.rewriter().JS(string(buf), target))
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
func (h *Handler) inject(target *url.URL) string {
	conf := map[string]string{"p": PlainPrefix, "t": target.String()}
	if hc, ok := h.codec().(*HostCodec); ok {
		conf["b"] = hc.Base
		conf["port"] = hc.Port
		if hc.TLS {
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
