// Package webvpn implements a small WebVPN gateway: an HTTP reverse proxy that
// fetches arbitrary http(s) origins on behalf of a browser and rewrites the
// responses so that every follow-up request comes back through the gateway.
//
// A target URL has to survive a round trip through the gateway's own address
// space. Three encodings are provided (see Codec):
//
//	plain:     https://example.com:8443/a?b=c -> /p/https/example.com:8443/a?b=c
//	wrd:       https://example.com/a          -> /https/<hex(iv)+hex(enc(host))>/a
//	subdomain: https://a-b.example.com/x      -> http://a--b-example-com-s.<base>/x
//
// plain is readable and trivial to debug. wrd hides the hostname in the address
// bar the way the commercial appliance common on Chinese campuses does.
// subdomain gives every origin its own browser origin — the best isolation of
// the three, and the only one where root-relative URLs work untouched — at the
// price of a wildcard DNS record and a wildcard certificate.
package webvpn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Errors returned while decoding a gateway request.
var (
	ErrNotProxyPath = errors.New("webvpn: not a proxy request")
	ErrBadTarget    = errors.New("webvpn: malformed target")
)

// Codec maps absolute target URLs onto gateway references and back.
//
// Encode may return either a path-absolute reference ("/p/https/example.com/")
// or a fully absolute URL, depending on whether the codec encodes the target in
// the path or in the hostname.
type Codec interface {
	// Name is the identifier used by the -url-mode flag.
	Name() string
	// Match reports whether an inbound request (Host header plus escaped path)
	// belongs to this codec's proxy space.
	Match(host, escapedPath string) bool
	// Encode returns a gateway reference, or "" if u cannot be represented.
	Encode(u *url.URL) string
	// Decode turns an inbound request back into the absolute target URL.
	Decode(host, escapedPath, rawQuery string) (*url.URL, error)
}

// SchemeSupported reports whether s is a scheme the gateway can proxy.
func SchemeSupported(s string) bool {
	switch s {
	case "http", "https", "ws", "wss":
		return true
	}
	return false
}

// httpScheme maps a websocket scheme onto the HTTP scheme used to dial it;
// net/http performs the upgrade handshake over http/https.
func httpScheme(s string) string {
	switch s {
	case "ws":
		return "http"
	case "wss":
		return "https"
	}
	return s
}

func isTLSScheme(s string) bool { return s == "https" || s == "wss" }

// defaultPort reports whether port is the default for scheme, in which case it
// does not need to be encoded.
func defaultPort(scheme, port string) bool {
	switch scheme {
	case "http", "ws":
		return port == "80"
	case "https", "wss":
		return port == "443"
	}
	return false
}

// hostOnly strips any :port from a Host header value.
func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.Trim(strings.TrimSuffix(host, "."), "[]"))
}

// assemble rebuilds an absolute URL from its already-escaped pieces.
func assemble(scheme, host, escapedTail, rawQuery string) (*url.URL, error) {
	if host == "" || strings.ContainsAny(host, "/\\ ") {
		return nil, ErrBadTarget
	}
	raw := scheme + "://" + host + "/" + escapedTail
	if rawQuery != "" {
		raw += "?" + rawQuery
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrBadTarget
	}
	return u, nil
}

// appendPathQuery writes the path, query and fragment of u onto b.
func appendPathQuery(b *strings.Builder, u *url.URL) {
	if p := u.EscapedPath(); p == "" {
		b.WriteByte('/')
	} else {
		if p[0] != '/' {
			b.WriteByte('/')
		}
		b.WriteString(p)
	}
	if u.ForceQuery || u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.EscapedFragment())
	}
}

// PlainPrefix is the path prefix used by the plain codec. It stays routable
// whatever codec is configured, because the browser-side shim emits it and
// because the other codecs fall back to it for targets they cannot represent.
const PlainPrefix = "/p/"

// PlainCodec keeps the target visible: /p/{scheme}/{host}/{path}.
type PlainCodec struct{}

func (PlainCodec) Name() string { return "plain" }

func (PlainCodec) Match(_, escapedPath string) bool {
	return strings.HasPrefix(escapedPath, PlainPrefix)
}

func (PlainCodec) Encode(u *url.URL) string {
	if u == nil || u.Host == "" || !SchemeSupported(u.Scheme) {
		return ""
	}
	var b strings.Builder
	b.WriteString(PlainPrefix)
	b.WriteString(u.Scheme)
	b.WriteByte('/')
	// A host never legally contains "/", but a stray one would shift the path
	// segmentation, so escape it.
	b.WriteString(strings.ReplaceAll(u.Host, "/", "%2F"))
	appendPathQuery(&b, u)
	return b.String()
}

func (PlainCodec) Decode(_, escapedPath, rawQuery string) (*url.URL, error) {
	if !strings.HasPrefix(escapedPath, PlainPrefix) {
		return nil, ErrNotProxyPath
	}
	scheme, rest, _ := strings.Cut(escapedPath[len(PlainPrefix):], "/")
	if !SchemeSupported(scheme) {
		return nil, ErrBadTarget
	}
	rawHost, tail, _ := strings.Cut(rest, "/")
	host, err := url.PathUnescape(rawHost)
	if err != nil {
		return nil, ErrBadTarget
	}
	return assemble(scheme, host, tail, rawQuery)
}

// DefaultWRDKey is the key/IV of the appliance whose URL shape the wrd codec
// imitates. The value circulates in community reverse-engineering write-ups
// rather than vendor documentation, and it buys obfuscation, not
// confidentiality: anyone holding it recovers the hostname. Override it with
// -url-key for URLs that only this gateway can decode.
const DefaultWRDKey = "wrdvpnisthebest!"

// wrdSchemeRe matches the first path segment of a wrd URL: "https", "http-8080".
var wrdSchemeRe = regexp.MustCompile(`^(http|https|ws|wss)(?:-([0-9]{1,5}))?$`)

// WRDCodec hides the target host: /{scheme}[-{port}]/{hex(iv)+hex(ct)}/{path},
// where the hostname is AES-CFB encrypted and the port travels in clear text as
// a suffix of the scheme segment.
type WRDCodec struct {
	block cipher.Block
	iv    []byte
}

// NewWRDCodec builds a WRDCodec. The key must be 16, 24 or 32 bytes; its first
// 16 bytes double as the IV, which keeps the encoding deterministic — and
// therefore cacheable and comparable — at the cost of leaking equality between
// identical hostnames, which is not a secret anyway.
func NewWRDCodec(key string) (*WRDCodec, error) {
	k := []byte(key)
	switch len(k) {
	case 16, 24, 32:
	default:
		return nil, errors.New("webvpn: url key must be 16, 24 or 32 bytes")
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return &WRDCodec{block: block, iv: k[:aes.BlockSize]}, nil
}

func (*WRDCodec) Name() string { return "wrd" }

func (*WRDCodec) Match(_, escapedPath string) bool {
	seg, _, _ := strings.Cut(strings.TrimPrefix(escapedPath, "/"), "/")
	return wrdSchemeRe.MatchString(seg)
}

func (c *WRDCodec) encryptHost(host string) string {
	out := make([]byte, len(host))
	cipher.NewCFBEncrypter(c.block, c.iv).XORKeyStream(out, []byte(host))
	return hex.EncodeToString(c.iv) + hex.EncodeToString(out)
}

func (c *WRDCodec) decryptHost(s string) (string, error) {
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) <= aes.BlockSize {
		return "", ErrBadTarget
	}
	iv, ct := raw[:aes.BlockSize], raw[aes.BlockSize:]
	out := make([]byte, len(ct))
	cipher.NewCFBDecrypter(c.block, iv).XORKeyStream(out, ct)
	host := string(out)
	// A wrong key decrypts to noise; reject anything that cannot be a hostname.
	for _, r := range host {
		if r < 0x21 || r > 0x7e {
			return "", ErrBadTarget
		}
	}
	return host, nil
}

func (c *WRDCodec) Encode(u *url.URL) string {
	if u == nil || u.Host == "" || !SchemeSupported(u.Scheme) {
		return ""
	}
	var b strings.Builder
	b.WriteByte('/')
	b.WriteString(u.Scheme)
	if port := u.Port(); port != "" && !defaultPort(u.Scheme, port) {
		b.WriteByte('-')
		b.WriteString(port)
	}
	b.WriteByte('/')
	b.WriteString(c.encryptHost(u.Hostname()))
	appendPathQuery(&b, u)
	return b.String()
}

func (c *WRDCodec) Decode(_, escapedPath, rawQuery string) (*url.URL, error) {
	seg, rest, _ := strings.Cut(strings.TrimPrefix(escapedPath, "/"), "/")
	m := wrdSchemeRe.FindStringSubmatch(seg)
	if m == nil {
		return nil, ErrNotProxyPath
	}
	enc, tail, _ := strings.Cut(rest, "/")
	host, err := c.decryptHost(enc)
	if err != nil {
		return nil, err
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]" // bare IPv6 literal
	}
	if port := m[2]; port != "" {
		if n, err := strconv.Atoi(port); err != nil || n == 0 || n > 65535 {
			return nil, ErrBadTarget
		}
		host += ":" + port
	}
	return assemble(m[1], host, tail, rawQuery)
}

// HostCodec encodes the target into a label of a wildcard domain: dots become
// "-", literal "-" is doubled, and an "-s" suffix marks a TLS origin.
//
//	https://git-scm.com/docs  ->  https://git--scm-com-s.<base>/docs
//
// Targets on a non-default port cannot be expressed this way; those fall back to
// the plain path form, which every gateway host also serves.
type HostCodec struct {
	// Base is the wildcard domain, e.g. "webvpn.example.com".
	Base string
	// Port is the port the gateway is reachable on, "" for the scheme default.
	Port string
	// TLS reports whether the gateway itself is served over https.
	TLS bool

	fallback PlainCodec
}

// NewHostCodec validates base and builds a HostCodec.
func NewHostCodec(base, port string, tls bool) (*HostCodec, error) {
	base = strings.ToLower(strings.Trim(strings.TrimSpace(base), "."))
	if base == "" || !strings.Contains(base, ".") {
		return nil, errors.New("webvpn: -base-domain must be a domain such as webvpn.example.com")
	}
	return &HostCodec{Base: base, Port: port, TLS: tls}, nil
}

func (*HostCodec) Name() string { return "subdomain" }

func (c *HostCodec) Match(host, escapedPath string) bool {
	if c.fallback.Match(host, escapedPath) {
		return false // handled by the plain codec
	}
	h := hostOnly(host)
	return strings.HasSuffix(h, "."+c.Base) && len(h) > len(c.Base)+1
}

// encodeLabel escapes a host into a single DNS label: dots become "-", a
// literal "-" is doubled, a non-default port is appended as "-p<port>", and an
// "-s" suffix marks a TLS origin.
func encodeLabel(hostname, port string, tls bool) string {
	label := strings.ReplaceAll(hostname, "-", "--")
	label = strings.ReplaceAll(label, ".", "-")
	if port != "" {
		label += "-p" + port
	}
	if tls {
		label += "-s"
	}
	return label
}

// labelPortRe matches the port suffix, taking care not to read the second half
// of a doubled "-" as the start of one.
var labelPortRe = regexp.MustCompile(`(^|[^-])-p([0-9]{1,5})$`)

// decodeLabel is the inverse of encodeLabel. The "-s" and "-p" markers are
// inherently ambiguous with a host whose last component is literally "s" or
// "p1234"; the appliance this mirrors has the same wart.
func decodeLabel(label string) (hostname, port string, tls bool) {
	if strings.HasSuffix(label, "-s") && !strings.HasSuffix(label, "--s") {
		label, tls = strings.TrimSuffix(label, "-s"), true
	}
	if m := labelPortRe.FindStringSubmatch(label); m != nil {
		port = m[2]
		label = label[:len(label)-len("-p")-len(port)]
	}
	var b strings.Builder
	for i := 0; i < len(label); i++ {
		switch {
		case label[i] != '-':
			b.WriteByte(label[i])
		case i+1 < len(label) && label[i+1] == '-':
			b.WriteByte('-')
			i++
		default:
			b.WriteByte('.')
		}
	}
	return b.String(), port, tls
}

// maxLabel is the DNS limit on a single label; a target that does not fit falls
// back to the plain path form, which has no such limit.
const maxLabel = 63

func (c *HostCodec) gatewayScheme(target string) string {
	switch {
	case target == "ws" || target == "wss":
		if c.TLS {
			return "wss"
		}
		return "ws"
	case c.TLS:
		return "https"
	}
	return "http"
}

func (c *HostCodec) Encode(u *url.URL) string {
	if u == nil || u.Host == "" || !SchemeSupported(u.Scheme) {
		return ""
	}
	if c.isGatewayHost(u.Hostname()) {
		// Already one of ours: wrapping it again would point the gateway at
		// itself.
		return ""
	}
	if strings.Contains(u.Hostname(), ":") {
		return c.fallback.Encode(u) // IPv6 literal
	}
	port := u.Port()
	if defaultPort(u.Scheme, port) {
		port = ""
	}
	label := encodeLabel(u.Hostname(), port, isTLSScheme(u.Scheme))
	if len(label) > maxLabel {
		return c.fallback.Encode(u) // too long to be a DNS label
	}
	host := label + "." + c.Base
	if c.Port != "" {
		host = net.JoinHostPort(host, c.Port)
	}
	var b strings.Builder
	b.WriteString(c.gatewayScheme(u.Scheme))
	b.WriteString("://")
	b.WriteString(host)
	appendPathQuery(&b, u)
	return b.String()
}

// isGatewayHost reports whether a host is the gateway itself or one of the
// sub-domains it serves targets on.
func (c *HostCodec) isGatewayHost(host string) bool {
	h := hostOnly(host)
	return h == c.Base || strings.HasSuffix(h, "."+c.Base)
}

func (c *HostCodec) Decode(host, escapedPath, rawQuery string) (*url.URL, error) {
	h := hostOnly(host)
	if !strings.HasSuffix(h, "."+c.Base) {
		return nil, ErrNotProxyPath
	}
	label := strings.TrimSuffix(h, "."+c.Base)
	if label == "" || strings.Contains(label, ".") {
		return nil, ErrBadTarget
	}
	hostname, port, tls := decodeLabel(label)
	scheme := "http"
	if tls {
		scheme = "https"
	}
	if port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return nil, ErrBadTarget
		}
		hostname = net.JoinHostPort(hostname, port)
	}
	return assemble(scheme, hostname, strings.TrimPrefix(escapedPath, "/"), rawQuery)
}

// ParseUserInput normalises what a human typed into the portal form. A bare
// "example.com/x" is treated as https.
func ParseUserInput(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrBadTarget
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || !SchemeSupported(u.Scheme) {
		return nil, ErrBadTarget
	}
	return u, nil
}
