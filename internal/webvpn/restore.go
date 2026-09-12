package webvpn

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Single sign-on breaks in a way rewriting responses cannot fix.
//
// An application hands the identity provider a redirect_uri saying where to
// come back to, and that value is derived from where the browser currently is —
// window.location.origin, or a link the gateway itself rewrote. Through the
// gateway that address is the gateway's, so the provider compares it against
// the callback registered for the real application and refuses.
//
// The fix is the mirror image of what the gateway does to responses: on the way
// out, any gateway address carried inside a request's parameters is put back to
// the address it stands for. The provider then sees its registered callback,
// and the redirect it answers with is rewritten on the way back as usual.

// absURLRe finds an absolute http(s) URL inside a parameter value.
var absURLRe = regexp.MustCompile(`(?i)https?://[^\s"'<>\\]+`)

// maxRestoreBody bounds how much of a form body is buffered to be restored.
const maxRestoreBody = 1 << 20

// browserPage is the real address of the page the request was made from. It is
// what a bare gateway origin in a parameter stands for, and under the path
// codec the address alone cannot say which site that is: every proxied page
// shares one origin.
//
// The Referer answers it exactly and is tried first. A site that suppresses the
// Referer falls back to the trail the gateway keeps for this browser, and a
// browser with no trail yet falls back to the target, which is right whenever
// the request is same-site.
func (h *Handler) browserPage(info *reqInfo, in *http.Request) *url.URL {
	if ref := in.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			if t, err := h.decode(u.Host, u.EscapedPath(), u.RawQuery); err == nil {
				return t
			}
		}
	}
	if info.page != nil {
		return info.page
	}
	return info.target
}

// restoreTargets replaces every gateway address in s with the address it stands
// for. Values without one are returned untouched.
func (h *Handler) restoreTargets(s string, page *url.URL, browserHost string) string {
	if !strings.Contains(s, "://") {
		return s
	}
	return absURLRe.ReplaceAllStringFunc(s, func(m string) string {
		u, err := url.Parse(m)
		if err != nil || u.Host == "" {
			return m
		}
		real := h.realAddress(u, page, browserHost)
		if real == nil {
			return m
		}
		return real.String()
	})
}

// realAddress turns one gateway URL back into the target it addresses, or
// returns nil when the URL is not the gateway's.
func (h *Handler) realAddress(u *url.URL, page *url.URL, browserHost string) *url.URL {
	if !h.addressedToGateway(u.Host, browserHost) {
		return nil
	}
	// A target encoded in the path or in the host is recoverable exactly.
	if t, err := h.plain.Decode(u.Host, u.EscapedPath(), u.RawQuery); err == nil {
		return sameShapeAs(u, t)
	}
	if t, err := h.codec().Decode(u.Host, u.EscapedPath(), u.RawQuery); err == nil {
		return sameShapeAs(u, t)
	}
	// A bare gateway address carries no target of its own: it is what a script
	// gets from location.origin, and it stands for the page the browser is on.
	if page == nil {
		return nil
	}
	out := *u
	out.Scheme, out.Host = page.Scheme, page.Host
	return &out
}

// sameShapeAs restores a decoded address to the shape of the address it stands
// for.
//
// Decoding produces a URL fit to be requested, and a request always has a path,
// so a bare origin comes back with a "/" the page never wrote. That matters
// here and nowhere else: this address is going back into a parameter, and the
// party who reads it compares strings. An OAuth redirect_uri is matched
// character for character against the registered value (RFC 6749 §3.1.2.3), so
// https://soc.corp.example/ is simply not https://soc.corp.example.
func sameShapeAs(src, decoded *url.URL) *url.URL {
	if decoded.EscapedPath() == "/" && !strings.HasSuffix(src.EscapedPath(), "/") {
		out := *decoded
		out.Path, out.RawPath = "", ""
		return &out
	}
	return decoded
}

// addressedToGateway reports whether a host is one the gateway answers on.
func (h *Handler) addressedToGateway(host, browserHost string) bool {
	if strings.EqualFold(hostOnly(host), hostOnly(browserHost)) {
		return true
	}
	if hc, ok := h.codec().(*HostCodec); ok {
		return hc.isGatewayHost(host)
	}
	return false
}

// restoreQuery rewrites the values of a query string, leaving the parameter
// names and their order alone.
func (h *Handler) restoreQuery(raw string, page *url.URL, browserHost string) string {
	if raw == "" || !strings.Contains(raw, "://") && !strings.Contains(strings.ToUpper(raw), "%3A") {
		return raw
	}
	var out strings.Builder
	for i, pair := range strings.Split(raw, "&") {
		if i > 0 {
			out.WriteByte('&')
		}
		name, value, hasValue := strings.Cut(pair, "=")
		if !hasValue {
			out.WriteString(pair)
			continue
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil {
			out.WriteString(pair)
			continue
		}
		restored := h.restoreTargets(decoded, page, browserHost)
		if restored == decoded {
			out.WriteString(pair)
			continue
		}
		out.WriteString(name)
		out.WriteByte('=')
		out.WriteString(url.QueryEscape(restored))
	}
	return out.String()
}

// restoreBody does the same for an application/x-www-form-urlencoded body,
// which is how SAML and CAS carry their return addresses.
func (h *Handler) restoreBody(r *http.Request, page *url.URL, browserHost string) {
	if r.Body == nil || r.ContentLength == 0 || r.ContentLength > maxRestoreBody {
		return
	}
	mediaType, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if strings.TrimSpace(strings.ToLower(mediaType)) != "application/x-www-form-urlencoded" {
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxRestoreBody+1))
	r.Body.Close()
	if err != nil || len(body) > maxRestoreBody {
		// Hand back what was read; a body too large to inspect is passed on.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		return
	}

	restored := h.restoreQuery(string(body), page, browserHost)
	r.Body = io.NopCloser(strings.NewReader(restored))
	r.ContentLength = int64(len(restored))
	r.Header.Set("Content-Length", strconv.Itoa(len(restored)))
	r.TransferEncoding = nil
}
