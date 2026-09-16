package webvpn

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Cookies are rewritten as text rather than parsed into http.Cookie and
// serialised back.
//
// Go's cookie parser is deliberately strict: a Set-Cookie whose value contains
// a non-ASCII byte is dropped outright, a value containing a space or comma is
// re-quoted on the way out, and Request.AddCookie strips invalid bytes from the
// value entirely. Any of those silently destroys a session token, which shows
// up as a site that accepts the login and then immediately claims the session
// expired — and only for the sites whose tokens happen to contain such bytes.
//
// The gateway is a proxy: whatever the origin set has to reach the browser
// byte for byte, and whatever the browser sends has to reach the origin the
// same way. Only the attributes are ours to change.

// setCookie is one Set-Cookie header, split into the parts the gateway needs
// while keeping the name=value pair exactly as it arrived.
type setCookie struct {
	Name string
	// Pair is the verbatim "name=value" text, quotes and all.
	Pair string
	// Attrs holds the remaining attributes in order, as written.
	Attrs []cookieAttr
}

type cookieAttr struct {
	// Key is the lower-cased attribute name; Raw is the attribute as written.
	Key string
	Val string
	Raw string
}

// parseSetCookie splits a Set-Cookie header value without touching the payload.
func parseSetCookie(raw string) (setCookie, bool) {
	parts := strings.Split(raw, ";")
	pair := strings.TrimSpace(parts[0])
	name, _, ok := strings.Cut(pair, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return setCookie{}, false
	}

	sc := setCookie{Name: name, Pair: pair}
	for _, p := range parts[1:] {
		attr := strings.TrimSpace(p)
		if attr == "" {
			continue
		}
		key, val, _ := strings.Cut(attr, "=")
		sc.Attrs = append(sc.Attrs, cookieAttr{
			Key: strings.ToLower(strings.TrimSpace(key)),
			Val: strings.TrimSpace(val),
			Raw: attr,
		})
	}
	return sc, true
}

// attr returns the value of an attribute, if present.
func (sc setCookie) attr(key string) (string, bool) {
	for _, a := range sc.Attrs {
		if a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

// rewrite re-scopes a cookie onto the gateway. path is the gateway path the
// cookie should apply to, and secure reports whether the browser leg is TLS.
func (sc setCookie) rewrite(path string, secure bool) string {
	// The value keeps its bytes; only the name moves into the gateway's space.
	_, value, _ := strings.Cut(sc.Pair, "=")
	out := []string{gatewayCookieName(sc.Name) + "=" + value}
	for _, a := range sc.Attrs {
		switch a.Key {
		case "domain":
			// Host-only on the gateway: one origin serves every target, so a
			// domain attribute has nothing to widen to.
			continue
		case "path":
			continue // replaced below
		case "secure":
			if !secure {
				// The browser would drop a Secure cookie over plain HTTP.
				continue
			}
		case "samesite":
			if strings.EqualFold(a.Val, "none") && !secure {
				// SameSite=None is only honoured together with Secure.
				out = append(out, "SameSite=Lax")
				continue
			}
		}
		out = append(out, a.Raw)
	}
	out = append(out, "Path="+path)
	return strings.Join(out, "; ")
}

// toHTTPCookie builds the parsed form the cookie jar needs. The value keeps the
// bytes the origin sent; it is only ever written back out as raw text.
func (sc setCookie) toHTTPCookie() *http.Cookie {
	_, value, _ := strings.Cut(sc.Pair, "=")
	c := &http.Cookie{Name: sc.Name, Value: value, Path: "/"}
	if v, ok := sc.attr("domain"); ok {
		c.Domain = v
	}
	if v, ok := sc.attr("path"); ok && strings.HasPrefix(v, "/") {
		c.Path = v
	}
	if _, ok := sc.attr("secure"); ok {
		c.Secure = true
	}
	if v, ok := sc.attr("max-age"); ok {
		if n, err := strconv.Atoi(v); err == nil {
			c.MaxAge = n
		}
	}
	if v, ok := sc.attr("expires"); ok {
		if t, err := http.ParseTime(v); err == nil {
			c.Expires = t
		}
	}
	return c
}

// originPath is the path the origin scoped the cookie to.
func (sc setCookie) originPath() string {
	if v, ok := sc.attr("path"); ok && strings.HasPrefix(v, "/") {
		return v
	}
	return "/"
}

// domainScope decides where a cookie has to live.
//
// A Domain attribute means the origin wants the cookie back from every host in
// that domain — which is how single sign-on carries a login from the identity
// provider to the applications. The gateway cannot express that reach in the
// browser, where those hosts are either one origin separated by path or one
// origin each, so the jar holds the copy that travels between them.
//
// The browser still gets a copy, scoped to where this target is served: the
// site's own scripts read their own cookies through document.cookie, and behind
// the gateway that copy is the only one they can see. A login that hands the
// page a token and expects to read it back on the next call depends on it.
// Scoping keeps it honest — under the path codecs the copy lives on this
// target's path, under the sub-domain codec on this target's host — so it
// reaches the site that set it and no other.
func (sc setCookie) domainScope(target *url.URL) (jar, browser bool) {
	domain, ok := sc.attr("domain")
	if !ok || strings.TrimSpace(domain) == "" {
		return false, true
	}
	domain = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(domain), "."))
	host := strings.ToLower(target.Hostname())
	if domain == host || strings.HasSuffix(host, "."+domain) {
		return true, true
	}
	// A domain the host does not belong to: the origin is confused, and the
	// browser would reject it too.
	return false, false
}

// cookieHeaderNames lists the cookie names already present in a Cookie header.
func cookieHeaderNames(header string) map[string]bool {
	names := map[string]bool{}
	for _, pair := range strings.Split(header, ";") {
		name, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
		if name = strings.TrimSpace(name); name != "" {
			names[name] = true
		}
	}
	return names
}

// appendCookiePairs adds "name=value" pairs to a Cookie header.
func appendCookiePairs(header string, pairs []string) string {
	if len(pairs) == 0 {
		return header
	}
	if header == "" {
		return strings.Join(pairs, "; ")
	}
	return header + "; " + strings.Join(pairs, "; ")
}

// CookiePrefix names the space the gateway keeps its cookies in.
//
// The gateway's own domain usually sits inside the domain of the sites it
// proxies — an organisation has one registrable domain, and a gateway does not
// get a second one. The browser then sends every cookie it holds for that wider
// domain to the gateway's hosts as well: cookies from visits made outside the
// tunnel, set by sites the current target has nothing to do with. Two things go
// wrong. One of them carries the same name as a cookie the site just set, and
// shadows it — a site reading the first of the two reads the stale one and says
// the session has expired. And all of them are forwarded to whichever site is
// being proxied, which is nobody's intent.
//
// A name can carry that distinction on its own, and nothing else can: the
// browser tells the gateway names and values, never the scope a cookie was
// stored at. So a cookie the gateway writes is given this prefix and has it
// taken off again on the way back to the site, which never sees it. Anything
// arriving without it was not put there by the gateway and is not forwarded.
const CookiePrefix = "__wvpn_"

// gatewayCookieName is what a site's cookie is called inside the browser.
func gatewayCookieName(name string) string { return CookiePrefix + name }

// siteCookieName takes the prefix off, reporting whether it was there at all.
func siteCookieName(name string) (string, bool) {
	if !strings.HasPrefix(name, CookiePrefix) {
		return name, false
	}
	return strings.TrimPrefix(name, CookiePrefix), true
}

// ourCookies keeps the cookies the gateway itself wrote, under the names the
// site knows them by. Everything else in the header reached the browser from
// outside the tunnel and is none of this site's business.
func ourCookies(header string) string {
	if header == "" {
		return header
	}
	var kept []string
	for _, pair := range strings.Split(header, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok {
			continue
		}
		site, ours := siteCookieName(strings.TrimSpace(name))
		if !ours {
			continue
		}
		kept = append(kept, site+"="+value)
	}
	return strings.Join(kept, "; ")
}
