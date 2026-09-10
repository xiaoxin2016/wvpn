package webvpn

import (
	"bytes"
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// schemeRe matches an explicit scheme at the start of a URL reference.
var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*:`)

// Rewriter turns the URL references inside a document into gateway references
// using a Codec.
type Rewriter struct {
	Codec Codec
}

// Ref resolves a URL reference found in a document against base and maps it into
// the gateway's address space. It returns "" when the reference must be left
// exactly as it is (fragments, data:/javascript:/mailto: and friends).
func (rw Rewriter) Ref(ref string, base *url.URL) string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if s := schemeRe.FindString(trimmed); s != "" {
		if !SchemeSupported(strings.ToLower(strings.TrimSuffix(s, ":"))) {
			return ""
		}
	}
	u, err := base.Parse(trimmed)
	if err != nil || !SchemeSupported(u.Scheme) {
		return ""
	}
	return rw.Codec.Encode(u)
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f'
}

// Srcset rewrites every candidate of a srcset/imagesrcset attribute, keeping the
// width/density descriptors intact.
func (rw Rewriter) Srcset(v string, base *url.URL) string {
	var b strings.Builder
	for i, n := 0, len(v); i < n; {
		start := i
		for i < n && (isSpace(v[i]) || v[i] == ',') {
			i++
		}
		b.WriteString(v[start:i])
		if i >= n {
			break
		}
		us := i
		for i < n && !isSpace(v[i]) {
			i++
		}
		candidate := v[us:i]
		// A candidate without a descriptor may carry the separating commas.
		trailing := ""
		for strings.HasSuffix(candidate, ",") {
			trailing += ","
			candidate = candidate[:len(candidate)-1]
		}
		if r := rw.Ref(candidate, base); r != "" {
			b.WriteString(r)
		} else {
			b.WriteString(candidate)
		}
		b.WriteString(trailing)
		if trailing != "" {
			continue // the candidate ended here, no descriptor follows
		}
		ds := i
		for i < n && v[i] != ',' {
			i++
		}
		b.WriteString(v[ds:i])
	}
	return b.String()
}

var (
	cssURLRe    = regexp.MustCompile(`(?i)url\(\s*("([^"\\]|\\.)*"|'([^'\\]|\\.)*'|[^)'"]*)\s*\)`)
	cssImportRe = regexp.MustCompile(`(?i)@import\s+("([^"\\]|\\.)*"|'([^'\\]|\\.)*')`)
)

// CSS rewrites url(...) and @import "..." references in a stylesheet or in an
// inline style attribute.
func (rw Rewriter) CSS(css string, base *url.URL) string {
	rewriteQuoted := func(raw string) string {
		quote := ""
		val := raw
		if len(raw) >= 2 && (raw[0] == '"' || raw[0] == '\'') && raw[len(raw)-1] == raw[0] {
			quote = string(raw[0])
			val = raw[1 : len(raw)-1]
		}
		r := rw.Ref(val, base)
		if r == "" {
			return raw
		}
		if quote == "" {
			// Unquoted url() tokens cannot contain these characters; quote to be safe.
			quote = `"`
		}
		return quote + strings.ReplaceAll(r, quote, "\\"+quote) + quote
	}

	css = cssURLRe.ReplaceAllStringFunc(css, func(m string) string {
		inner := m[strings.Index(m, "(")+1 : len(m)-1]
		return "url(" + rewriteQuoted(strings.TrimSpace(inner)) + ")"
	})
	css = cssImportRe.ReplaceAllStringFunc(css, func(m string) string {
		i := strings.IndexAny(m, `"'`)
		if i < 0 {
			return m
		}
		return m[:i] + rewriteQuoted(m[i:])
	})
	return css
}

// urlAttrs lists the per-element attributes that carry a single URL.
var urlAttrs = map[string]map[string]bool{
	"a":          {"href": true},
	"area":       {"href": true},
	"audio":      {"src": true},
	"base":       {"href": true},
	"blockquote": {"cite": true},
	"body":       {"background": true},
	"button":     {"formaction": true},
	"del":        {"cite": true},
	"embed":      {"src": true},
	"form":       {"action": true},
	"frame":      {"src": true, "longdesc": true},
	"iframe":     {"src": true, "longdesc": true},
	"image":      {"href": true},
	"img":        {"src": true, "longdesc": true},
	"input":      {"src": true, "formaction": true},
	"ins":        {"cite": true},
	"link":       {"href": true},
	"object":     {"data": true, "codebase": true},
	"q":          {"cite": true},
	"script":     {"src": true},
	"source":     {"src": true},
	"table":      {"background": true},
	"td":         {"background": true},
	"th":         {"background": true},
	"track":      {"src": true},
	"use":        {"href": true},
	"video":      {"src": true, "poster": true},
}

// srcsetAttrs lists the per-element attributes that carry a candidate list.
var srcsetAttrs = map[string]string{
	"img":    "srcset",
	"source": "srcset",
	"link":   "imagesrcset",
}

// droppedAttrs are removed outright: subresource integrity would fail on
// rewritten stylesheets, and CORS attributes are meaningless once everything is
// served from the gateway's own origin.
var droppedAttrs = map[string]bool{
	"integrity":   true,
	"crossorigin": true,
}

var metaRefreshRe = regexp.MustCompile(`(?i)^(\s*[0-9.]*\s*;\s*url\s*=\s*)(.*)$`)

// tag rewrites a start tag in place. It reports whether the token was modified
// and whether it should be dropped from the output entirely.
func (rw Rewriter) tag(tok *html.Token, base *url.URL) (changed, drop bool) {
	name := tok.Data

	if name == "meta" {
		var httpEquiv string
		for _, a := range tok.Attr {
			if a.Key == "http-equiv" {
				httpEquiv = strings.ToLower(strings.TrimSpace(a.Val))
			}
		}
		switch httpEquiv {
		case "content-security-policy", "content-security-policy-report-only":
			return false, true
		case "refresh":
			for i, a := range tok.Attr {
				if a.Key != "content" {
					continue
				}
				m := metaRefreshRe.FindStringSubmatch(a.Val)
				if m == nil {
					continue
				}
				target := strings.Trim(strings.TrimSpace(m[2]), `'"`)
				if r := rw.Ref(target, base); r != "" {
					tok.Attr[i].Val = m[1] + r
					changed = true
				}
			}
			return changed, false
		}
	}

	attrs := tok.Attr[:0]
	for _, a := range tok.Attr {
		if droppedAttrs[a.Key] {
			changed = true
			continue
		}
		switch {
		case a.Key == "style":
			if v := rw.CSS(a.Val, base); v != a.Val {
				a.Val = v
				changed = true
			}
		case a.Key == srcsetAttrs[name]:
			if v := rw.Srcset(a.Val, base); v != a.Val {
				a.Val = v
				changed = true
			}
		case a.Key == "xlink:href" || urlAttrs[name][a.Key]:
			if v := rw.Ref(a.Val, base); v != "" {
				a.Val = v
				changed = true
			}
		}
		attrs = append(attrs, a)
	}
	tok.Attr = attrs
	return changed, false
}

// baseHref returns the href of a <base> tag, if any.
func baseHref(tok *html.Token) (string, bool) {
	for _, a := range tok.Attr {
		if a.Key == "href" {
			return a.Val, true
		}
	}
	return "", false
}

// HTML rewrites every URL reference in an HTML document so that it points back
// at the gateway, and injects the client-side shim into <head>.
//
// Tokens the rewriter does not touch are copied through byte for byte, which
// keeps script bodies, comments, entities and odd-but-legal markup intact.
func (rw Rewriter) HTML(src []byte, base *url.URL, inject string) []byte {
	var out bytes.Buffer
	out.Grow(len(src) + len(inject) + 512)

	z := html.NewTokenizer(bytes.NewReader(src))
	injected := inject == ""
	inStyle := false

	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		raw := z.Raw()

		switch tt {
		case html.StartTagToken, html.SelfClosingTagToken:
			tok := z.Token()
			name := tok.Data
			inStyle = tt == html.StartTagToken && name == "style"

			if name == "base" {
				if href, ok := baseHref(&tok); ok {
					if abs, err := base.Parse(strings.TrimSpace(href)); err == nil && SchemeSupported(abs.Scheme) {
						// Later references in this document resolve against the
						// declared base, so follow it before rewriting it.
						base = abs
					}
				}
			}

			changed, drop := rw.tag(&tok, base)
			switch {
			case drop:
				// omit
			case changed:
				out.WriteString(tok.String())
			default:
				out.Write(raw)
			}

			if !injected && (name == "head" || name == "body") {
				out.WriteString(inject)
				injected = true
			}

		case html.EndTagToken:
			inStyle = false
			out.Write(raw)

		case html.TextToken:
			if inStyle {
				out.WriteString(rw.CSS(string(raw), base))
			} else {
				out.Write(raw)
			}

		default:
			out.Write(raw)
		}
	}

	if !injected {
		return append([]byte(inject), out.Bytes()...)
	}
	return out.Bytes()
}
