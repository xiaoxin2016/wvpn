package webvpn

import (
	"net/url"
	"strings"
	"testing"
)

func testRewriter() Rewriter { return Rewriter{Codec: PlainCodec{}} }

func TestRefResolution(t *testing.T) {
	rw := testRewriter()
	base := mustURL(t, "https://example.com/dir/page.html")
	cases := []struct{ in, want string }{
		{"/abs", "/p/https/example.com/abs"},
		{"rel.png", "/p/https/example.com/dir/rel.png"},
		{"../up.png", "/p/https/example.com/up.png"},
		{"//cdn.example.net/x.js", "/p/https/cdn.example.net/x.js"},
		{"http://other.test/y", "/p/http/other.test/y"},
		{"#anchor", ""},
		{"", ""},
		{"data:image/png;base64,AAAA", ""},
		{"javascript:void(0)", ""},
		{"mailto:a@b.c", ""},
		{"ftp://files.test/x", ""},
	}
	for _, tc := range cases {
		if got := rw.Ref(tc.in, base); got != tc.want {
			t.Errorf("Ref(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSrcset(t *testing.T) {
	rw := testRewriter()
	base := mustURL(t, "https://example.com/dir/")
	in := "a.png 1x, /b.png 2x, https://cdn.test/c.png 640w"
	want := "/p/https/example.com/dir/a.png 1x, /p/https/example.com/b.png 2x, /p/https/cdn.test/c.png 640w"
	if got := rw.Srcset(in, base); got != want {
		t.Errorf("Srcset:\n got %q\nwant %q", got, want)
	}
	// Candidates without descriptors keep their separators. Note that per the
	// HTML srcset grammar a comma only ends a candidate after the URL token, so
	// "a.png,b.png" without a space is a single (odd) URL, not two candidates.
	if got := rw.Srcset("a.png, b.png", base); got != "/p/https/example.com/dir/a.png, /p/https/example.com/dir/b.png" {
		t.Errorf("Srcset without descriptors = %q", got)
	}
}

func TestCSS(t *testing.T) {
	rw := testRewriter()
	base := mustURL(t, "https://example.com/css/main.css")
	in := `@import "reset.css"; body{background:url(../img/bg.png) no-repeat;}
	       .a{background:url('https://cdn.test/x.png')} .b{background:url(data:image/gif;base64,AA)}`
	got := rw.CSS(in, base)
	for _, want := range []string{
		`@import "/p/https/example.com/css/reset.css"`,
		`url("/p/https/example.com/img/bg.png")`,
		`url('/p/https/cdn.test/x.png')`, // the original quoting style is kept
		`url(data:image/gif;base64,AA)`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("CSS output missing %q\ngot: %s", want, got)
		}
	}
}

const sampleHTML = `<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'">
<meta http-equiv="refresh" content="5; url=/next">
<link rel="stylesheet" href="/s.css" integrity="sha384-abc" crossorigin="anonymous">
<style>body{background:url(/bg.png)}</style>
<script>var re = /a<b/; if (a && b) { x("</b>"); }</script>
</head>
<body background="/old.gif">
<a href="page2.html">next</a>
<img src="/i.png" srcset="/i.png 1x, /i2.png 2x" alt="&amp;">
<form action="/submit"><button formaction="/other">go</button></form>
<svg><use xlink:href="/sprite.svg#icon"></use></svg>
<div style="background:url(/d.png)">x</div>
<!-- a comment -->
</body></html>`

func TestHTMLRewrite(t *testing.T) {
	rw := testRewriter()
	base := mustURL(t, "https://example.com/dir/index.html")
	out := string(rw.HTML([]byte(sampleHTML), base, "<!--SHIM-->"))

	mustContain := []string{
		`<!--SHIM-->`,
		`href="/p/https/example.com/s.css"`,
		`href="/p/https/example.com/dir/page2.html"`,
		`src="/p/https/example.com/i.png"`,
		`srcset="/p/https/example.com/i.png 1x, /p/https/example.com/i2.png 2x"`,
		`action="/p/https/example.com/submit"`,
		`formaction="/p/https/example.com/other"`,
		`xlink:href="/p/https/example.com/sprite.svg#icon"`,
		`background="/p/https/example.com/old.gif"`,
		`url(&#34;/p/https/example.com/d.png&#34;)`,
		`url("/p/https/example.com/bg.png")`,
		`content="5; url=/p/https/example.com/next"`,
		// untouched tokens survive byte for byte
		`var re = /a<b/; if (a && b) { x("</b>"); }`,
		`<!-- a comment -->`,
		`alt="&amp;"`,
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}
	mustNotContain := []string{"integrity=", "crossorigin=", "Content-Security-Policy"}
	for _, bad := range mustNotContain {
		if strings.Contains(out, bad) {
			t.Errorf("output still contains %q\n---\n%s", bad, out)
		}
	}
}

func TestHTMLBaseTagChangesResolution(t *testing.T) {
	rw := testRewriter()
	base := mustURL(t, "https://example.com/dir/index.html")
	in := `<head><base href="https://cdn.test/assets/"></head><body><img src="a.png"></body>`
	out := string(rw.HTML([]byte(in), base, ""))
	if !strings.Contains(out, `href="/p/https/cdn.test/assets/"`) {
		t.Errorf("base href not rewritten: %s", out)
	}
	if !strings.Contains(out, `src="/p/https/cdn.test/assets/a.png"`) {
		t.Errorf("relative URL after <base> resolved wrongly: %s", out)
	}
}

func TestHTMLInjectionFallback(t *testing.T) {
	rw := testRewriter()
	base := mustURL(t, "https://example.com/")
	out := string(rw.HTML([]byte(`<p>no head here</p>`), base, "<!--SHIM-->"))
	if !strings.HasPrefix(out, "<!--SHIM-->") {
		t.Errorf("shim not injected into a headless document: %s", out)
	}
	if strings.Count(out, "<!--SHIM-->") != 1 {
		t.Errorf("shim injected more than once: %s", out)
	}
}

func TestHTMLRewriteWithHostCodec(t *testing.T) {
	c, _ := NewHostCodec("gw.test", "", false)
	rw := Rewriter{Codec: c}
	base := mustURL(t, "https://example.com/dir/")
	out := string(rw.HTML([]byte(`<a href="/x">x</a>`), base, ""))
	if !strings.Contains(out, `href="http://example-com-s.gw.test/x"`) {
		t.Errorf("subdomain rewrite wrong: %s", out)
	}
}

func BenchmarkHTMLRewrite(b *testing.B) {
	rw := testRewriter()
	base, _ := url.Parse("https://example.com/dir/index.html")
	src := []byte(strings.Repeat(sampleHTML, 20))
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rw.HTML(src, base, "")
	}
}

func TestJSRewriteRelated(t *testing.T) {
	rw := Rewriter{Codec: PlainCodec{}, Scope: JSRelated}
	base := mustURL(t, "https://app.corp.example/portal")

	cases := []struct{ in, want string }{
		// The single sign-on hop: same registrable domain, so it is rewritten.
		{`location.href = "https://sso.corp.example/login?back=x"`,
			`location.href = "/p/https/sso.corp.example/login?back=x"`},
		// JSON escapes its slashes; the escaped form has to match too.
		{`{"url":"https:\/\/sso.corp.example\/login"}`,
			`{"url":"/p/https/sso.corp.example\/login"}`},
		// A port is part of the host.
		{`fetch("http://api.corp.example:8443/v1")`,
			`fetch("/p/http/api.corp.example:8443/v1")`},
		// The page's own host, trivially related.
		{`"https://app.corp.example/x"`, `"/p/https/app.corp.example/x"`},
		// Somebody else's domain is left alone: it may be a string the page
		// compares against, and the user is not tunnelling to it.
		{`"https://cdn.other.example/lib.js"`, `"https://cdn.other.example/lib.js"`},
		{`"ftp://files.corp.example/x"`, `"ftp://files.corp.example/x"`},
	}
	for _, tc := range cases {
		if got := rw.JS(tc.in, base); got != tc.want {
			t.Errorf("JS(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
}

func TestJSRewriteScopes(t *testing.T) {
	base := mustURL(t, "https://app.corp.example/")
	src := `a="https://sso.corp.example/x"; b="https://cdn.other.example/y"`

	off := Rewriter{Codec: PlainCodec{}, Scope: JSOff}
	if got := off.JS(src, base); got != src {
		t.Errorf("JSOff changed the script: %q", got)
	}

	all := Rewriter{Codec: PlainCodec{}, Scope: JSAll}
	got := all.JS(src, base)
	for _, want := range []string{`"/p/https/sso.corp.example/x"`, `"/p/https/cdn.other.example/y"`} {
		if !strings.Contains(got, want) {
			t.Errorf("JSAll missing %q in %q", want, got)
		}
	}
}

func TestRelatedHosts(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"app.corp.example", "sso.corp.example", true},
		{"corp.example", "sso.corp.example", true},
		{"app.corp.example", "app.corp.example", true},
		{"app.corp.example:8443", "app.corp.example", true},
		{"app.corp.example", "corp.other", false},
		{"10.0.0.1", "10.0.0.2", false},
		{"10.0.0.1", "10.0.0.1", true},
		{"intranet", "intranet", true},
		{"a.corp.local", "b.corp.local", true},
	}
	for _, tc := range cases {
		if got := relatedHosts(tc.a, tc.b); got != tc.want {
			t.Errorf("relatedHosts(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestHTMLRewritesInlineScripts(t *testing.T) {
	rw := Rewriter{Codec: PlainCodec{}, Scope: JSRelated}
	base := mustURL(t, "https://app.corp.example/")
	in := `<html><head><script>if (!token) location.href = "https://sso.corp.example/login";</script></head>` +
		`<body><script>var re = /a<b/; x("</b>"); var cdn = "https://cdn.other.example/l.js";</script></body></html>`
	out := string(rw.HTML([]byte(in), base, ""))

	if !strings.Contains(out, `location.href = "/p/https/sso.corp.example/login"`) {
		t.Errorf("inline navigation was not rewritten: %s", out)
	}
	// Everything else about script bodies still survives untouched.
	for _, want := range []string{`var re = /a<b/;`, `x("</b>");`, `"https://cdn.other.example/l.js"`} {
		if !strings.Contains(out, want) {
			t.Errorf("script body was damaged, missing %q: %s", want, out)
		}
	}
}
