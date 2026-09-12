package webvpn

import (
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

func TestPlainCodecRoundTrip(t *testing.T) {
	c := PlainCodec{}
	cases := []struct {
		target string
		want   string
	}{
		{"https://example.com/", "/p/https/example.com/"},
		{"https://example.com", "/p/https/example.com/"},
		{"http://example.com:8080/a/b?c=d&e=f", "/p/http/example.com:8080/a/b?c=d&e=f"},
		{"https://example.com/%E4%B8%AD%20%E6%96%87/x", "/p/https/example.com/%E4%B8%AD%20%E6%96%87/x"},
		{"wss://example.com/socket", "/p/wss/example.com/socket"},
		{"https://[2001:db8::1]:8443/x", "/p/https/[2001:db8::1]:8443/x"},
	}
	for _, tc := range cases {
		u := mustURL(t, tc.target)
		got := c.Encode(u)
		if got != tc.want {
			t.Errorf("Encode(%s) = %q, want %q", tc.target, got, tc.want)
		}
		ref := mustURL(t, "http://gw.local"+got)
		back, err := c.Decode("gw.local", ref.EscapedPath(), ref.RawQuery)
		if err != nil {
			t.Fatalf("Decode(%q): %v", got, err)
		}
		if want := mustURL(t, tc.target); back.Scheme != want.Scheme || back.Host != want.Host ||
			back.EscapedPath() != orSlash(want.EscapedPath()) || back.RawQuery != want.RawQuery {
			t.Errorf("round trip of %s gave %s", tc.target, back)
		}
	}
}

func orSlash(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

func TestPlainCodecRejects(t *testing.T) {
	c := PlainCodec{}
	for _, path := range []string{"/", "/p/", "/p/ftp/example.com/", "/p/https//x", "/other/https/x"} {
		if _, err := c.Decode("gw", path, ""); err == nil {
			t.Errorf("Decode(%q) unexpectedly succeeded", path)
		}
	}
	if got := c.Encode(mustURL(t, "ftp://example.com/x")); got != "" {
		t.Errorf("Encode(ftp) = %q, want empty", got)
	}
}

func TestWRDCodecRoundTrip(t *testing.T) {
	c, err := NewWRDCodec(DefaultWRDKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		"https://example.com/",
		"http://intranet.corp:8080/a?b=c",
		"https://a.b.c.example.com/deep/path",
	} {
		u := mustURL(t, target)
		enc := c.Encode(u)
		if !c.Match("gw", enc) {
			t.Fatalf("Match(%q) = false", enc)
		}
		ref := mustURL(t, "http://gw.local"+enc)
		back, err := c.Decode("gw.local", ref.EscapedPath(), ref.RawQuery)
		if err != nil {
			t.Fatalf("Decode(%q): %v", enc, err)
		}
		if back.Scheme != u.Scheme || back.Host != u.Host || back.RawQuery != u.RawQuery {
			t.Errorf("round trip of %s gave %s", target, back)
		}
	}
}

func TestWRDCodecShape(t *testing.T) {
	c, err := NewWRDCodec(DefaultWRDKey)
	if err != nil {
		t.Fatal(err)
	}
	enc := c.Encode(mustURL(t, "https://example.com/x"))
	const ivHex = "77726476706e69737468656265737421" // hex("wrdvpnisthebest!")
	want := "/https/" + ivHex
	if len(enc) < len(want) || enc[:len(want)] != want {
		t.Errorf("Encode = %q, want prefix %q", enc, want)
	}
	if got := c.Encode(mustURL(t, "http://example.com:8080/")); got[:len("/http-8080/")] != "/http-8080/" {
		t.Errorf("port went missing: %q", got)
	}
}

func TestWRDCodecWrongKeyFails(t *testing.T) {
	good, _ := NewWRDCodec(DefaultWRDKey)
	other, _ := NewWRDCodec("0123456789abcdef")
	enc := good.Encode(mustURL(t, "https://example.com/x"))
	if _, err := other.Decode("gw", enc, ""); err == nil {
		t.Error("decoding with the wrong key unexpectedly succeeded")
	}
}

func TestHostCodecRoundTrip(t *testing.T) {
	c, err := NewHostCodec("webvpn.example.com", "", "8001", false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		target string
		want   string
	}{
		{"https://git-scm.com/docs", "http://git--scm-com-s.webvpn.example.com:8001/docs"},
		{"http://oa.corp.local/index.jsp?a=1", "http://oa-corp-local.webvpn.example.com:8001/index.jsp?a=1"},
	}
	for _, tc := range cases {
		got := c.Encode(mustURL(t, tc.target))
		if got != tc.want {
			t.Fatalf("Encode(%s) = %q, want %q", tc.target, got, tc.want)
		}
		ref := mustURL(t, got)
		if !c.Match(ref.Host, ref.EscapedPath()) {
			t.Fatalf("Match(%s) = false", got)
		}
		back, err := c.Decode(ref.Host, ref.EscapedPath(), ref.RawQuery)
		if err != nil {
			t.Fatalf("Decode(%q): %v", got, err)
		}
		if back.String() != tc.target {
			t.Errorf("round trip of %s gave %s", tc.target, back)
		}
	}
}

func TestLabelRoundTrip(t *testing.T) {
	for _, host := range []string{"example.com", "git-scm.com", "a--b.example.com", "x.y.z", "intranet"} {
		for _, port := range []string{"", "8080", "443"} {
			for _, tls := range []bool{false, true} {
				label := encodeLabel(host, port, tls)
				gotHost, gotPort, gotTLS := decodeLabel(label)
				if gotHost != host || gotPort != port || gotTLS != tls {
					t.Errorf("label round trip of (%q,%q,%v) gave (%q,%q,%v) via %q",
						host, port, tls, gotHost, gotPort, gotTLS, label)
				}
			}
		}
	}
}

func TestHostCodecCarriesThePort(t *testing.T) {
	c, err := NewHostCodec("app.intra.corp.com", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ target, want string }{
		{"http://oa.intra.corp.com/x", "http://oa-intra-corp-com.app.intra.corp.com/x"},
		{"http://oa.intra.corp.com:8080/x", "http://oa-intra-corp-com-p8080.app.intra.corp.com/x"},
		{"https://git-scm.com:8443/docs", "https://git--scm-com-p8443-s.app.intra.corp.com/docs"},
		// A default port is not part of the address.
		{"https://oa.intra.corp.com:443/x", "https://oa-intra-corp-com-s.app.intra.corp.com/x"},
	}
	for _, tc := range cases {
		// The gateway's own scheme follows its TLS setting, so compare on a
		// TLS gateway for the https cases.
		codec := c
		if strings.HasPrefix(tc.want, "https://") {
			codec, _ = NewHostCodec("app.intra.corp.com", "", "", true)
		}
		got := codec.Encode(mustURL(t, tc.target))
		if got != tc.want {
			t.Errorf("Encode(%s) = %q, want %q", tc.target, got, tc.want)
			continue
		}
		ref := mustURL(t, got)
		back, err := codec.Decode(ref.Host, ref.EscapedPath(), ref.RawQuery)
		if err != nil {
			t.Fatalf("Decode(%q): %v", got, err)
		}
		if back.String() != strings.Replace(tc.target, ":443", "", 1) {
			t.Errorf("round trip of %s gave %s", tc.target, back)
		}
	}
}

func TestHostCodecFallsBackForLongLabels(t *testing.T) {
	c, _ := NewHostCodec("app.intra.corp.com", "", "", false)
	long := strings.Repeat("a", 60) + ".corp.com"
	got := c.Encode(mustURL(t, "http://"+long+"/x"))
	if !strings.HasPrefix(got, "/p/http/") {
		t.Errorf("a host too long for a DNS label should fall back to the path form: %q", got)
	}
}

func TestParseUserInput(t *testing.T) {
	u, err := ParseUserInput(" example.com/path ")
	if err != nil || u.Scheme != "https" || u.Host != "example.com" || u.Path != "/path" {
		t.Fatalf("ParseUserInput = %v, %v", u, err)
	}
	if _, err := ParseUserInput("ftp://example.com"); err == nil {
		t.Error("ftp target unexpectedly accepted")
	}
	if _, err := ParseUserInput(""); err == nil {
		t.Error("empty input unexpectedly accepted")
	}
}

func TestHostCodecKeepsThePortalOutOfTheTargetSpace(t *testing.T) {
	// The portal sits inside the same wildcard domain the targets use, so it
	// has to be excluded from it in both directions.
	c, err := NewHostCodec("intra.corp.com", "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Portal != "app.intra.corp.com" {
		t.Fatalf("default portal host = %q", c.Portal)
	}

	if c.Match("app.intra.corp.com", "/") {
		t.Error("the portal was treated as a proxied target")
	}
	if !c.Match("oa-corp-example.intra.corp.com", "/") {
		t.Error("a target sub-domain was not recognised")
	}
	if _, err := c.Decode("app.intra.corp.com", "/admin", ""); err == nil {
		t.Error("the portal host decoded as a target")
	}

	// A target whose label would land on the portal's own name goes back to
	// the path form rather than taking the console with it.
	got := c.Encode(mustURL(t, "http://app/"))
	if !strings.HasPrefix(got, "/p/http/") {
		t.Errorf("a target colliding with the portal name = %q", got)
	}

	// An explicitly named portal is honoured.
	named, err := NewHostCodec("intra.corp.com", "webvpn.intra.corp.com", "", false)
	if err != nil {
		t.Fatal(err)
	}
	if named.Match("webvpn.intra.corp.com", "/") {
		t.Error("the named portal was treated as a target")
	}
	if !named.Match("app.intra.corp.com", "/") {
		t.Error("app.<domain> should be an ordinary target once the portal is named elsewhere")
	}
}

func TestHostCodecTargetsUseTheWildcardDomain(t *testing.T) {
	c, _ := NewHostCodec("intra.corp.com", "", "8443", true)
	got := c.Encode(mustURL(t, "https://oa.other.example/portal"))
	want := "https://oa-other-example-s.intra.corp.com:8443/portal"
	if got != want {
		t.Errorf("Encode = %q, want %q", got, want)
	}
	ref := mustURL(t, got)
	back, err := c.Decode(ref.Host, ref.EscapedPath(), ref.RawQuery)
	if err != nil || back.String() != "https://oa.other.example/portal" {
		t.Errorf("round trip gave %v, %v", back, err)
	}
}
