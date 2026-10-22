package store

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHeaderRulesMatchTheSitesTheyName(t *testing.T) {
	s, err := LoadStore(filepath.Join(t.TempDir(), "config.json"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := s.Get()
	cfg.Headers = []HeaderRule{
		{Site: "test.corp.com", Name: "test-env", Value: "dev"},
		{Site: "*.uat.corp.com", Name: "test-env", Value: "uat"},
		{Site: "10.0.0.0/8", Name: "X-Zone", Value: "intranet"},
		// A narrower rule after a broad one: the later one wins.
		{Site: "corp.com", Name: "X-Via", Value: "webvpn"},
		{Site: "special.corp.com", Name: "X-Via", Value: "webvpn-special"},
	}
	if err := s.Set(cfg); err != nil {
		t.Fatal(err)
	}

	got := func(host string) map[string]string {
		out := map[string]string{}
		for _, h := range s.HeadersFor(host) {
			out[h.Name] = h.Value // later rules overwrite, as the proxy's Set does
		}
		return out
	}
	cases := []struct {
		host string
		want map[string]string
	}{
		{"test.corp.com", map[string]string{"test-env": "dev", "X-Via": "webvpn"}},
		{"TEST.corp.com:8443", map[string]string{"test-env": "dev", "X-Via": "webvpn"}},
		{"api.test.corp.com", map[string]string{"test-env": "dev", "X-Via": "webvpn"}},
		{"a.uat.corp.com", map[string]string{"test-env": "uat", "X-Via": "webvpn"}},
		{"special.corp.com", map[string]string{"X-Via": "webvpn-special"}},
		{"10.2.3.4:8080", map[string]string{"X-Zone": "intranet"}},
		{"prod.example.org", map[string]string{}},
	}
	for _, tc := range cases {
		g := got(tc.host)
		if len(g) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.host, g, tc.want)
			continue
		}
		for k, v := range tc.want {
			if g[k] != v {
				t.Errorf("%s: %s = %q, want %q", tc.host, k, g[k], v)
			}
		}
	}

	// They outlive the process.
	reopened, err := LoadStore(s.path, Config{})
	if err != nil {
		t.Fatal(err)
	}
	if hs := reopened.HeadersFor("test.corp.com"); len(hs) != 2 || hs[0].Value != "dev" {
		t.Errorf("after reload: %+v", hs)
	}
}

func TestHeaderRulesAreValidated(t *testing.T) {
	s, err := LoadStore(filepath.Join(t.TempDir(), "config.json"), Config{})
	if err != nil {
		t.Fatal(err)
	}
	bad := []struct {
		rule HeaderRule
		want string
	}{
		{HeaderRule{Site: "", Name: "test-env", Value: "dev"}, "站点不能为空"},
		{HeaderRule{Site: "test corp", Name: "test-env", Value: "dev"}, "不是合法的主机匹配式"},
		{HeaderRule{Site: "test.corp.com", Name: "", Value: "dev"}, "名称不能为空"},
		{HeaderRule{Site: "test.corp.com", Name: "test env", Value: "dev"}, "不是合法的 Header 名称"},
		{HeaderRule{Site: "test.corp.com", Name: "test-env:", Value: "dev"}, "不是合法的 Header 名称"},
		{HeaderRule{Site: "test.corp.com", Name: "test-env", Value: ""}, "值不能为空"},
		{HeaderRule{Site: "test.corp.com", Name: "test-env", Value: "dev\r\nX-Injected: 1"}, "控制字符"},
		{HeaderRule{Site: "test.corp.com", Name: "test-env", Value: "dev\nx"}, "控制字符"},
		{HeaderRule{Site: "test.corp.com", Name: "test-env", Value: strings.Repeat("a", MaxHeaderValue+1)}, "超过"},
		// The gateway's own business, in any letter case.
		{HeaderRule{Site: "test.corp.com", Name: "host", Value: "evil.example"}, "Host 不能在这里设置"},
		{HeaderRule{Site: "test.corp.com", Name: "COOKIE", Value: "a=b"}, "Cookie 不能在这里设置"},
		{HeaderRule{Site: "test.corp.com", Name: "x-forwarded-for", Value: "1.2.3.4"}, "会话与来源 IP"},
		{HeaderRule{Site: "test.corp.com", Name: "Transfer-Encoding", Value: "chunked"}, "不能在这里设置"},
		{HeaderRule{Site: "test.corp.com", Name: "X-Wvpn-Credentials", Value: "omit"}, "不能在这里设置"},
	}
	for _, tc := range bad {
		cfg := s.Get()
		cfg.Headers = []HeaderRule{tc.rule}
		err := s.Set(cfg)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want one mentioning %q", tc.rule, err, tc.want)
		}
	}
	if len(s.Get().Headers) != 0 {
		t.Error("a rejected rule was stored")
	}

	// A tab is a legal character inside a value, and surrounding space is not
	// part of it. Rows the editor left entirely blank are dropped, not refused.
	cfg := s.Get()
	cfg.Headers = []HeaderRule{
		{Site: " Test.Corp.com ", Name: " test-env ", Value: "  a\tb  "},
		{},
	}
	if err := s.Set(cfg); err != nil {
		t.Fatalf("a valid rule was refused: %v", err)
	}
	stored := s.Get().Headers
	if len(stored) != 1 || stored[0] != (HeaderRule{Site: "test.corp.com", Name: "test-env", Value: "a\tb"}) {
		t.Errorf("stored %+v", stored)
	}
}
