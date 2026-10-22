package store

import (
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// HeaderRule adds one request header to what the gateway sends a site. It is
// how an operator tells a test environment from production, hands a site a
// static key it expects, or marks traffic that came through the gateway.
//
// The configured value replaces whatever the browser sent under that name: a
// header the operator sets on the way in is not one a user can override from
// the other side.
type HeaderRule struct {
	// Site is a host pattern in the same form as the access policy's site
	// list: "test.corp.com" (which covers its sub-domains), "*.corp.com", or a
	// CIDR block, which only an IP-literal target can match — the header is set
	// before anything is resolved.
	Site string `json:"site"`
	// Name and Value are the header itself.
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Limits on the header rules, which are applied to every proxied request.
const (
	MaxHeaderRules   = 200
	MaxHeaderValue   = 4096
	maxHeaderNameLen = 256
)

// reservedHeaders are the ones the gateway itself decides, or that describe the
// connection rather than the request. Letting the console set them would break
// the proxy (Host, Content-Length), undo its rewriting (Origin, Referer),
// bypass a switch that exists for them (X-Forwarded-For), or hand a site the
// gateway's own business (Cookie, the omit marker).
var reservedHeaders = map[string]string{
	"Host":                "目标地址决定",
	"Cookie":              "网关按站点管理 Cookie",
	"Origin":              "网关会改写成目标站点自身",
	"Referer":             "网关会改写成目标站点自身",
	"Accept-Encoding":     "网关需要能解开响应以便改写",
	"Content-Length":      "由请求体决定",
	"Transfer-Encoding":   "由请求体决定",
	"Connection":          "这是连接级的头",
	"Keep-Alive":          "这是连接级的头",
	"Proxy-Connection":    "这是连接级的头",
	"Proxy-Authorization": "这是给代理的头，源站用不上",
	"Te":                  "这是连接级的头",
	"Trailer":             "这是连接级的头",
	"Upgrade":             "这是连接级的头",
	"X-Forwarded-For":     "请用「会话与来源 IP」里的开关",
	"X-Forwarded-Host":    "网关不会向源站透露自己的地址",
	"X-Forwarded-Proto":   "网关不会向源站透露自己的地址",
	"X-Wvpn-Credentials":  "网关内部使用",
}

func normalizeHeaderRules(in []HeaderRule) []HeaderRule {
	out := make([]HeaderRule, 0, len(in))
	for _, r := range in {
		r.Site = strings.ToLower(strings.TrimSpace(r.Site))
		r.Name = strings.TrimSpace(r.Name)
		// Surrounding whitespace is not part of a header value (RFC 9110 §5.5).
		r.Value = strings.TrimSpace(r.Value)
		if r.Site == "" && r.Name == "" && r.Value == "" {
			continue // a row the editor left blank
		}
		out = append(out, r)
	}
	return out
}

func validateHeaderRules(rules []HeaderRule) error {
	if len(rules) > MaxHeaderRules {
		return fmt.Errorf("附加请求头最多 %d 条", MaxHeaderRules)
	}
	for i, r := range rules {
		where := fmt.Sprintf("附加请求头第 %d 条", i+1)
		if r.Site == "" {
			return fmt.Errorf("%s：站点不能为空", where)
		}
		if _, err := parseSites([]string{r.Site}); err != nil {
			return fmt.Errorf("%s：%w", where, err)
		}
		if r.Name == "" {
			return fmt.Errorf("%s：Header 名称不能为空", where)
		}
		if len(r.Name) > maxHeaderNameLen || !validHeaderName(r.Name) {
			return fmt.Errorf("%s：%q 不是合法的 Header 名称（只能用字母、数字和 !#$%%&'*+-.^_`|~）", where, r.Name)
		}
		if why, ok := reservedHeaders[textproto.CanonicalMIMEHeaderKey(r.Name)]; ok {
			return fmt.Errorf("%s：%s 不能在这里设置，%s", where, textproto.CanonicalMIMEHeaderKey(r.Name), why)
		}
		if r.Value == "" {
			return fmt.Errorf("%s：%s 的值不能为空", where, r.Name)
		}
		if len(r.Value) > MaxHeaderValue {
			return fmt.Errorf("%s：%s 的值超过 %d 字节", where, r.Name, MaxHeaderValue)
		}
		// Rejects CR and LF above all: a value that could end the header line
		// would let the console write arbitrary headers, or a second request.
		if !validHeaderValue(r.Value) {
			return fmt.Errorf("%s：%s 的值含有不允许的控制字符（如换行）", where, r.Name)
		}
	}
	return nil
}

// validHeaderName reports whether s is an HTTP token (RFC 9110 §5.1, §5.6.2).
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// validHeaderValue reports whether s can be sent as a field value (RFC 9110
// §5.5): no control characters other than horizontal tab, and so no CR or LF.
func validHeaderValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// headerRule is a HeaderRule with its site pattern parsed, which is the form
// the proxy consults on every request.
type headerRule struct {
	site        siteRules
	name, value string
}

func compileHeaderRules(rules []HeaderRule) []headerRule {
	out := make([]headerRule, 0, len(rules))
	for _, r := range rules {
		site, err := parseSites([]string{r.Site})
		if err != nil {
			continue // Set validated it; a hand-edited file loses only this rule
		}
		out = append(out, headerRule{site: site, name: r.Name, value: r.Value})
	}
	return out
}

// HeadersFor returns the headers to add to a request for this target host, in
// the order they were configured. Where two rules set the same header the later
// one wins, so a broad rule can be followed by a narrower exception.
func (s *Store) HeadersFor(host string) []HeaderRule {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	s.mu.RLock()
	rules := s.headers
	s.mu.RUnlock()

	var out []HeaderRule
	for _, r := range rules {
		if r.site.matchHost(host) {
			out = append(out, HeaderRule{Name: r.name, Value: r.value})
		}
	}
	return out
}
