package webvpn

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// Verdict is what a SitePolicy has to say about a target.
type Verdict int

const (
	// VerdictNeutral means the policy has no opinion: a pass under a denylist,
	// and under an allowlist a decision deferred to the resolved address.
	VerdictNeutral Verdict = iota
	// VerdictAllow means the target satisfies an allowlist.
	VerdictAllow
	// VerdictDeny means the target is refused.
	VerdictDeny
)

// SitePolicy is the runtime, admin-editable half of the target policy. It is
// consulted twice per request: once on the hostname, before DNS, and once on
// the address the resolver actually returned, which is what gives a CIDR rule
// any teeth against a name that points somewhere unexpected.
type SitePolicy interface {
	// RequiresMatch reports whether a target must match to be reachable at all
	// (allowlist mode).
	RequiresMatch() bool
	// HasAddrRules reports whether the policy contains address rules. Without
	// them an unmatched name under an allowlist can be refused immediately,
	// with a clear error, instead of failing at dial time.
	HasAddrRules() bool
	HostVerdict(host string) Verdict
	AddrVerdict(addr netip.Addr) Verdict
}

// SiteCheck carries the outcome of the name-phase site check into the
// dial-phase one, so a target accepted by name is not asked to match a second
// time against the address rules.
type SiteCheck struct {
	// Bypass means the requester is exempt from the admin-editable policy.
	// Administrators are: the console they control must not be able to lock
	// them out of the network they administer.
	Bypass bool
	// Allowed means the hostname already satisfied the policy.
	Allowed bool
}

// Guard decides which origins the gateway is willing to reach. A WebVPN is an
// open relay by construction, so the default posture is: public unicast
// addresses only, which keeps the gateway from being turned into an SSRF
// pivot into the network it runs in.
//
// The command-line lists are the operator's hard boundary; Site is the layer
// the admin console edits, and both have to pass.
type Guard struct {
	// AllowPrivate permits loopback, RFC1918 and CGNAT targets. Link-local and
	// multicast stay blocked either way.
	AllowPrivate bool
	// AllowHosts, when non-empty, is an allowlist. An entry matches a host
	// exactly, or as a domain suffix when written as ".example.com".
	AllowHosts []string
	// DenyHosts is applied after AllowHosts and uses the same matching rules.
	DenyHosts []string
	// Site is the admin-editable policy. Nil means no runtime restriction.
	Site SitePolicy
}

// NewGuard builds a Guard from comma-separated flag values.
func NewGuard(allow, deny string, allowPrivate bool) *Guard {
	return &Guard{
		AllowPrivate: allowPrivate,
		AllowHosts:   splitList(allow),
		DenyHosts:    splitList(deny),
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func hostMatches(host string, patterns []string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range patterns {
		if p == host {
			return true
		}
		if strings.HasPrefix(p, ".") && strings.HasSuffix(host, p) {
			return true
		}
		// "example.com" also covers "www.example.com".
		if !strings.HasPrefix(p, ".") && strings.HasSuffix(host, "."+p) {
			return true
		}
	}
	return false
}

// CheckHost applies the name-based policy to a target nobody is exempt from.
// Use CheckTarget when the result feeds a proxied request.
func (g *Guard) CheckHost(host string) error {
	_, err := g.CheckTarget(host, false)
	return err
}

// CheckTarget applies the name-based policy. It runs before DNS resolution, so
// it is only half of the story: CheckDialAddr closes the DNS-rebinding gap and
// applies the address rules.
//
// bypass exempts the requester from the admin-editable site policy. The
// operator's own -allow/-deny lists and the internal-address guard still apply:
// those are the boundary of the machine the gateway runs on, not a setting the
// console owns.
func (g *Guard) CheckTarget(host string, bypass bool) (SiteCheck, error) {
	check := SiteCheck{Bypass: bypass}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	if name == "" {
		return check, fmt.Errorf("empty host")
	}
	if len(g.AllowHosts) > 0 && !hostMatches(name, g.AllowHosts) {
		return check, fmt.Errorf("host %q is not on the allowlist", name)
	}
	if hostMatches(name, g.DenyHosts) {
		return check, fmt.Errorf("host %q is on the denylist", name)
	}
	// A literal private address is rejected here as well, so the error surfaces
	// before a connection is attempted.
	if addr, err := netip.ParseAddr(name); err == nil {
		if err := g.CheckAddr(addr); err != nil {
			return check, err
		}
	}

	if g.Site == nil || bypass {
		return check, nil
	}
	switch g.Site.HostVerdict(name) {
	case VerdictDeny:
		return check, fmt.Errorf("目标 %q 在禁止访问的站点清单中", name)
	case VerdictAllow:
		check.Allowed = true
		return check, nil
	}
	if g.Site.RequiresMatch() && !g.Site.HasAddrRules() {
		return check, fmt.Errorf("目标 %q 不在允许访问的站点清单中", name)
	}
	return check, nil
}

// CheckDialAddr is the dial-time half: the baseline address policy plus the
// site policy, applied to the address the resolver returned.
func (g *Guard) CheckDialAddr(addr netip.Addr, check SiteCheck) error {
	if err := g.CheckAddr(addr); err != nil {
		return err
	}
	if g.Site == nil || check.Bypass {
		return nil
	}
	switch g.Site.AddrVerdict(addr) {
	case VerdictDeny:
		return fmt.Errorf("目标地址 %s 在禁止访问的站点清单中", addr)
	case VerdictAllow:
		return nil
	}
	if !check.Allowed && g.Site.RequiresMatch() {
		return fmt.Errorf("目标地址 %s 不在允许访问的站点清单中", addr)
	}
	return nil
}

// CheckAddr applies the address policy to an already-resolved IP.
//
// Link-local and multicast are refused unconditionally: 169.254.169.254 and its
// IPv6 twin are the cloud metadata services, and a gateway that has to reach
// RFC1918 hosts still has no business reaching those.
func (g *Guard) CheckAddr(addr netip.Addr) error {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	switch {
	case !addr.IsValid(), addr.IsUnspecified():
		return fmt.Errorf("refusing unspecified address")
	case addr.IsLinkLocalUnicast(), addr.IsLinkLocalMulticast():
		return fmt.Errorf("refusing link-local address %s", addr)
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("refusing multicast address %s", addr)
	}
	if g.AllowPrivate {
		return nil
	}
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("refusing loopback address %s", addr)
	case addr.IsPrivate():
		return fmt.Errorf("refusing private address %s", addr)
	case isCGNAT(addr):
		return fmt.Errorf("refusing carrier-grade NAT address %s", addr)
	}
	return nil
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func isCGNAT(addr netip.Addr) bool {
	return addr.Is4() && cgnat.Contains(addr)
}

// DialControl returns a net.Dialer ControlContext hook that re-checks the
// address the resolver actually returned. Doing the check here — rather than
// only on the hostname — is what defeats DNS rebinding, because this runs on
// the socket that is about to be connected.
//
// siteCheck reads the name-phase result back out of the request context; the
// proxy puts it there.
func (g *Guard) DialControl(siteCheck func(context.Context) SiteCheck) func(ctx context.Context, network, address string, c syscall.RawConn) error {
	return func(ctx context.Context, network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("webvpn: unparseable dial address %q", address)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("webvpn: unparseable dial address %q", address)
		}
		var check SiteCheck
		if siteCheck != nil {
			check = siteCheck(ctx)
		}
		if err := g.CheckDialAddr(addr, check); err != nil {
			return fmt.Errorf("webvpn: blocked upstream: %w", err)
		}
		return nil
	}
}
