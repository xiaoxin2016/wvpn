package webvpn

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// Guard decides which origins the gateway is willing to reach. A WebVPN is an
// open relay by construction, so the default posture is: public unicast
// addresses only, which keeps the gateway from being turned into an SSRF
// pivot into the network it runs in.
type Guard struct {
	// AllowPrivate permits loopback, RFC1918 and CGNAT targets. Link-local and
	// multicast stay blocked either way.
	AllowPrivate bool
	// AllowHosts, when non-empty, is an allowlist. An entry matches a host
	// exactly, or as a domain suffix when written as ".example.com".
	AllowHosts []string
	// DenyHosts is applied after AllowHosts and uses the same matching rules.
	DenyHosts []string
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

// CheckHost applies the name-based policy. It runs before DNS resolution, so it
// is only half of the story; CheckAddr closes the DNS-rebinding gap.
func (g *Guard) CheckHost(host string) error {
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	if name == "" {
		return fmt.Errorf("empty host")
	}
	if len(g.AllowHosts) > 0 && !hostMatches(name, g.AllowHosts) {
		return fmt.Errorf("host %q is not on the allowlist", name)
	}
	if hostMatches(name, g.DenyHosts) {
		return fmt.Errorf("host %q is on the denylist", name)
	}
	// A literal private address is rejected here as well, so the error surfaces
	// before a connection is attempted.
	if addr, err := netip.ParseAddr(name); err == nil {
		return g.CheckAddr(addr)
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

// DialControl returns a net.Dialer Control hook that re-checks the address the
// resolver actually returned. Doing the check here — rather than only on the
// hostname — is what defeats DNS rebinding, because this runs on the socket
// that is about to be connected.
func (g *Guard) DialControl() func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("webvpn: unparseable dial address %q", address)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("webvpn: unparseable dial address %q", address)
		}
		if err := g.CheckAddr(addr); err != nil {
			return fmt.Errorf("webvpn: blocked upstream: %w", err)
		}
		return nil
	}
}
