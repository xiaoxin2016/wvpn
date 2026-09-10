package webvpn

import (
	"context"
	"net/netip"
	"testing"
)

func TestGuardBlocksInternalAddresses(t *testing.T) {
	g := &Guard{}
	blocked := []string{
		"127.0.0.1", "::1", "10.0.0.5", "192.168.1.1", "172.16.3.4",
		"169.254.169.254", "0.0.0.0", "100.64.1.1", "fd00::1", "::ffff:127.0.0.1",
	}
	for _, ip := range blocked {
		if err := g.CheckAddr(netip.MustParseAddr(ip)); err == nil {
			t.Errorf("CheckAddr(%s) allowed an internal address", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "93.184.216.34", "2606:4700::1111"} {
		if err := g.CheckAddr(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("CheckAddr(%s) = %v, want allowed", ip, err)
		}
	}
}

func TestGuardAllowPrivate(t *testing.T) {
	g := &Guard{AllowPrivate: true}
	for _, ip := range []string{"127.0.0.1", "10.0.0.5", "192.168.1.1", "::1"} {
		if err := g.CheckAddr(netip.MustParseAddr(ip)); err != nil {
			t.Errorf("CheckAddr(%s) with AllowPrivate = %v", ip, err)
		}
	}
	// Cloud metadata stays out of reach even then.
	for _, ip := range []string{"169.254.169.254", "fe80::1", "224.0.0.1"} {
		if err := g.CheckAddr(netip.MustParseAddr(ip)); err == nil {
			t.Errorf("CheckAddr(%s) with AllowPrivate allowed a link-local/multicast address", ip)
		}
	}
}

func TestGuardHostPolicy(t *testing.T) {
	g := NewGuard("example.com, .corp.local", "secret.example.com", true)
	allowed := []string{"example.com", "www.example.com", "a.b.corp.local", "EXAMPLE.COM"}
	for _, h := range allowed {
		if err := g.CheckHost(h); err != nil {
			t.Errorf("CheckHost(%s) = %v, want allowed", h, err)
		}
	}
	denied := []string{"evil.test", "secret.example.com", "corp.local.evil.test"}
	for _, h := range denied {
		if err := g.CheckHost(h); err == nil {
			t.Errorf("CheckHost(%s) allowed", h)
		}
	}
}

func TestGuardHostWithPortAndLiteral(t *testing.T) {
	g := &Guard{}
	if err := g.CheckHost("127.0.0.1:8080"); err == nil {
		t.Error("literal loopback with port was allowed")
	}
	if err := g.CheckHost("[::1]:8080"); err == nil {
		t.Error("literal IPv6 loopback was allowed")
	}
	if err := g.CheckHost("example.com:8443"); err != nil {
		t.Errorf("CheckHost(example.com:8443) = %v", err)
	}
}

func TestDialControlRejectsResolvedPrivateAddress(t *testing.T) {
	// The name check cannot see a DNS answer, so the dial-time hook is what
	// stops a rebinding record from reaching the internal network.
	control := (&Guard{}).DialControl(nil)
	ctx := context.Background()
	if err := control(ctx, "tcp4", "10.1.2.3:443", nil); err == nil {
		t.Error("DialControl allowed a private address")
	}
	if err := control(ctx, "tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("DialControl blocked a public address: %v", err)
	}
}

// fakeSite is a hand-rolled SitePolicy so the guard can be tested without the
// store package.
type fakeSite struct {
	allowlist bool
	addrRules bool
	hosts     map[string]Verdict
	addrs     map[string]Verdict
}

func (f fakeSite) RequiresMatch() bool { return f.allowlist }
func (f fakeSite) HasAddrRules() bool  { return f.addrRules }
func (f fakeSite) HostVerdict(host string) Verdict {
	return f.hosts[host]
}
func (f fakeSite) AddrVerdict(addr netip.Addr) Verdict {
	return f.addrs[addr.String()]
}

func TestGuardSitePolicy(t *testing.T) {
	denial := &Guard{AllowPrivate: true, Site: fakeSite{
		hosts: map[string]Verdict{"blocked.test": VerdictDeny},
	}}
	if _, err := denial.CheckTarget("blocked.test", false); err == nil {
		t.Error("denylisted host was allowed")
	}
	if _, err := denial.CheckTarget("other.test", false); err != nil {
		t.Errorf("unlisted host under a denylist: %v", err)
	}

	// An allowlist with no address rules can refuse by name, with a clear error.
	byName := &Guard{AllowPrivate: true, Site: fakeSite{
		allowlist: true,
		hosts:     map[string]Verdict{"ok.test": VerdictAllow},
	}}
	check, err := byName.CheckTarget("ok.test", false)
	if err != nil || !check.Allowed {
		t.Fatalf("CheckTarget(ok.test) = %+v, %v", check, err)
	}
	if _, err := byName.CheckTarget("nope.test", false); err == nil {
		t.Error("allowlist let an unlisted host through")
	}

	// With address rules the name phase defers, and the dial phase decides.
	byAddr := &Guard{AllowPrivate: true, Site: fakeSite{
		allowlist: true,
		addrRules: true,
		addrs:     map[string]Verdict{"10.1.2.3": VerdictAllow},
	}}
	check, err = byAddr.CheckTarget("anything.test", false)
	if err != nil || check.Allowed {
		t.Fatalf("CheckTarget deferred wrongly: %+v, %v", check, err)
	}
	if err := byAddr.CheckDialAddr(netip.MustParseAddr("10.1.2.3"), check); err != nil {
		t.Errorf("CheckDialAddr refused an allowlisted network: %v", err)
	}
	if err := byAddr.CheckDialAddr(netip.MustParseAddr("10.9.9.9"), check); err == nil {
		t.Error("CheckDialAddr allowed an address outside the allowlist")
	}
	// A name the policy already accepted does not need a second match.
	if err := byAddr.CheckDialAddr(netip.MustParseAddr("10.9.9.9"), SiteCheck{Allowed: true}); err != nil {
		t.Errorf("CheckDialAddr second-guessed a name-phase allow: %v", err)
	}
}

func TestGuardAdminBypassesSitePolicy(t *testing.T) {
	g := &Guard{AllowPrivate: true, Site: fakeSite{
		allowlist: true,
		addrRules: true,
		hosts:     map[string]Verdict{"blocked.test": VerdictDeny},
		addrs:     map[string]Verdict{"10.0.0.1": VerdictDeny},
	}}

	// A normal user is bound by the policy at both phases.
	if _, err := g.CheckTarget("blocked.test", false); err == nil {
		t.Error("denylisted host reached a normal user")
	}
	if err := g.CheckDialAddr(netip.MustParseAddr("10.0.0.1"), SiteCheck{}); err == nil {
		t.Error("denylisted address reached a normal user")
	}

	// An administrator is exempt from the console-managed policy.
	check, err := g.CheckTarget("blocked.test", true)
	if err != nil {
		t.Fatalf("admin blocked by the site policy: %v", err)
	}
	if err := g.CheckDialAddr(netip.MustParseAddr("10.0.0.1"), check); err != nil {
		t.Errorf("admin blocked at dial time by the site policy: %v", err)
	}

	// The operator's own boundary still holds for administrators.
	hard := &Guard{DenyHosts: []string{"forbidden.test"}, Site: fakeSite{}}
	if _, err := hard.CheckTarget("forbidden.test", true); err == nil {
		t.Error("admin bypassed the command-line denylist")
	}
	if _, err := hard.CheckTarget("127.0.0.1", true); err == nil {
		t.Error("admin bypassed the internal-address guard")
	}
}
