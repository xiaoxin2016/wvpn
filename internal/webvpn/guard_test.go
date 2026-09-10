package webvpn

import (
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
	control := (&Guard{}).DialControl()
	if err := control("tcp4", "10.1.2.3:443", nil); err == nil {
		t.Error("DialControl allowed a private address")
	}
	if err := control("tcp4", "8.8.8.8:443", nil); err != nil {
		t.Errorf("DialControl blocked a public address: %v", err)
	}
}
