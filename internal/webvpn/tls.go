package webvpn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// An internal site with a self-signed certificate is the normal case, not an
// attack, and refusing it outright makes the gateway useless there. Blanket
// -insecure-tls is the other extreme: it silently accepts any certificate for
// every target.
//
// So the gateway does what a browser does: it stops, shows what the certificate
// actually is, and continues only after someone says so — and then remembers
// that exact certificate rather than disabling verification for the host. A
// swapped certificate stops the traffic again.

// certError is returned by the TLS dialer when a certificate fails to verify
// and has not been confirmed. It carries what the interstitial has to show.
type certError struct {
	Host        string // host:port as dialed
	Reason      error
	Leaf        *x509.Certificate
	Fingerprint string
}

func (e *certError) Error() string {
	return fmt.Sprintf("webvpn: untrusted certificate for %s: %v", e.Host, e.Reason)
}

func (e *certError) Unwrap() error { return e.Reason }

// fingerprint is the SHA-256 of the certificate in the form a browser shows.
func fingerprint(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	hexed := strings.ToUpper(hex.EncodeToString(sum[:]))
	var b strings.Builder
	for i := 0; i < len(hexed); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexed[i : i+2])
	}
	return b.String()
}

// offerTTL bounds how long a confirmation may follow the interstitial that
// produced it, so the confirm endpoint cannot be used to pin a certificate the
// gateway never saw.
const offerTTL = 10 * time.Minute

type offer struct {
	fingerprint string
	seen        time.Time
}

// trustStore remembers certificates confirmed in this process. It is memory
// only: a restart asks again, which is the safer default for an exception.
type trustStore struct {
	mu      sync.Mutex
	pinned  map[string]string
	offered map[string]offer
	now     func() time.Time
}

func newTrustStore() *trustStore {
	return &trustStore{
		pinned:  map[string]string{},
		offered: map[string]offer{},
		now:     time.Now,
	}
}

// offer records a certificate the gateway has just shown to a user.
func (t *trustStore) offer(host, fp string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, v := range t.offered {
		if now.Sub(v.seen) > offerTTL {
			delete(t.offered, k)
		}
	}
	t.offered[host] = offer{fingerprint: fp, seen: now}
}

// confirm pins a certificate, but only one this gateway actually offered.
func (t *trustStore) confirm(host, fp string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	o, ok := t.offered[host]
	if !ok || o.fingerprint != fp || t.now().Sub(o.seen) > offerTTL {
		return false
	}
	delete(t.offered, host)
	t.pinned[host] = fp
	return true
}

// trusted reports whether this exact certificate was confirmed for this host.
func (t *trustStore) trusted(host, fp string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.pinned[host] == fp
}

// dialTLS replaces the transport's own TLS dialer so that a verification
// failure can be turned into a question instead of an error.
func (h *Handler) dialTLS(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		cfg := &tls.Config{
			ServerName: host,
			MinVersion: tls.VersionTLS12,
			// Verification happens below, by hand, so that a failure can carry
			// the certificate along with it.
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2", "http/1.1"},
		}
		conn := tls.Client(raw, cfg)
		if err := conn.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		if h.opts.InsecureTLS {
			return conn, nil // the operator turned verification off globally
		}

		state := conn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			conn.Close()
			return nil, fmt.Errorf("webvpn: %s presented no certificate", addr)
		}
		if err := verifyChain(host, state); err != nil {
			leaf := state.PeerCertificates[0]
			fp := fingerprint(leaf)
			if !h.trust.trusted(addr, fp) {
				conn.Close()
				return nil, &certError{Host: addr, Reason: err, Leaf: leaf, Fingerprint: fp}
			}
		}
		return conn, nil
	}
}

// verifyChain runs the verification the TLS stack would have run.
func verifyChain(host string, state tls.ConnectionState) error {
	opts := x509.VerifyOptions{
		DNSName:       host,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range state.PeerCertificates[1:] {
		opts.Intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(opts)
	return err
}

// untrustedData is what the interstitial shows about a certificate.
type untrustedData struct {
	Target      string
	Host        string
	Reason      string
	Subject     string
	Issuer      string
	SelfSigned  bool
	Expired     bool
	NotBefore   string
	NotAfter    string
	Names       string
	Fingerprint string
	Next        string
}

// serveUntrusted asks whether to continue to a site whose certificate does not
// verify, and records the offer so the answer can be checked against it.
func (h *Handler) serveUntrusted(w http.ResponseWriter, r *http.Request, ce *certError) {
	h.trust.offer(ce.Host, ce.Fingerprint)
	h.log.Printf("webvpn: untrusted certificate for %s (%s): %v", ce.Host, ce.Fingerprint, ce.Reason)

	if !isNavigation(r) {
		// A sub-resource cannot show a page; failing it plainly is clearer than
		// rendering HTML into an <img>.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, "证书不受信任，请先在主页面中确认后再访问 (%s)\n", ce.Host)
		return
	}

	// ErrorHandler runs with the outbound request, whose URL is the target's
	// own — the way back has to be rebuilt from the target instead.
	target, next := ce.Host, "/"
	if info := infoFrom(r.Context()); info != nil {
		target = info.target.String()
		if enc := h.codec().Encode(info.target); enc != "" {
			next = enc
		}
	}
	leaf := ce.Leaf
	names := append([]string{}, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}

	data := untrustedData{
		Target:      target,
		Host:        ce.Host,
		Reason:      ce.Reason.Error(),
		Subject:     leaf.Subject.String(),
		Issuer:      leaf.Issuer.String(),
		SelfSigned:  leaf.Subject.String() == leaf.Issuer.String(),
		Expired:     h.trust.now().After(leaf.NotAfter) || h.trust.now().Before(leaf.NotBefore),
		NotBefore:   leaf.NotBefore.Local().Format("2006-01-02 15:04"),
		NotAfter:    leaf.NotAfter.Local().Format("2006-01-02 15:04"),
		Names:       strings.Join(names, ", "),
		Fingerprint: ce.Fingerprint,
		Next:        next,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// 502: the upstream leg did not happen. The body explains why and offers
	// the way forward.
	w.WriteHeader(http.StatusBadGateway)
	if err := untrustedTmpl.Execute(w, data); err != nil {
		h.log.Printf("webvpn: rendering certificate warning: %v", err)
	}
}

// isNavigation reports whether this request is a page load rather than a
// sub-resource fetch.
func isNavigation(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" {
		return mode == "navigate"
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// serveTrust records a confirmation and sends the browser back to the page it
// was trying to reach.
func (h *Handler) serveTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && origin != "null" {
		u, err := url.Parse(origin)
		if err != nil || !strings.EqualFold(u.Host, r.Host) {
			http.Error(w, "bad origin", http.StatusForbidden)
			return
		}
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	host := r.PostFormValue("host")
	fp := r.PostFormValue("fingerprint")
	if !h.trust.confirm(host, fp) {
		// Either the gateway never offered this certificate, or the offer has
		// expired. Either way, do not pin it.
		http.Error(w, "该证书确认已失效，请重新访问目标站点", http.StatusForbidden)
		return
	}

	who := "anonymous"
	if h.opts.Identity != nil {
		if email, _, ok := h.opts.Identity.User(r); ok {
			who = email
		}
	}
	h.log.Printf("webvpn: %s trusted certificate %s for %s", who, fp, host)

	http.Redirect(w, r, safeReturn(r.PostFormValue("next"), r.Host), http.StatusSeeOther)
}

// safeReturn keeps the post-confirmation redirect on the gateway. Under the
// subdomain codec the way back is an absolute URL on a proxied host, so those
// are allowed when they share the gateway's registrable suffix.
func safeReturn(next, gatewayHost string) string {
	if next == "" || strings.HasPrefix(next, "//") {
		return "/"
	}
	if strings.HasPrefix(next, "/") {
		return next
	}
	u, err := url.Parse(next)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return "/"
	}
	base := hostOnly(gatewayHost)
	if i := strings.Index(base, "."); i >= 0 {
		base = base[i+1:] // the gateway's own name minus its first label
	}
	host := hostOnly(u.Host)
	if base != "" && (host == base || strings.HasSuffix(host, "."+base)) {
		return next
	}
	return "/"
}
