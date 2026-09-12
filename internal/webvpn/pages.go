package webvpn

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Where the browser is, remembered.
//
// A parameter carrying nothing but the gateway's own origin — what a script
// gets from location.origin — names no target: it stands for the page that
// script was running on. The Referer says exactly which page that was, and is
// the first thing consulted. But a site is free to suppress it, and enterprise
// software often does (Referrer-Policy: no-referrer), leaving a request with no
// clue about where it came from.
//
// So the gateway keeps, per browser, the last two documents it navigated to. A
// sub-resource belongs to the current document; a navigation to a new document
// was started by the one before it. That is enough to attribute a bare gateway
// origin when the browser will not say.

const (
	// pageIdleTTL discards the trail of a browser that has gone quiet.
	pageIdleTTL = 2 * time.Hour
	// maxPages bounds the memory a busy gateway can accumulate.
	maxPages = 20000
)

type pageEntry struct {
	// cur is the document the browser is on, prev the one it came from.
	cur, prev *url.URL
	touched   time.Time
}

// pageMemory holds one trail per browser.
type pageMemory struct {
	mu  sync.Mutex
	m   map[string]*pageEntry
	now func() time.Time
}

func newPageMemory() *pageMemory {
	return &pageMemory{m: map[string]*pageEntry{}, now: time.Now}
}

// record files a request against a browser and returns the page it belongs to:
// the document it is part of, or, for a navigation, the document that started
// it.
func (p *pageMemory) record(key string, target *url.URL, document bool) *url.URL {
	if key == "" || target == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	e, ok := p.m[key]
	if !ok {
		p.sweepLocked(now)
		if len(p.m) >= maxPages {
			return nil
		}
		e = &pageEntry{}
		p.m[key] = e
	}
	e.touched = now

	if !document {
		return e.cur
	}
	u := *target
	e.prev, e.cur = e.cur, &u
	return e.prev
}

func (p *pageMemory) sweepLocked(now time.Time) {
	for k, e := range p.m {
		if now.Sub(e.touched) > pageIdleTTL {
			delete(p.m, k)
		}
	}
}

// isDocumentRequest reports whether a request is the browser navigating to a
// new top-level document, as opposed to a page fetching something for itself.
func isDocumentRequest(r *http.Request) bool {
	if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" {
		// A frame names itself (iframe, frame); its initiator is the page
		// holding it, so only the top-level document counts here.
		return strings.EqualFold(dest, "document")
	}
	// Browsers that predate Sec-Fetch-* are read by what they ask for.
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return false
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html")
}

// browserKey identifies the browser a request came from. A signed-in browser is
// keyed by its session, which is the only strong answer; with sign-in switched
// off there is no session, and the peer with its user agent is enough to tell
// two browsers apart in that mode.
func (h *Handler) browserKey(r *http.Request) string {
	if key := h.sessionKey(r); key != "" {
		return key
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return jarKey("anonymous\x00" + host + "\x00" + r.Header.Get("User-Agent"))
}
