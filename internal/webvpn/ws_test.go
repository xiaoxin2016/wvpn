package webvpn

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// wsSeen is what a WebSocket origin observed about a handshake.
type wsSeen struct {
	mu                    sync.Mutex
	proto, origin, cookie string
	pageProto             string
}

func (s *wsSeen) get() wsSeen {
	s.mu.Lock()
	defer s.mu.Unlock()
	return wsSeen{proto: s.proto, origin: s.origin, cookie: s.cookie, pageProto: s.pageProto}
}

// wsOrigin answers "/" with a page and "/ws" with a WebSocket that echoes one
// text frame, recording what each request carried.
func wsOrigin(seen *wsSeen) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.pageProto = r.Proto
		seen.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "page")
	})
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		seen.mu.Lock()
		seen.proto, seen.origin, seen.cookie = r.Proto, r.Header.Get("Origin"), r.Header.Get("Cookie")
		seen.mu.Unlock()
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			http.Error(w, "not a websocket handshake", http.StatusBadRequest)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(sum[:]))
		rw.Flush()
		// One masked client text frame of under 126 bytes, echoed back.
		head := make([]byte, 2)
		if _, err := io.ReadFull(rw, head); err != nil {
			return
		}
		mask := make([]byte, 4)
		io.ReadFull(rw, mask)
		payload := make([]byte, head[1]&0x7f)
		io.ReadFull(rw, payload)
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		reply := "echo:" + string(payload)
		conn.Write(append([]byte{0x81, byte(len(reply))}, reply...))
	})
	return mux
}

// wsRoundTrip opens a WebSocket through the gateway the way a browser does,
// sends "ping", and returns the status of the handshake and the reply.
func wsRoundTrip(t *testing.T, gw *httptest.Server, path string, headers map[string]string) (int, string) {
	t.Helper()
	u, _ := url.Parse(gw.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var req strings.Builder
	fmt.Fprintf(&req, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n", path, u.Host)
	for k, v := range headers {
		fmt.Fprintf(&req, "%s: %s\r\n", k, v)
	}
	req.WriteString("\r\n")
	io.WriteString(conn, req.String())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("reading the handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("handshake answered %d: %s", resp.StatusCode, body)
		return resp.StatusCode, ""
	}
	mask := []byte{1, 2, 3, 4}
	frame := []byte{0x81, 0x80 | 4}
	frame = append(frame, mask...)
	for i, c := range []byte("ping") {
		frame = append(frame, c^mask[i%4])
	}
	conn.Write(frame)
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		t.Fatalf("reading the echo: %v", err)
	}
	payload := make([]byte, head[1]&0x7f)
	io.ReadFull(br, payload)
	return resp.StatusCode, string(payload)
}

// A WebSocket reaches a plain-HTTP site as the site: with the site's own
// Origin, the site's cookies, and nothing of the gateway's.
func TestWebSocketThroughTheGateway(t *testing.T) {
	var seen wsSeen
	origin := httptest.NewServer(wsOrigin(&seen))
	t.Cleanup(origin.Close)
	host := originHost(t, origin)
	gw, _ := gatewayFor(t, Options{SessionCookie: "wvsid"})

	for _, path := range []string{"/p/http/" + host + "/ws", "/p/ws/" + host + "/ws"} {
		status, reply := wsRoundTrip(t, gw, path, map[string]string{
			"Origin": gw.URL,
			"Cookie": "wvsid=session; " + CookiePrefix + "JSESSIONID=abc",
		})
		if status != http.StatusSwitchingProtocols || reply != "echo:ping" {
			t.Fatalf("%s: status %d, reply %q", path, status, reply)
		}
		got := seen.get()
		// A ws:// address names the same site; the Origin a browser would have
		// sent there is http://, never ws://.
		if got.origin != "http://"+host {
			t.Errorf("%s: site saw Origin %q, want http://%s", path, got.origin, host)
		}
		if got.cookie != "JSESSIONID=abc" {
			t.Errorf("%s: site saw Cookie %q, want only its own", path, got.cookie)
		}
	}
}

// An HTTPS site that speaks HTTP/2 — nginx with "listen 443 ssl http2" — still
// gets its WebSocket handshakes over HTTP/1.1, where Upgrade exists, even after
// the page itself was fetched over a pooled HTTP/2 connection.
func TestWebSocketToAnHTTP2Site(t *testing.T) {
	var seen wsSeen
	origin := httptest.NewUnstartedServer(wsOrigin(&seen))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	t.Cleanup(origin.Close)
	host := originHost(t, origin)
	gw, client := gatewayFor(t, Options{InsecureTLS: true})

	// The page first, which leaves an HTTP/2 connection in the pool.
	if resp, _ := get(t, client, gw.URL+"/p/https/"+host+"/", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	if got := seen.get().pageProto; got != "HTTP/2.0" {
		t.Fatalf("the page went over %s; the test needs the site to have negotiated HTTP/2", got)
	}

	status, reply := wsRoundTrip(t, gw, "/p/https/"+host+"/ws", map[string]string{"Origin": gw.URL})
	if status != http.StatusSwitchingProtocols || reply != "echo:ping" {
		t.Fatalf("status %d, reply %q", status, reply)
	}
	if got := seen.get(); got.proto != "HTTP/1.1" || got.origin != "https://"+host {
		t.Errorf("site saw the handshake as %s with Origin %q", got.proto, got.origin)
	}

	// And ordinary requests keep their HTTP/2.
	if resp, _ := get(t, client, gw.URL+"/p/https/"+host+"/", nil); resp.StatusCode != http.StatusOK || seen.get().pageProto != "HTTP/2.0" {
		t.Errorf("the page no longer goes over HTTP/2: %s", seen.get().pageProto)
	}
}
