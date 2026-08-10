package cli

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hackwither/reap/internal/probe/common"
	"github.com/hackwither/reap/internal/probe/mcp"
)

// TestNewSessionForTransport_DispatchesByTransport is the integration point
// for M3/M4 transport generalization: given a resolved transport string
// (from discovery, or the "http-streamable" default for the static
// --protocol=mcp path), the CLI must construct the matching concrete
// probe.Session implementation.
func TestNewSessionForTransport_DispatchesByTransport(t *testing.T) {
	// "http-streamable", empty, and anything unrecognized all fall through
	// to the original streamable-HTTP session — this is the backward-compat
	// guarantee: existing --protocol=mcp invocations must behave exactly as
	// they did before transport resolution existed.
	for _, transport := range []string{"http-streamable", "", "some-future-transport"} {
		sess, err := newSessionForTransport("http://example.invalid/mcp", transport, "", time.Second)
		if err != nil {
			t.Fatalf("transport %q: unexpected error: %v", transport, err)
		}
		if _, ok := sess.(*mcp.Session); !ok {
			t.Fatalf("transport %q: expected *mcp.Session, got %T", transport, sess)
		}
	}

	sess, err := newSessionForTransport("http://example.invalid/sse", "http-sse-legacy", "", time.Second)
	if err != nil {
		t.Fatalf("http-sse-legacy: unexpected error: %v", err)
	}
	if _, ok := sess.(*mcp.SSESession); !ok {
		t.Fatalf("http-sse-legacy: expected *mcp.SSESession, got %T", sess)
	}
}

// TestNewSessionForTransport_WebSocketDialsImmediately confirms the
// websocket branch actually completes a real upgrade handshake (unlike the
// other transports, NewWSSession dials eagerly and can fail at
// construction time) and returns the WebSocket-specific session type.
func TestNewSessionForTransport_WebSocketDialsImmediately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Sec-WebSocket-Key")
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		accept := common.ExpectedWebSocketAccept(key)
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
		buf.Flush()
		<-r.Context().Done()
	}))
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]

	sess, err := newSessionForTransport(wsURL, "websocket", "", 5*time.Second)
	if err != nil {
		t.Fatalf("websocket: unexpected error: %v", err)
	}
	if _, ok := sess.(*mcp.WSSession); !ok {
		t.Fatalf("websocket: expected *mcp.WSSession, got %T", sess)
	}
}

// TestNewSessionForTransport_WebSocketErrorPropagates ensures a failed
// handshake surfaces as an error rather than a nil/zero session — the CLI
// depends on this to report an accurate ConfirmReason.
func TestNewSessionForTransport_WebSocketErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK) // never upgrades
	}))
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]

	_, err := newSessionForTransport(wsURL, "websocket", "", 5*time.Second)
	if err == nil {
		t.Fatal("expected an error when the server never completes the WebSocket upgrade")
	}
}
