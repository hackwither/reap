package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func wsUpgradeServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		accept := expectedWebSocketAccept(key)
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
		buf.Flush()
	}))
}

func TestWebSocketDetector_MatchesConformantUpgrade(t *testing.T) {
	srv := wsUpgradeServer()
	defer srv.Close()

	det := &mcpWebSocketDetector{}
	fp, err := det.Detect(context.Background(), Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp == nil {
		t.Fatal("expected a fingerprint match against a conformant WS upgrade, got nil")
	}
	if fp.Confidence != "medium" {
		t.Fatalf("expected confidence capped at medium (non-standard transport), got %q", fp.Confidence)
	}
	if fp.Transport != "websocket" {
		t.Fatalf("expected transport 'websocket', got %q", fp.Transport)
	}
}

// TestWebSocketDetector_NoFalsePositiveOnPlainHTTP is the false-positive
// discipline check: a server that never upgrades at all must not match.
func TestWebSocketDetector_NoFalsePositiveOnPlainHTTP(t *testing.T) {
	srv := mockInitializeServer()
	defer srv.Close()

	det := &mcpWebSocketDetector{}
	fp, err := det.Detect(context.Background(), Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != nil {
		t.Fatalf("expected no match against a plain (non-upgrading) HTTP server, got %+v", fp)
	}
}

// TestWebSocketDetector_RejectsForgedAccept confirms the detector actually
// verifies Sec-WebSocket-Accept per RFC 6455, rather than trusting a bare
// "101 Switching Protocols" status line — a server claiming to upgrade
// without computing the real handshake must not be mistaken for one that did.
func TestWebSocketDetector_RejectsForgedAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bm90LXRoZS1yZWFsLWFjY2VwdA==\r\n\r\n")
		buf.Flush()
	}))
	defer srv.Close()

	det := &mcpWebSocketDetector{}
	fp, err := det.Detect(context.Background(), Candidate{Kind: KindURL, URL: srv.URL}, DetectOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fp != nil {
		t.Fatalf("expected no match when Sec-WebSocket-Accept doesn't match the computed value, got %+v", fp)
	}
}
