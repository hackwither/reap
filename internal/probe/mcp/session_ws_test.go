package mcp

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hackwither/reap/internal/probe/common"
)

// writeServerWSFrame writes one unfragmented, unmasked frame — servers must
// NOT mask frames per RFC 6455, unlike the client-side writeFrame in
// session_ws.go.
func writeServerWSFrame(conn net.Conn, opcode byte, payload []byte) error {
	var header []byte
	header = append(header, 0x80|opcode)
	n := len(payload)
	switch {
	case n < 126:
		header = append(header, byte(n))
	case n <= 0xFFFF:
		header = append(header, 126)
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(n))
		header = append(header, lenBuf...)
	default:
		header = append(header, 127)
		lenBuf := make([]byte, 8)
		binary.BigEndian.PutUint64(lenBuf, uint64(n))
		header = append(header, lenBuf...)
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

// wsEchoServer completes the upgrade, then for every text frame it
// receives, decodes the JSON-RPC request and writes back a matching
// result frame — enough to exercise session_ws.go's full write/dispatch
// round trip.
func wsEchoServer(t *testing.T) *httptest.Server {
	t.Helper()
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
		accept := common.ExpectedWebSocketAccept(key)
		buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n")
		buf.Flush()

		reader := bufio.NewReader(buf)
		for {
			fin, opcode, payload, err := readWSFrame(reader)
			if err != nil {
				return
			}
			if !fin || opcode != wsOpText {
				continue
			}
			var req struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			if json.Unmarshal(payload, &req) != nil {
				continue
			}
			resp, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{"echo": req.Method},
			})
			if err := writeServerWSFrame(conn, wsOpText, resp); err != nil {
				return
			}
		}
	}))
}

func TestWSSession_RoundTrip(t *testing.T) {
	srv := wsEchoServer(t)
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]

	sess, err := NewWSSession(wsURL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewWSSession failed: %v", err)
	}
	defer sess.conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw, err := sess.Do(ctx, "tools/list", map[string]any{})
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	var envelope struct {
		Result struct {
			Echo string `json:"echo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		t.Fatalf("failed to decode response: %v; body=%s", err, raw.Body)
	}
	if envelope.Result.Echo != "tools/list" {
		t.Fatalf("expected echoed method 'tools/list', got %q", envelope.Result.Echo)
	}
}

func TestWSSession_MultipleSequentialRequests(t *testing.T) {
	srv := wsEchoServer(t)
	defer srv.Close()
	wsURL := "ws" + srv.URL[len("http"):]

	sess, err := NewWSSession(wsURL, "", 5*time.Second)
	if err != nil {
		t.Fatalf("NewWSSession failed: %v", err)
	}
	defer sess.conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, method := range []string{"initialize", "tools/list", "resources/list"} {
		raw, err := sess.Do(ctx, method, map[string]any{})
		if err != nil {
			t.Fatalf("Do(%s) failed: %v", method, err)
		}
		var envelope struct {
			Result struct {
				Echo string `json:"echo"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw.Body, &envelope); err != nil || envelope.Result.Echo != method {
			t.Fatalf("Do(%s): expected echoed method, got body=%s err=%v", method, raw.Body, err)
		}
	}
}
