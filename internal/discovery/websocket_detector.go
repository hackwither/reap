package discovery

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// websocketMagicGUID is the fixed RFC 6455 constant every conforming
// WebSocket server must append to the client's Sec-WebSocket-Key before
// hashing, to prove it actually understood the upgrade request rather than
// coincidentally answering 101 for an unrelated reason.
const websocketMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// mcpWebSocketDetector confirms a raw WebSocket upgrade handshake succeeds.
// This is not part of the official MCP spec — some community gateways/proxies
// speak JSON-RPC over a plain WebSocket anyway, so it's worth detecting, but
// it's flagged non-standard and capped at medium confidence.
//
// A socket upgrade handshake has no meaningful mapping onto "one HTTP
// request + matchers over the response" the way fingerprints/*.json
// expresses other detectors, so this stays hand-written Go rather than
// becoming a fingerprint. It only confirms the upgrade itself; a full
// JSON-RPC round trip over the resulting connection is session_ws.go's job
// (a later milestone), not discovery's.
type mcpWebSocketDetector struct{}

func (d *mcpWebSocketDetector) ID() string { return "mcp-websocket" }

func (d *mcpWebSocketDetector) Kinds() []CandidateKind {
	return []CandidateKind{KindURL, KindHostPort}
}

func (d *mcpWebSocketDetector) Detect(ctx context.Context, c Candidate, opts DetectOptions) (*Fingerprint, error) {
	if c.URL == "" {
		return nil, nil
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return nil, nil
	}

	tlsMode := u.Scheme == "https" || u.Scheme == "wss"
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if tlsMode {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: opts.Timeout}
	var conn net.Conn
	if tlsMode {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, nil // unreachable candidate is not a Detector failure
	}
	defer conn.Close()

	key, err := generateWebSocketKey()
	if err != nil {
		return nil, nil
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n",
		path, u.Host, key,
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		return nil, nil
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, nil
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		return nil, nil
	}
	if resp.Header.Get("Sec-WebSocket-Accept") != expectedWebSocketAccept(key) {
		return nil, nil // claims 101 but didn't actually compute the handshake — reject rather than trust it
	}

	return &Fingerprint{
		Candidate:  c,
		Protocol:   "mcp",
		Transport:  "websocket",
		Confidence: "medium", // capped: non-standard transport, upgrade-only confirmation, no JSON-RPC round trip yet
		Evidence: map[string]any{
			"upgrade_confirmed": true,
			"note":              "WebSocket is not part of the official MCP spec; this only confirms a conformant upgrade handshake, not an MCP JSON-RPC round trip",
		},
		DetectorID: d.ID(),
	}, nil
}

func generateWebSocketKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

func expectedWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + websocketMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
