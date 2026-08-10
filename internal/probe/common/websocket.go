package common

import (
	"bufio"
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

// DialWebSocket performs a raw RFC 6455 WebSocket upgrade handshake over
// TCP/TLS using only the standard library, and returns the still-open
// connection plus the HTTP upgrade response. Callers that only need to
// confirm the handshake (discovery) can inspect the response and close the
// connection; callers that need a working session (probe.Session) keep
// using the returned net.Conn to frame further messages. extraHeaders (e.g.
// Authorization) are sent with the upgrade request itself — a WebSocket
// connection has no per-message header concept, so this is the only place
// auth can be attached.
func DialWebSocket(dialer *net.Dialer, targetURL string, extraHeaders map[string]string) (net.Conn, *http.Response, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse target URL: %w", err)
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

	var conn net.Conn
	if tlsMode {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, nil, err
	}

	key, err := generateWebSocketKey()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	for k, v := range extraHeaders {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		conn.Close()
		return nil, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	if resp.StatusCode != http.StatusSwitchingProtocols ||
		!strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") ||
		resp.Header.Get("Sec-WebSocket-Accept") != ExpectedWebSocketAccept(key) {
		conn.Close()
		return nil, resp, fmt.Errorf("server did not complete a conformant WebSocket upgrade")
	}

	return conn, resp, nil
}

func generateWebSocketKey() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf), nil
}

// ExpectedWebSocketAccept computes the Sec-WebSocket-Accept value a
// conformant server must return for the given client-generated key.
func ExpectedWebSocketAccept(key string) string {
	h := sha1.New()
	h.Write([]byte(key + websocketMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
