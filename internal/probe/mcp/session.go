// Package mcp implements protocol support for the Model Context Protocol
// (streamable-HTTP transport) — handshake, capability/tool enumeration,
// and the read-only checks built on top of them.
//
// This client speaks plain JSON-RPC 2.0 over HTTP using only the Go
// standard library. It intentionally implements just enough of MCP to do
// recon (initialize, tools/list, resources/list, prompts/list) — it is not
// a general-purpose MCP client and never calls tools/call.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/version"
)

// SupportedProtocolVersions is the negotiation ladder, newest first.
//
// reap used to send a single hardcoded version. A server that only speaks an
// older revision answers with an error, the handshake fails, and every
// downstream probe silently reports nothing — so the target reads as clean
// when in fact reap never spoke to it. Walking the ladder is the difference
// between "no findings" meaning something and meaning nothing.
var SupportedProtocolVersions = []string{
	"2025-06-18",
	"2025-03-26",
	"2024-11-05",
}

// maxResponseBytes caps a single response body. Recon, not a download tool.
const maxResponseBytes = 4 << 20

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// rpcNotification is a JSON-RPC message with no id, so the server must not
// reply. Used only for notifications/initialized.
type rpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// Session is the MCP-specific implementation of probe.Session.
type Session struct {
	url        string
	client     *httpx.Client
	authHeader string // e.g. "Bearer xyz", set via --auth-header; empty if none supplied

	mu sync.Mutex
	// sessionID is captured from the Mcp-Session-Id header of the initialize
	// response only. It used to be captured from every response, which let the
	// host-header and rate-limit probes (both of which re-issue initialize)
	// overwrite it mid-scan and make the entropy check order-dependent.
	sessionID string
	// negotiatedVersion is the protocolVersion the server accepted. Sent as
	// the MCP-Protocol-Version header on every subsequent request, which the
	// 2025-06-18 spec requires and strict servers enforce.
	negotiatedVersion string
	initResult        *InitializeResult
	initRaw           *probe.RawResult
	initErr           error
	initDone          bool
	reqID             int
	// cache memoises identical read requests within one scan. Fourteen probes
	// previously issued thirteen requests per scan, nine of them the same
	// tools/list.
	cache map[string]*probe.RawResult
}

func NewSession(url, authHeader string, client *httpx.Client) *Session {
	return &Session{
		url:        url,
		authHeader: authHeader,
		client:     client,
		cache:      map[string]*probe.RawResult{},
	}
}

func (s *Session) TargetURL() string { return s.url }

// SessionID is the Mcp-Session-Id observed during the handshake, if any.
func (s *Session) SessionID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessionID
}

// NegotiatedVersion is the MCP protocol revision the server accepted, empty
// if the handshake never succeeded.
func (s *Session) NegotiatedVersion() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.negotiatedVersion
}

// cacheKey identifies one logical read. Auth and per-request headers are part
// of the key: the unauthenticated tools/list probe and the Origin-bearing CORS
// probe must never be served each other's response.
func cacheKey(method string, params any, o *probe.ReqOpts) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%t\x00", method, o.SkipAuthHeader)
	if params != nil {
		if b, err := json.Marshal(params); err == nil {
			h.Write(b)
		}
	}
	keys := make([]string, 0, len(o.ExtraHeaders))
	for k := range o.ExtraHeaders {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "\x00%s=%s", k, o.ExtraHeaders[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (s *Session) Do(ctx context.Context, method string, params any, opts ...probe.ReqOption) (*probe.RawResult, error) {
	o := &probe.ReqOpts{}
	for _, opt := range opts {
		opt(o)
	}

	key := cacheKey(method, params, o)
	s.mu.Lock()
	cached, ok := s.cache[key]
	s.mu.Unlock()
	if ok {
		return cached, nil
	}

	raw, err := s.do(ctx, method, params, o)
	if err == nil && raw != nil {
		s.mu.Lock()
		s.cache[key] = raw
		s.mu.Unlock()
	}
	return raw, err
}

// do performs one uncached round trip.
func (s *Session) do(ctx context.Context, method string, params any, o *probe.ReqOpts) (*probe.RawResult, error) {
	s.mu.Lock()
	s.reqID++
	id := s.reqID
	sessionID := s.sessionID
	protoVer := s.negotiatedVersion
	s.mu.Unlock()

	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	// Required by MCP 2025-06-18 on every request after initialize. Strict
	// servers (including the reference SDK) reject requests without it.
	if protoVer != "" && method != "initialize" {
		req.Header.Set("MCP-Protocol-Version", protoVer)
	}
	if s.authHeader != "" && !o.SkipAuthHeader {
		req.Header.Set("Authorization", s.authHeader)
	}
	for k, v := range o.ExtraHeaders {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := s.client.HTTP().Do(req)
	latency := time.Since(start)
	if err != nil {
		return &probe.RawResult{Latency: latency, Err: err}, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return &probe.RawResult{StatusCode: resp.StatusCode, Latency: latency, Err: err}, err
	}

	// Streamable-HTTP MCP servers may legally answer a single request with
	// text/event-stream instead of application/json (the spec leaves this
	// to the server). Normalize here so Initialize() and every downstream
	// json_path matcher always see a plain JSON-RPC body, regardless of
	// which content-type the server picked.
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		if data, sseErr := extractSSEData(respBody); sseErr == nil {
			respBody = data
		}
		// If extraction fails, fall through with the raw body — the
		// caller's json.Unmarshal will surface a clear decode error.
	}

	return &probe.RawResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Latency:    latency,
	}, nil
}

// notify sends a JSON-RPC notification (no id, so no reply is expected).
//
// This is deliberately NOT part of probe.Session. Probes get a read-only
// handle; the ability to send an unanswered message to the target belongs to
// the session's own handshake bookkeeping, not to a check. See
// docs/ARCHITECTURE.md — widening the probe-facing interface is how a recon
// tool turns into an agent.
func (s *Session) notify(ctx context.Context, method string, params any) error {
	s.mu.Lock()
	sessionID := s.sessionID
	protoVer := s.negotiatedVersion
	s.mu.Unlock()

	body, err := json.Marshal(rpcNotification{JSONRPC: "2.0", Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("encode notification: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build notification: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	if protoVer != "" {
		req.Header.Set("MCP-Protocol-Version", protoVer)
	}
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}

	resp, err := s.client.HTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

// extractSSEData pulls the JSON-RPC payload out of a text/event-stream
// response body. A single JSON-RPC request/response is expected to arrive
// as one SSE event; per the SSE spec, multi-line "data:" fields within that
// event are joined with "\n" before being treated as the payload. If the
// stream contains multiple events (e.g. a keepalive comment followed by the
// real message), the last complete event's data is returned.
func extractSSEData(body []byte) ([]byte, error) {
	var current []string
	var last []byte

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), maxResponseBytes)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "data:"):
			current = append(current, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "":
			if len(current) > 0 {
				last = []byte(strings.Join(current, "\n"))
				current = nil
			}
		}
		// any other SSE fields (event:, id:, retry:, comments) are framing
		// metadata we don't need for a single request/response exchange.
	}
	if len(current) > 0 { // stream ended without a trailing blank line
		last = []byte(strings.Join(current, "\n"))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan SSE body: %w", err)
	}
	if len(last) == 0 {
		return nil, fmt.Errorf("no data field found in SSE stream")
	}
	return last, nil
}

func initializeParams(protocolVersion string) map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "reap",
			"version": version.Version,
		},
	}
}

// Initialize performs the MCP handshake and returns the decoded server info.
//
// It walks SupportedProtocolVersions until one is accepted, records the
// negotiated version, and then sends the spec-required
// notifications/initialized. The result is memoised: several probes want the
// handshake response, and re-handshaking per probe both wastes requests and
// churns the server's session state.
func (s *Session) Initialize(ctx context.Context) (*InitializeResult, *probe.RawResult, error) {
	s.mu.Lock()
	if s.initDone {
		res, raw, err := s.initResult, s.initRaw, s.initErr
		s.mu.Unlock()
		return res, raw, err
	}
	s.mu.Unlock()

	res, raw, err := s.handshake(ctx)

	s.mu.Lock()
	s.initDone = true
	s.initResult, s.initRaw, s.initErr = res, raw, err
	s.mu.Unlock()

	if err == nil {
		// Best effort: a server that doesn't care won't mind, and one that
		// does will reject everything downstream without it.
		_ = s.notify(ctx, "notifications/initialized", nil)
	}
	return res, raw, err
}

// handshake tries each supported protocol version in order.
func (s *Session) handshake(ctx context.Context) (*InitializeResult, *probe.RawResult, error) {
	res, raw, accepted, err := negotiateInitialize(ctx, s)
	if err != nil {
		return nil, raw, err
	}
	s.mu.Lock()
	s.negotiatedVersion = accepted
	if raw != nil && raw.Headers != nil {
		if sid := raw.Headers.Get("Mcp-Session-Id"); sid != "" {
			s.sessionID = sid
		}
	}
	s.mu.Unlock()
	return res, raw, nil
}

// InitializeSession performs the MCP handshake against any probe.Session
// implementation — streamable-HTTP, legacy-SSE, WebSocket, or any future
// transport. Every transport speaks the same JSON-RPC "initialize" method
// once a Session exists, so the handshake logic itself doesn't need to be
// transport-specific; only Session.Do's wire format differs underneath.
func InitializeSession(ctx context.Context, sess probe.Session) (*InitializeResult, *probe.RawResult, error) {
	// A streamable-HTTP Session must go through its own Initialize: that is
	// where the negotiated protocol version, the Mcp-Session-Id, and the
	// spec-required notifications/initialized are recorded and sent. Calling
	// negotiateInitialize directly here would complete a handshake the session
	// itself knows nothing about, so every later request would omit the
	// MCP-Protocol-Version header and a strict server would reject it.
	if ms, ok := sess.(*Session); ok {
		return ms.Initialize(ctx)
	}
	res, raw, _, err := negotiateInitialize(ctx, sess)
	return res, raw, err
}

// negotiateInitialize walks SupportedProtocolVersions against sess and returns
// the first accepted handshake along with the version that was accepted.
//
// Two independent things are going on here, and both are load-bearing:
//
//   - The ladder. A server speaking only an older revision answers a
//     single hardcoded protocolVersion with an error. Without the retry, the
//     handshake fails, every probe below silently reports nothing, and the
//     target reads as clean when reap never actually spoke to it.
//   - The validation. A response is only a handshake if it looks like one. A
//     401 body from some unrelated API, or a 200 whose JSON has neither
//     "result" nor "error", used to decode into an empty-but-error-free
//     envelope and get reported as a confirmed MCP server with empty
//     serverInfo.
func negotiateInitialize(ctx context.Context, sess probe.Session) (*InitializeResult, *probe.RawResult, string, error) {
	var lastRaw *probe.RawResult
	var lastErr error

	for _, ver := range SupportedProtocolVersions {
		raw, err := sess.Do(ctx, "initialize", initializeParams(ver))
		if err != nil {
			// Transport failure: the ladder can't help, and retrying every
			// rung would multiply the wait on an unreachable host.
			return nil, raw, "", err
		}
		lastRaw = raw

		var envelope struct {
			Result InitializeResult `json:"result"`
			Error  json.RawMessage  `json:"error"` // may be object {"code":…,"message":…} OR plain string
		}
		decodeErr := json.Unmarshal(raw.Body, &envelope)

		if decodeErr == nil && len(envelope.Error) > 0 && string(envelope.Error) != "null" {
			msg := rpcErrorMessage(envelope.Error)
			lastErr = fmt.Errorf("server returned JSON-RPC error: %s", msg)
			if isVersionRejection(raw.StatusCode, msg) {
				continue // try the next rung
			}
			return nil, raw, "", lastErr
		}

		// A non-200 must never count as a successful handshake, even when the
		// error body happens to be valid JSON.
		if raw.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("server returned HTTP %d for initialize (expected 200)", raw.StatusCode)
			if isVersionRejection(raw.StatusCode, string(raw.Body)) {
				continue
			}
			return nil, raw, "", lastErr
		}
		if decodeErr != nil {
			return nil, raw, "", fmt.Errorf("decode initialize response: %w", decodeErr)
		}
		// A 200 with neither field is the same false-match risk as the 401
		// case above: require the result to actually look like an MCP
		// initialize result, not merely "not an error".
		if envelope.Result.ProtocolVersion == "" && envelope.Result.ServerInfo.Name == "" {
			return nil, raw, "", fmt.Errorf("initialize response included neither protocolVersion nor serverInfo.name — doesn't look like a real MCP handshake result")
		}

		accepted := envelope.Result.ProtocolVersion
		if accepted == "" {
			accepted = ver
		}
		result := envelope.Result
		return &result, raw, accepted, nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no supported MCP protocol version was accepted")
	}
	return nil, lastRaw, "", lastErr
}

// isVersionRejection reports whether a failed initialize looks like "I don't
// speak that revision" rather than a substantive refusal (auth, not found).
// Servers phrase this inconsistently, so this matches on the shape of the
// complaint rather than an exact string.
func isVersionRejection(status int, message string) bool {
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return false
	}
	m := strings.ToLower(message)
	if !strings.Contains(m, "version") {
		return false
	}
	for _, hint := range []string{"unsupported", "not supported", "unknown", "invalid", "protocolversion", "protocol version", "must be one of", "expected"} {
		if strings.Contains(m, hint) {
			return true
		}
	}
	return false
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rpcErrorMessage extracts a human-readable message from a JSON-RPC error
// field that may be either a {"code":…,"message":…} object or a plain string.
func rpcErrorMessage(raw json.RawMessage) string {
	var obj rpcError
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Message != "" {
		return obj.Message
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// ProbeInitialize performs a standalone MCP initialize handshake against url,
// without requiring a caller to construct and hold a Session. This exists so
// internal/discovery can reuse the exact JSON-RPC envelope, version ladder
// and SSE-normalization logic Session already implements, rather than
// duplicating it, while keeping the dependency direction one-way (discovery
// depends on probe/mcp, not the other way around).
func ProbeInitialize(ctx context.Context, url, authHeader string, client *httpx.Client) (*InitializeResult, error) {
	s := NewSession(url, authHeader, client)
	init, _, err := s.Initialize(ctx)
	return init, err
}

type InitializeResult struct {
	ProtocolVersion string `json:"protocolVersion"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
	Capabilities map[string]any `json:"capabilities"`
	Instructions string         `json:"instructions,omitempty"`
}
