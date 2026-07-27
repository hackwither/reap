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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hackwither/reap/internal/probe"
)

const mcpProtocolVersion = "2025-06-18" // most recent MCP spec version at write time; server may negotiate down

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// Session is the MCP-specific implementation of probe.Session.
type Session struct {
	url        string
	httpClient *http.Client
	authHeader string // e.g. "Bearer xyz", set via --auth-header; empty if none supplied
	sessionID  string // captured from Mcp-Session-Id response header, if the server issues one
	reqID      int
}

func NewSession(url, authHeader string, timeout time.Duration) *Session {
	return &Session{
		url:        url,
		authHeader: authHeader,
		httpClient: &http.Client{Timeout: timeout},
	}
}

func (s *Session) TargetURL() string { return s.url }

func (s *Session) Do(ctx context.Context, method string, params any, opts ...probe.ReqOption) (*probe.RawResult, error) {
	o := &probe.ReqOpts{}
	for _, opt := range opts {
		opt(o)
	}

	s.reqID++
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: s.reqID, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if s.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", s.sessionID)
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
	resp, err := s.httpClient.Do(req)
	latency := time.Since(start)
	if err != nil {
		return &probe.RawResult{Latency: latency, Err: err}, err
	}
	defer resp.Body.Close()

	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" {
		s.sessionID = sid
	}

	limited := io.LimitReader(resp.Body, 4<<20) // 4MB cap — recon, not a download tool
	respBody, err := io.ReadAll(limited)
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
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)
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

// Initialize performs the MCP handshake and returns the decoded server info.
// This is called once by the CLI before probes run, so every probe can rely
// on the session already being negotiated (or know clearly that it failed).
func (s *Session) Initialize(ctx context.Context) (*InitializeResult, *probe.RawResult, error) {
	params := map[string]any{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "reap",
			"version": "0.1.0",
		},
	}
	raw, err := s.Do(ctx, "initialize", params)
	if err != nil {
		return nil, raw, err
	}
	var envelope struct {
		Result InitializeResult `json:"result"`
		Error  json.RawMessage  `json:"error"` // may be object {"code":…,"message":…} OR plain string
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		return nil, raw, fmt.Errorf("decode initialize response: %w", err)
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return nil, raw, fmt.Errorf("server returned JSON-RPC error: %s", rpcErrorMessage(envelope.Error))
	}
	return &envelope.Result, raw, nil
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
// internal/discovery can reuse the exact JSON-RPC envelope and SSE-normalization
// logic Session already implements, rather than duplicating it, while keeping
// the dependency direction one-way (discovery depends on probe/mcp, not the
// other way around).
func ProbeInitialize(ctx context.Context, url, authHeader string, timeout time.Duration) (*InitializeResult, error) {
	s := NewSession(url, authHeader, timeout)
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
