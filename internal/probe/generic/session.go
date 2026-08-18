// Package generic provides a probe.Session for targets whose protocol reap
// can identify but does not yet enumerate.
//
// Before this existed, cli.Run built an mcp.Session for every target no matter
// what discovery said. Identifying an A2A agent card or an OpenAPI service
// therefore produced a fingerprint and then a failed MCP handshake, so the
// report carried no posture information at all — which is a strange outcome
// for a tool whose transport checks never needed the protocol in the first
// place.
//
// With this session, a non-MCP target still gets the full protocol-neutral
// check set (TLS, plaintext, downgrade, CORS, rate-limit headers) plus its
// identification. It is also the smallest honest step toward the per-protocol
// session factory docs/ARCHITECTURE.md describes: cli.go now selects a session
// implementation instead of hardcoding one.
package generic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hackwither/reap/internal/httpx"
	"github.com/hackwither/reap/internal/probe"
)

const maxResponseBytes = 4 << 20

// Session performs plain HTTP reads against a target. It satisfies
// probe.Session without pretending to speak any RPC protocol.
type Session struct {
	url        string
	client     *httpx.Client
	authHeader string
}

func NewSession(url, authHeader string, client *httpx.Client) *Session {
	return &Session{url: url, authHeader: authHeader, client: client}
}

func (s *Session) TargetURL() string { return s.url }

// Do performs one HTTP request.
//
// The method argument is interpreted as an HTTP verb ("GET", "POST", …)
// rather than an RPC method name; an empty method means GET. When params is
// non-nil the request is sent as a JSON body. This is enough for the
// protocol-neutral probes, which only ever need headers and status codes.
func (s *Session) Do(ctx context.Context, method string, params any, opts ...probe.ReqOption) (*probe.RawResult, error) {
	o := &probe.ReqOpts{}
	for _, opt := range opts {
		opt(o)
	}

	verb := strings.ToUpper(strings.TrimSpace(method))
	if verb == "" {
		verb = http.MethodGet
	}

	var body io.Reader
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("encode request body: %w", err)
		}
		body = bytes.NewReader(encoded)
		if verb == http.MethodGet {
			verb = http.MethodPost
		}
	}

	req, err := http.NewRequestWithContext(ctx, verb, s.url, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json, */*")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
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
	return &probe.RawResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Latency:    latency,
	}, nil
}
