// session_sse.go implements the legacy pre-2025-03-26 MCP HTTP+SSE
// transport as a probe.Session. Unlike streamable-HTTP (session.go), this
// is not a simple request/response exchange: the client opens one
// long-lived GET SSE connection; the server's first event announces a
// separate POST endpoint for JSON-RPC requests; and per the legacy spec,
// responses to those POSTs are delivered asynchronously as further events
// on the same open GET stream, not necessarily in the POST's own HTTP
// response. SSESession handles both delivery paths in practice: some
// server implementations answer the POST synchronously with the full
// result anyway, so Do() prefers that when it arrives and otherwise waits
// for a matching id to show up over the SSE stream.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hackwither/reap/internal/probe"
)

// SSESession is the legacy-HTTP+SSE implementation of probe.Session.
type SSESession struct {
	sseURL     string
	authHeader string
	httpClient *http.Client

	connOnce sync.Once
	ready    chan struct{}

	mu      sync.Mutex
	postURL string
	connErr error
	reqID   int
	pending map[int]chan *probe.RawResult
}

func NewSSESession(sseURL, authHeader string, timeout time.Duration) *SSESession {
	return &SSESession{
		sseURL:     sseURL,
		authHeader: authHeader,
		// The GET stream is intentionally long-lived — per-request
		// deadlines are enforced via the ctx each Do() call receives, not
		// a client-wide timeout that would kill the SSE connection itself.
		httpClient: &http.Client{},
		ready:      make(chan struct{}),
		pending:    make(map[int]chan *probe.RawResult),
	}
}

func (s *SSESession) TargetURL() string { return s.sseURL }

// connect opens the persistent GET SSE connection on first use and blocks
// until the server's `event: endpoint` announcement arrives (or the
// connection fails). Safe to call from multiple goroutines — only the
// first caller does any work, everyone else just waits on s.ready.
func (s *SSESession) connect(ctx context.Context) error {
	s.connOnce.Do(func() {
		go s.runStream(ctx)
	})
	select {
	case <-s.ready:
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.connErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SSESession) runStream(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.sseURL, nil)
	if err != nil {
		s.failConnect(err)
		return
	}
	req.Header.Set("Accept", "text/event-stream")
	if s.authHeader != "" {
		req.Header.Set("Authorization", s.authHeader)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		s.failConnect(err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.failConnect(fmt.Errorf("SSE endpoint returned status %d", resp.StatusCode))
		return
	}

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4<<20)

	var eventName string
	var dataLines []string
	announced := false

	flush := func() {
		if len(dataLines) == 0 {
			eventName = ""
			return
		}
		data := strings.Join(dataLines, "\n")
		dataLines = nil
		name := eventName
		eventName = ""
		switch name {
		case "endpoint":
			if !announced {
				s.mu.Lock()
				s.postURL = resolveEndpoint(s.sseURL, data)
				s.mu.Unlock()
				announced = true
				close(s.ready)
			}
		default: // "message" or unlabeled — treat as a JSON-RPC response frame
			s.dispatch([]byte(data))
		}
	}

	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "event:"):
			eventName = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		case line == "":
			flush()
		}
	}
	if !announced {
		s.failConnect(fmt.Errorf("SSE stream ended before an 'event: endpoint' announcement"))
	}
}

func (s *SSESession) failConnect(err error) {
	s.mu.Lock()
	if s.connErr == nil {
		s.connErr = err
	}
	s.mu.Unlock()
	select {
	case <-s.ready:
	default:
		close(s.ready)
	}
}

// dispatch routes one decoded SSE data frame to whichever pending Do() call
// is waiting on its JSON-RPC id, if any. A frame with no matching pending
// request (e.g. a server-initiated notification) is silently dropped —
// this session only speaks the request/response subset of JSON-RPC, same
// restriction as the streamable-HTTP session.
func (s *SSESession) dispatch(data []byte) {
	var envelope struct {
		ID *int `json:"id"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.ID == nil {
		return
	}
	s.mu.Lock()
	ch, ok := s.pending[*envelope.ID]
	if ok {
		delete(s.pending, *envelope.ID)
	}
	s.mu.Unlock()
	if ok {
		ch <- &probe.RawResult{StatusCode: 200, Body: data}
	}
}

func resolveEndpoint(sseURL, announced string) string {
	base, err := url.Parse(sseURL)
	if err != nil {
		return announced
	}
	ref, err := url.Parse(announced)
	if err != nil {
		return announced
	}
	return base.ResolveReference(ref).String()
}

func (s *SSESession) Do(ctx context.Context, method string, params any, opts ...probe.ReqOption) (*probe.RawResult, error) {
	o := &probe.ReqOpts{}
	for _, opt := range opts {
		opt(o)
	}

	if err := s.connect(ctx); err != nil {
		return nil, fmt.Errorf("connect SSE stream: %w", err)
	}

	s.mu.Lock()
	s.reqID++
	id := s.reqID
	postURL := s.postURL
	respCh := make(chan *probe.RawResult, 1)
	s.pending[id] = respCh
	s.mu.Unlock()

	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return nil, fmt.Errorf("encode request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, postURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
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
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return &probe.RawResult{Latency: latency, Err: err}, err
	}
	defer resp.Body.Close()
	postBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	// Prefer a synchronous POST response body if the server sent one and
	// it's a JSON-RPC envelope carrying an id — some legacy implementations
	// answer directly rather than round-tripping through the SSE stream.
	var idEnvelope struct {
		ID *int `json:"id"`
	}
	if len(postBody) > 0 && json.Unmarshal(postBody, &idEnvelope) == nil && idEnvelope.ID != nil {
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return &probe.RawResult{StatusCode: resp.StatusCode, Headers: resp.Header, Body: postBody, Latency: latency}, nil
	}

	select {
	case raw := <-respCh:
		raw.Latency = latency
		return raw, nil
	case <-ctx.Done():
		s.mu.Lock()
		delete(s.pending, id)
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}
