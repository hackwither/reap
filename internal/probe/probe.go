// Package probe defines the plugin contract for reap.
//
// A Probe is one self-contained check: "connect, ask one question, record
// what came back." Probes never chain destructive actions and never invoke
// a discovered tool's side-effecting capability — they observe protocol
// and metadata surface only. That constraint is what keeps this a recon
// tool rather than an exploitation framework, and it's enforced by the
// Session type each probe receives (see Session below), not just by
// convention.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hackwither/reap/internal/report"
)

// ErrNotApplicable is the sentinel a Probe returns when it correctly declined
// to run: a TLS check against an http:// target, a session-ID check where the
// server issues no session ID, an MCP check on a target that never
// handshook.
//
// This exists to close reap's worst evidence-integrity gap. Probes used to
// "return nil" both when they found nothing and when they couldn't look,
// which made a silent report indistinguishable from a clean one. A probe must
// now say which it was: nil (ran, nothing found), ErrNotApplicable (declined),
// or a real error (could not complete).
var ErrNotApplicable = errors.New("probe not applicable to this target")

// NotApplicable wraps a reason as an ErrNotApplicable, so the report can
// record why a probe declined rather than just that it did.
func NotApplicable(format string, args ...any) error {
	return &notApplicableError{msg: fmt.Sprintf(format, args...)}
}

type notApplicableError struct{ msg string }

func (e *notApplicableError) Error() string { return e.msg }
func (e *notApplicableError) Is(target error) bool {
	return target == ErrNotApplicable
}

// Session is the sandboxed handle a Probe gets. It deliberately does NOT
// expose a generic "invoke any tool with any args" method — only the
// read-only protocol operations recon needs (handshake, listing,
// metadata). If you're adding a probe that needs more than this, it's
// probably no longer a recon probe.
type Session interface {
	// TargetURL is the endpoint under test.
	TargetURL() string
	// Do performs one raw JSON-RPC (or protocol-equivalent) request/response
	// round trip and returns the decoded payload plus transport metadata
	// (status code, headers, timing) for probes to inspect.
	Do(ctx context.Context, method string, params any, opts ...ReqOption) (*RawResult, error)
}

// RawResult is the raw observation of a single protocol round trip.
type RawResult struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Latency    time.Duration
	Err        error

	// ReqMethod, ReqURL, ReqHeaders, and ReqBody echo the actual outgoing
	// request that produced this result. Each Session implementation
	// captures these at the one place it already builds the real request,
	// so they can never drift from what was actually sent the way a
	// probe's own hand-reconstructed evidence could.
	ReqMethod  string
	ReqURL     string
	ReqHeaders map[string]string
	ReqBody    []byte

	// Setup is the initialize handshake's own RawResult, when this result
	// depended on session state (Mcp-Session-Id, negotiated protocol
	// version) obtained from a prior handshake on the same Session. Nil for
	// a standalone request, including the handshake itself.
	Setup *RawResult
}

// SnapshotHeaders copies an http.Header into a flat map suitable for finding
// evidence — the exact headers actually sent, captured by a Session
// implementation right after it sets them on the real request, rather than
// reconstructed from probe-side assumptions. Multi-value headers collapse to
// their first value; no Session implementation here sets any header twice.
func SnapshotHeaders(h http.Header) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

// Exchange converts this result into a report.HTTPExchange for finding
// evidence, recursively including Setup so a session-dependent finding's
// evidence carries the handshake that established its session alongside
// the call that actually produced the finding. Returns nil if the request
// side was never captured (e.g. a WebSocket transport, which has no
// per-message HTTP request to curl-replay).
func (r *RawResult) Exchange() *report.HTTPExchange {
	if r == nil || r.ReqMethod == "" {
		return nil
	}
	e := &report.HTTPExchange{
		Method:     r.ReqMethod,
		URL:        r.ReqURL,
		Headers:    r.ReqHeaders,
		Body:       string(r.ReqBody),
		StatusCode: r.StatusCode,
		BodySize:   len(r.Body),
		Setup:      r.Setup.Exchange(),
	}
	if r.Headers != nil {
		e.ContentType = r.Headers.Get("Content-Type")
	}
	return e
}

// ReqOption customizes one request (e.g. WithNoAuth to test the
// unauthenticated path explicitly).
type ReqOption func(*ReqOpts)

type ReqOpts struct {
	SkipAuthHeader bool
	ExtraHeaders   map[string]string
}

func WithNoAuth() ReqOption {
	return func(o *ReqOpts) { o.SkipAuthHeader = true }
}

func WithHeader(k, v string) ReqOption {
	return func(o *ReqOpts) {
		if o.ExtraHeaders == nil {
			o.ExtraHeaders = map[string]string{}
		}
		o.ExtraHeaders[k] = v
	}
}

// Probe is the interface every check implements, whether hand-written Go
// or loaded from a JSON template via the generic template-runner Probe.
type Probe interface {
	// ID must be a stable, unique slug (used in --include/--exclude, JSON output).
	ID() string
	// Protocol this probe applies to ("mcp", "a2a", "openai-functions", "*").
	Protocol() string
	// Transports lists which Session transports this probe can run over
	// ("http-streamable", "http-sse-legacy", "websocket", "stdio"), or
	// ["*"] if it only inspects JSON-RPC payload shape and doesn't care
	// which transport carried it (e.g. a tools/list schema check). Probes
	// that depend on HTTP-specific mechanics (headers, TLS, CORS) must
	// list the transports they actually need rather than returning ["*"].
	Transports() []string
	// Run executes the probe and appends zero or more Findings to r.
	// A probe returning an error means the probe itself failed to run
	// (network error, etc.) — not that it "found" anything.
	Run(ctx context.Context, sess Session, r *report.Report) error
}

// Registry holds every probe available to the CLI, built-in or loaded.
type Registry struct {
	probes []Probe
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (reg *Registry) Register(p Probe) {
	reg.probes = append(reg.probes, p)
}

func (reg *Registry) All() []Probe {
	return reg.probes
}

// ForProtocol returns probes that apply to the given protocol, plus any
// protocol-agnostic ("*") probes.
func (reg *Registry) ForProtocol(protocol string) []Probe {
	var out []Probe
	for _, p := range reg.probes {
		if p.Protocol() == protocol || p.Protocol() == "*" {
			out = append(out, p)
		}
	}
	return out
}

// ForProtocolAndTransport is ForProtocol further filtered to probes that
// support the given transport (or declare themselves transport-agnostic
// via "*"). An empty transport means "unknown/not yet resolved" and skips
// transport filtering entirely — the existing static --protocol=mcp path
// doesn't discover a transport up front, so it must keep running every
// protocol-matched probe exactly as it did before this filter existed.
func (reg *Registry) ForProtocolAndTransport(protocol, transport string) []Probe {
	byProtocol := reg.ForProtocol(protocol)
	if transport == "" {
		return byProtocol
	}
	var out []Probe
	for _, p := range byProtocol {
		if supportsTransport(p.Transports(), transport) {
			out = append(out, p)
		}
	}
	return out
}

func supportsTransport(supported []string, transport string) bool {
	for _, t := range supported {
		if t == "*" || t == transport {
			return true
		}
	}
	return false
}
