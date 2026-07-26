// Package probe defines the plugin contract for agentrecon.
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
	"net/http"
	"time"

	"github.com/hackwither/agentrecon/internal/report"
)

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
