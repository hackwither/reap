// Package discovery answers the question that comes before Enumeration and
// Assessment: "is there an agent here at all, and what is it?"
//
// A Detector is the discovery-time equivalent of probe.Probe: one
// self-contained "does this candidate look like protocol X over transport Y"
// check. It runs before any probe.Session exists — there's nothing to
// negotiate yet, so it gets a raw Candidate, not a Session. Detectors never
// perform enumeration or assessment themselves; they only ever produce a
// Fingerprint (or nothing) for the CLI to hand off to the existing
// Enumeration/Assessment pipeline unchanged.
package discovery

import (
	"context"
	"time"

	"github.com/hackwither/reap/internal/report"
)

type CandidateKind string

const (
	KindURL      CandidateKind = "url"       // fully-formed endpoint URL, protocol unknown
	KindHostPort CandidateKind = "host-port" // bare host/port, path unknown too
	KindStdio    CandidateKind = "stdio"     // manually-specified local launch spec (command+args+env)
)

// Candidate is one thing worth probing for "is an agent here."
type Candidate struct {
	Kind     CandidateKind
	RawInput string // exactly what the user gave us
	URL      string // resolved URL, for KindURL / KindHostPort after path expansion
	Host     string // for KindHostPort
	Port     int    // for KindHostPort
	Command  string // for KindStdio
	Args     []string
	Env      map[string]string
}

// Fingerprint is a positive (or best-effort) identification of an agent
// protocol on a Candidate.
type Fingerprint struct {
	Candidate   Candidate
	Protocol    string // "mcp", "a2a", "openai-assistants", "unknown"
	Transport   string // "http-streamable", "http-sse-legacy", "websocket", "stdio"
	Confidence  string // "high", "medium", "low"
	ServerName  string
	ServerVer   string
	ProtocolVer string
	Evidence    map[string]any
	DetectorID  string // which Detector produced this, for provenance/debugging

	// Request is the single request/response this Fingerprint was matched
	// from, in the same shape a Finding's reproduction uses — a detector
	// firing "high confidence" on a target is exactly the kind of claim
	// someone should be able to re-run themselves, same as any finding.
	Request *report.HTTPExchange
}

// DetectOptions carries the same cross-cutting knobs probe.Probe already has
// (timeout, auth header) so Detectors don't need their own parallel config
// surface.
type DetectOptions struct {
	Timeout    time.Duration
	AuthHeader string
}

// Detector is one self-contained "does this candidate look like protocol X
// over transport Y" check. Returning (nil, nil) means "ran fine, found
// nothing" — an error means the check itself couldn't run (network error,
// etc.), not that it found something negative.
type Detector interface {
	ID() string
	Kinds() []CandidateKind
	Detect(ctx context.Context, c Candidate, opts DetectOptions) (*Fingerprint, error)
}

// Registry mirrors probe.Registry deliberately — same mental model,
// different stage of the pipeline.
type Registry struct {
	detectors []Detector
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(d Detector) {
	r.detectors = append(r.detectors, d)
}

func (r *Registry) All() []Detector {
	return r.detectors
}

// ForKind returns detectors that apply to the given candidate kind.
func (r *Registry) ForKind(k CandidateKind) []Detector {
	var out []Detector
	for _, d := range r.detectors {
		for _, kind := range d.Kinds() {
			if kind == k {
				out = append(out, d)
				break
			}
		}
	}
	return out
}

var confidenceRank = map[string]int{
	"high":   3,
	"medium": 2,
	"low":    1,
}

// Run tries every applicable Detector for c.Kind and returns the
// highest-confidence Fingerprint (nil if none matched). Individual detector
// errors are not surfaced — discovery is a best-effort sweep across many
// candidates, and one detector failing (e.g. a network timeout) must not
// abort the rest.
func Run(ctx context.Context, reg *Registry, c Candidate, opts DetectOptions) *Fingerprint {
	var best *Fingerprint
	for _, d := range reg.ForKind(c.Kind) {
		fp, err := d.Detect(ctx, c, opts)
		if err != nil || fp == nil {
			continue
		}
		if best == nil || confidenceRank[fp.Confidence] > confidenceRank[best.Confidence] {
			best = fp
		}
	}
	return best
}
