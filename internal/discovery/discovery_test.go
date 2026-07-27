package discovery

import (
	"context"
	"testing"
)

// fakeDetector is a test double implementing Detector.
type fakeDetector struct {
	id         string
	kinds      []CandidateKind
	confidence string // empty means "no match" (Detect returns nil, nil)
	err        error
}

func (f *fakeDetector) ID() string             { return f.id }
func (f *fakeDetector) Kinds() []CandidateKind { return f.kinds }
func (f *fakeDetector) Detect(ctx context.Context, c Candidate, opts DetectOptions) (*Fingerprint, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.confidence == "" {
		return nil, nil
	}
	return &Fingerprint{Candidate: c, Confidence: f.confidence, DetectorID: f.id}, nil
}

func TestRegistry_ForKind_FiltersByKind(t *testing.T) {
	reg := NewRegistry()
	urlOnly := &fakeDetector{id: "url-only", kinds: []CandidateKind{KindURL}, confidence: "high"}
	stdioOnly := &fakeDetector{id: "stdio-only", kinds: []CandidateKind{KindStdio}, confidence: "high"}
	both := &fakeDetector{id: "both", kinds: []CandidateKind{KindURL, KindHostPort}, confidence: "high"}
	reg.Register(urlOnly)
	reg.Register(stdioOnly)
	reg.Register(both)

	if got := reg.ForKind(KindURL); len(got) != 2 {
		t.Fatalf("expected 2 detectors for KindURL, got %d", len(got))
	}
	if got := reg.ForKind(KindStdio); len(got) != 1 || got[0].ID() != "stdio-only" {
		t.Fatalf("expected exactly stdio-only for KindStdio, got %v", got)
	}
	if got := reg.ForKind(KindHostPort); len(got) != 1 || got[0].ID() != "both" {
		t.Fatalf("expected exactly 'both' for KindHostPort, got %v", got)
	}
	if len(reg.All()) != 3 {
		t.Fatalf("expected All() to return 3 detectors, got %d", len(reg.All()))
	}
}

func TestRun_PicksHighestConfidence(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeDetector{id: "low-conf", kinds: []CandidateKind{KindURL}, confidence: "low"})
	reg.Register(&fakeDetector{id: "high-conf", kinds: []CandidateKind{KindURL}, confidence: "high"})
	reg.Register(&fakeDetector{id: "medium-conf", kinds: []CandidateKind{KindURL}, confidence: "medium"})

	fp := Run(context.Background(), reg, Candidate{Kind: KindURL}, DetectOptions{})
	if fp == nil {
		t.Fatal("expected a fingerprint, got nil")
	}
	if fp.DetectorID != "high-conf" {
		t.Fatalf("expected highest-confidence detector to win, got %q", fp.DetectorID)
	}
}

func TestRun_ReturnsNilWhenNothingMatches(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeDetector{id: "no-match", kinds: []CandidateKind{KindURL}})
	reg.Register(&fakeDetector{id: "errors-out", kinds: []CandidateKind{KindURL}, err: context.DeadlineExceeded})

	fp := Run(context.Background(), reg, Candidate{Kind: KindURL}, DetectOptions{})
	if fp != nil {
		t.Fatalf("expected nil fingerprint when no detector matches, got %+v", fp)
	}
}

func TestRun_IgnoresDetectorsForOtherKinds(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeDetector{id: "stdio-only", kinds: []CandidateKind{KindStdio}, confidence: "high"})

	fp := Run(context.Background(), reg, Candidate{Kind: KindURL}, DetectOptions{})
	if fp != nil {
		t.Fatalf("expected nil fingerprint since no registered detector applies to KindURL, got %+v", fp)
	}
}

func TestExpandHostPort(t *testing.T) {
	urls := ExpandHostPort("example.com", 8080, "http")
	if len(urls) != len(MCPWellKnownPaths) {
		t.Fatalf("expected %d urls, got %d", len(MCPWellKnownPaths), len(urls))
	}
	want := "http://example.com:8080/mcp"
	found := false
	for _, u := range urls {
		if u == want {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q among expanded urls, got %v", want, urls)
	}
}
