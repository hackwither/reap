package probe

import (
	"context"
	"testing"

	"github.com/hackwither/reap/internal/report"
)

type fakeProbe struct {
	id, protocol string
	transports   []string
}

func (f *fakeProbe) ID() string                                                    { return f.id }
func (f *fakeProbe) Protocol() string                                              { return f.protocol }
func (f *fakeProbe) Transports() []string                                          { return f.transports }
func (f *fakeProbe) Run(ctx context.Context, sess Session, r *report.Report) error { return nil }

func TestForProtocolAndTransport_FiltersByTransport(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeProbe{id: "http-only", protocol: "mcp", transports: []string{"http-streamable", "http-sse-legacy"}})
	reg.Register(&fakeProbe{id: "any", protocol: "mcp", transports: []string{"*"}})
	reg.Register(&fakeProbe{id: "websocket-only", protocol: "mcp", transports: []string{"websocket"}})

	got := reg.ForProtocolAndTransport("mcp", "websocket")
	if len(got) != 2 {
		t.Fatalf("expected 2 probes to support websocket (any + websocket-only), got %d: %v", len(got), ids(got))
	}
	if !containsID(got, "any") || !containsID(got, "websocket-only") {
		t.Fatalf("expected any and websocket-only, got %v", ids(got))
	}
}

func TestForProtocolAndTransport_EmptyTransportSkipsFiltering(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&fakeProbe{id: "http-only", protocol: "mcp", transports: []string{"http-streamable"}})
	reg.Register(&fakeProbe{id: "websocket-only", protocol: "mcp", transports: []string{"websocket"}})

	got := reg.ForProtocolAndTransport("mcp", "")
	if len(got) != 2 {
		t.Fatalf("expected empty transport to skip filtering entirely (backward-compat path), got %d: %v", len(got), ids(got))
	}
}

func ids(probes []Probe) []string {
	out := make([]string, len(probes))
	for i, p := range probes {
		out[i] = p.ID()
	}
	return out
}

func containsID(probes []Probe, id string) bool {
	for _, p := range probes {
		if p.ID() == id {
			return true
		}
	}
	return false
}
