package mcp

import (
	"context"
	"net/http"
	"testing"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/report"
)

func TestServerHeaderFingerprintProbe_SuppressesPureEdgeServer(t *testing.T) {
	sess := newFakeSession(map[string]*probe.RawResult{
		"tools/list": {
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Server": []string{"cloudflare"}},
		},
	})
	r := &report.Report{}
	if err := (&serverHeaderFingerprintProbe{}).Run(context.Background(), sess, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected no finding for a pure-Cloudflare Server header (already shown in the Edge line), got %+v", r.Findings)
	}
}

func TestServerHeaderFingerprintProbe_FiresOnOriginAppServer(t *testing.T) {
	sess := newFakeSession(map[string]*probe.RawResult{
		"tools/list": {
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Server": []string{"Werkzeug/2.0.1 Python/3.9"}},
		},
	})
	r := &report.Report{}
	if err := (&serverHeaderFingerprintProbe{}).Run(context.Background(), sess, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding for an origin-app Server header, got %d: %+v", len(r.Findings), r.Findings)
	}
}

func TestServerHeaderFingerprintProbe_XPoweredByAlwaysFires(t *testing.T) {
	sess := newFakeSession(map[string]*probe.RawResult{
		"tools/list": {
			StatusCode: http.StatusOK,
			Headers:    http.Header{"Server": []string{"cloudflare"}, "X-Powered-By": []string{"Express"}},
		},
	})
	r := &report.Report{}
	if err := (&serverHeaderFingerprintProbe{}).Run(context.Background(), sess, r); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding driven by X-Powered-By even with an edge Server header, got %d: %+v", len(r.Findings), r.Findings)
	}
}
