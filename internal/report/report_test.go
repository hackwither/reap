package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestWriteHuman_NeverLeaksGoMapSyntax is a regression test for the
// "map[k:v ...]" leak the human report used to have: WriteHuman must render
// nested evidence as indented human-readable lines, never Go's default %v
// stringification of a map or slice of maps.
func TestWriteHuman_NeverLeaksGoMapSyntax(t *testing.T) {
	r := &Report{
		Target: Target{URL: "https://example.com/mcp", Confirmed: true},
		Findings: []Finding{
			{
				ID:       "test-nested-evidence",
				Title:    "Nested evidence finding",
				Severity: SeverityMedium,
				Protocol: "mcp",
				Evidence: map[string]any{
					"fallbacks": []map[string]any{
						{"path": "/sse", "status": 200, "content_type": "text/html; charset=UTF-8"},
					},
					"nested": map[string]any{"a": 1, "b": []any{"x", "y"}},
				},
			},
		},
	}
	var buf bytes.Buffer
	r.WriteHuman(&buf)
	out := buf.String()
	if strings.Contains(out, "map[") {
		t.Fatalf("WriteHuman output leaked Go map syntax:\n%s", out)
	}
}

// TestWriteHuman_NeverLeaksGoSliceSyntax is a regression test for a gap the
// map-syntax fix above missed: a plain []string value (e.g.
// "observed_paths": []string{...}) fell through renderEvidenceValue's type
// switch to the %v default, which prints Go's bracket-and-space slice
// syntax ("[a b c]") — a different but equally real "this is stdout, not a
// report" leak. The fix moved to a reflect-based check covering any
// slice/array kind, not just []any and []map[string]any.
func TestWriteHuman_NeverLeaksGoSliceSyntax(t *testing.T) {
	r := &Report{
		Target: Target{URL: "https://example.com/mcp", Confirmed: true},
		Findings: []Finding{
			{
				ID:       "test-string-slice-evidence",
				Title:    "String slice evidence finding",
				Severity: SeverityMedium,
				Protocol: "mcp",
				Evidence: map[string]any{
					"observed_paths": []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-authorization-server"},
				},
			},
		},
	}
	var buf bytes.Buffer
	r.WriteHuman(&buf)
	out := buf.String()
	if strings.Contains(out, "[/.well-known") {
		t.Fatalf("WriteHuman output leaked Go slice syntax:\n%s", out)
	}
}

func TestWriteHuman_DossierPlainText(t *testing.T) {
	r := &Report{
		Version:    "0.1.0",
		StartedAt:  time.Unix(0, 0),
		FinishedAt: time.Unix(0, int64(842*time.Millisecond)),
		Target: Target{
			URL:         "https://agent.example/mcp",
			Protocol:    "mcp",
			ProtocolVer: "2025-03-26",
			Transport:   "streamable_http",
			Confirmed:   true,
			ServerName:  "example-agent",
			ServerVer:   "2.4.1",
		},
		Coverage: Coverage{Total: 12, Fired: 1, Clean: 9, Skipped: 2},
		Findings: []Finding{{
			ID:          "mcp-unauth-tools-list",
			Title:       "Unauthenticated Tool Enumeration",
			Severity:    SeverityHigh,
			Confidence:  "high",
			Description: "Tools are visible without authentication.",
		}},
	}
	var buf bytes.Buffer
	r.WriteHuman(&buf)
	out := buf.String()
	for _, want := range []string{
		"REAP", "AI AGENT RECON", "TARGET", "MCP 2025-03-26",
		"CONFIRMED", "FINDINGS", "mcp-unauth-tools-list",
		"HIGH RISK", "12 checks", "842ms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plain dossier missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Fatalf("WriteHuman emitted ANSI escapes:\n%q", out)
	}
}

func TestWriteHumanColor_EmitsANSIWithoutChangingContent(t *testing.T) {
	r := &Report{
		Version: "0.1.0",
		Target:  Target{URL: "https://agent.example/mcp", Protocol: "mcp", Confirmed: true},
		Findings: []Finding{{
			ID: "mcp-test", Title: "Test finding", Severity: SeverityMedium,
		}},
	}
	var plain, colored bytes.Buffer
	r.WriteHumanColor(&plain, false)
	r.WriteHumanColor(&colored, true)
	if !strings.Contains(colored.String(), "\x1b[") {
		t.Fatalf("colored dossier contains no ANSI escapes:\n%q", colored.String())
	}
	stripped := ansiPattern.ReplaceAllString(colored.String(), "")
	if stripped != plain.String() {
		t.Fatalf("color changed report content\nplain:\n%s\ncolored stripped:\n%s", plain.String(), stripped)
	}
}

func TestWriteHumanDossier_CompactAndVerboseDetail(t *testing.T) {
	r := &Report{
		Target: Target{URL: "https://agent.example/mcp", Confirmed: true},
		Findings: []Finding{{
			ID: "mcp-test", Title: "Test finding", Severity: SeverityLow,
			Request: &HTTPExchange{
				Method: "POST", URL: "https://agent.example/mcp",
				Expected: "401", Body: `{"method":"tools/list"}`,
			},
			Evidence:   map[string]any{"tool_count": 3},
			References: []string{"MCP specification"},
		}},
	}
	var compact, verbose bytes.Buffer
	r.WriteHumanDossier(&compact, false, false)
	r.WriteHumanDossier(&verbose, false, true)
	for _, hidden := range []string{"Reproduce", "Expected", "tool count", "MCP specification"} {
		if strings.Contains(compact.String(), hidden) {
			t.Errorf("compact dossier unexpectedly contains %q:\n%s", hidden, compact.String())
		}
		if !strings.Contains(verbose.String(), hidden) {
			t.Errorf("verbose dossier missing %q:\n%s", hidden, verbose.String())
		}
	}
	if !strings.Contains(compact.String(), "use -v for full evidence") {
		t.Fatalf("compact dossier missing detail hint:\n%s", compact.String())
	}
}

// TestWriteHumanDossier_DetailsSkipsEmptyAndRedundantStatusCode covers the
// two dangling-label cases from the task: an empty-string evidence value
// (e.g. www_authenticate when the header was absent) must not render a
// label with nothing after it, and a status_code evidence entry equal to
// the Evidence line's own status must not repeat it below.
func TestWriteHumanDossier_DetailsSkipsEmptyAndRedundantStatusCode(t *testing.T) {
	r := &Report{
		Target: Target{URL: "https://agent.example/mcp", Confirmed: true},
		Findings: []Finding{{
			ID: "mcp-test", Title: "Test finding", Severity: SeverityLow,
			Request: &HTTPExchange{Method: "POST", URL: "https://agent.example/mcp", StatusCode: 401},
			Evidence: map[string]any{
				"www_authenticate": "",
				"status_code":      401,
				"note":             "kept",
			},
		}},
	}
	var buf bytes.Buffer
	r.WriteHumanDossier(&buf, false, true)
	out := buf.String()
	if strings.Contains(out, "www authenticate") {
		t.Errorf("expected empty-value evidence row to be skipped:\n%s", out)
	}
	if strings.Contains(out, "status code") {
		t.Errorf("expected status_code row duplicating the Evidence line to be skipped:\n%s", out)
	}
	if !strings.Contains(out, "note") || !strings.Contains(out, "kept") {
		t.Errorf("expected a non-empty, non-redundant evidence row to still render:\n%s", out)
	}
}

// TestWriteHumanDossier_DetailsHeaderOmittedWhenAllRowsFiltered ensures the
// "Details" label itself doesn't dangle above nothing when every row in
// Evidence gets filtered out.
func TestWriteHumanDossier_DetailsHeaderOmittedWhenAllRowsFiltered(t *testing.T) {
	r := &Report{
		Target: Target{URL: "https://agent.example/mcp", Confirmed: true},
		Findings: []Finding{{
			ID: "mcp-test", Title: "Test finding", Severity: SeverityLow,
			Request:  &HTTPExchange{Method: "POST", URL: "https://agent.example/mcp", StatusCode: 401},
			Evidence: map[string]any{"status_code": 401, "empty": ""},
		}},
	}
	var buf bytes.Buffer
	r.WriteHumanDossier(&buf, false, true)
	if strings.Contains(buf.String(), "Details") {
		t.Errorf("expected Details header to be omitted when every row filters out:\n%s", buf.String())
	}
}

// TestWriteHumanDossier_AuthGatedHeaderAndNoWarning verifies the header
// state label reads CONFIRMED (AUTH-GATED), the target is not reported as
// UNCONFIRMED, and the generic-web-server warning is suppressed — the
// verification bar from the task.
func TestWriteHumanDossier_AuthGatedHeaderAndNoWarning(t *testing.T) {
	r := &Report{
		Target: Target{
			URL:           "https://agent.example/mcp",
			Confirmed:     true,
			ConfirmState:  ConfirmStateAuthGated,
			ConfirmReason: "initialize requires auth: HTTP 401 (application/problem+json)",
		},
	}
	var buf bytes.Buffer
	r.WriteHumanDossier(&buf, false, true)
	out := buf.String()
	if !strings.Contains(out, "CONFIRMED (AUTH-GATED)") {
		t.Errorf("expected header state CONFIRMED (AUTH-GATED):\n%s", out)
	}
	if strings.Contains(out, "UNCONFIRMED") {
		t.Errorf("expected no UNCONFIRMED label for an auth-gated target:\n%s", out)
	}
	if strings.Contains(out, "generic web server") {
		t.Errorf("expected no generic-web-server warning for an auth-gated target:\n%s", out)
	}
	if !strings.Contains(out, "AUTH REQUIRED") || !strings.Contains(out, "initialize requires auth") {
		t.Errorf("expected an informational auth-required note:\n%s", out)
	}
}

// TestApplyConfidenceDowngrade_CapsSeverityAndConfidence verifies the core
// x.com-bug fix: an unconfirmed target's findings must never render above
// info severity or above low confidence, regardless of what a probe set.
func TestApplyConfidenceDowngrade_CapsSeverityAndConfidence(t *testing.T) {
	r := &Report{
		Target: Target{Confirmed: false, ConfirmReason: "initialize returned non-JSON-RPC body"},
		Findings: []Finding{
			{ID: "a", Severity: SeverityHigh, Confidence: "high"},
			{ID: "b", Severity: SeverityMedium, Confidence: "high"},
			{ID: "c", Severity: SeverityInfo, Confidence: "high"},
		},
	}
	r.ApplyConfidenceDowngrade()
	for _, f := range r.Findings {
		if f.Severity != SeverityInfo {
			t.Errorf("finding %q: expected severity capped at info, got %q", f.ID, f.Severity)
		}
		if f.Confidence != "low" {
			t.Errorf("finding %q: expected confidence forced to low, got %q", f.ID, f.Confidence)
		}
	}
}

// TestApplyConfidenceDowngrade_NoOpWhenConfirmed ensures a confirmed
// target's findings are left untouched — the downgrade must not fire just
// because it exists.
func TestApplyConfidenceDowngrade_NoOpWhenConfirmed(t *testing.T) {
	r := &Report{
		Target: Target{Confirmed: true},
		Findings: []Finding{
			{ID: "a", Severity: SeverityHigh, Confidence: "high"},
		},
	}
	r.ApplyConfidenceDowngrade()
	if r.Findings[0].Severity != SeverityHigh || r.Findings[0].Confidence != "high" {
		t.Fatalf("expected confirmed target's findings untouched, got %+v", r.Findings[0])
	}
}

func TestWriteJSON_SortsBySeverityDescending(t *testing.T) {
	r := &Report{
		Findings: []Finding{
			{ID: "a", Severity: SeverityLow},
			{ID: "b", Severity: SeverityHigh},
			{ID: "c", Severity: SeverityInfo},
			{ID: "d", Severity: SeverityMedium},
		},
	}
	var buf bytes.Buffer
	if err := r.WriteJSON(&buf); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	want := []string{"b", "d", "a", "c"} // high, medium, low, info
	for i, f := range r.Findings {
		if f.ID != want[i] {
			t.Fatalf("position %d: got %q, want %q (order: %v)", i, f.ID, want[i], findingIDs(r.Findings))
		}
	}
}

func TestASITitles_AllTenPresent(t *testing.T) {
	for i := 1; i <= 10; i++ {
		id := asiID(i)
		if _, ok := ASITitles[id]; !ok {
			t.Errorf("missing ASI title for %s", id)
		}
	}
}

func findingIDs(fs []Finding) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.ID
	}
	return out
}

func TestWriteSARIF_DeduplicatesRules(t *testing.T) {
	r := &Report{
		Version: "0.1.0",
		Target:  Target{URL: "https://example.com/mcp"},
		Findings: []Finding{
			{ID: "mcp-foo", Title: "Foo", Severity: SeverityLow, Description: "desc", Remediation: "fix", ASI: []string{"ASI09"}},
			{ID: "mcp-foo", Title: "Foo", Severity: SeverityLow, Description: "desc", Remediation: "fix", ASI: []string{"ASI09"}},
			{ID: "mcp-bar", Title: "Bar", Severity: SeverityHigh, Description: "desc2", Remediation: "fix2", ASI: []string{"ASI02"}},
		},
	}
	var buf bytes.Buffer
	if err := r.WriteSARIF(&buf); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if out["version"] != "2.1.0" {
		t.Fatalf("unexpected SARIF version: %v", out["version"])
	}
	runs, ok := out["runs"].([]any)
	if !ok || len(runs) != 1 {
		t.Fatalf("expected one run, got %v", out["runs"])
	}
	firstRun, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatal("invalid run object")
	}
	rules, ok := firstRun["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	if !ok {
		t.Fatal("invalid rules structure")
	}
	if len(rules) != 2 {
		t.Fatalf("expected 2 unique rules, got %d", len(rules))
	}
	results, ok := firstRun["results"].([]any)
	if !ok || len(results) != 3 {
		t.Fatalf("expected 3 results, got %v", firstRun["results"])
	}
}

func asiID(n int) string {
	if n < 10 {
		return "ASI0" + string(rune('0'+n))
	}
	return "ASI10"
}
