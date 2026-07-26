package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

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
