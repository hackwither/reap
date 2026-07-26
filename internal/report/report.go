// Package report defines the shared data model every probe writes into.
//
// Every probe, whether it's a built-in Go check or a JSON template loaded at
// runtime, produces Findings. Findings are the only thing that gets
// rendered, diffed, or exported — this keeps the output format stable even
// as new protocols and checks are added.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"time"
)

// Severity is intentionally coarse. This tool enumerates and observes; it
// does not exploit. Severity reflects exposure, not confirmed impact.
type Severity string

const (
	SeverityInfo   Severity = "info"
	SeverityLow    Severity = "low"
	SeverityMedium Severity = "medium"
	SeverityHigh   Severity = "high"
)

// Finding is one observation about a target. Findings are additive and
// read-only in nature — "the server returned X when asked Y", not "we did Z
// to the server."
type Finding struct {
	ID          string         `json:"id"` // stable slug, e.g. "mcp-unauth-tools-list"
	Title       string         `json:"title"`
	Severity    Severity       `json:"severity"`
	Protocol    string         `json:"protocol"`           // "mcp", "a2a", "openai-functions", ...
	ASI         []string       `json:"asi_refs,omitempty"` // OWASP Agentic Top 10 (2026) refs, e.g. ["ASI02","ASI03"]
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence,omitempty"` // raw observation, kept structured for jq/SARIF conversion
	Remediation string         `json:"remediation,omitempty"`
	Source      string         `json:"source"` // "builtin:mcp" or "template:<path>"
	Tags        []string       `json:"tags,omitempty"`
}

// Target describes what was scanned.
type Target struct {
	URL         string `json:"url"`
	Protocol    string `json:"protocol,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	ServerVer   string `json:"server_version,omitempty"`
	ProtocolVer string `json:"protocol_version,omitempty"`
}

// Report is the full output of a scan run.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Target     Target    `json:"target"`
	Findings   []Finding `json:"findings"`
	Errors     []string  `json:"errors,omitempty"`
}

func (r *Report) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
}

func (r *Report) AddError(err error) {
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
}

// severityRank is used for sorting only; higher = shown first.
var severityRank = map[Severity]int{
	SeverityHigh:   3,
	SeverityMedium: 2,
	SeverityLow:    1,
	SeverityInfo:   0,
}

// WriteJSON writes the machine-readable report. This is the canonical
// output — the human summary is a view over the same data.
func (r *Report) WriteJSON(w io.Writer) error {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return severityRank[r.Findings[i].Severity] > severityRank[r.Findings[j].Severity]
	})
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteHuman writes a compact terminal-friendly summary.
func (r *Report) WriteHuman(w io.Writer) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return severityRank[r.Findings[i].Severity] > severityRank[r.Findings[j].Severity]
	})

	fmt.Fprintf(w, "\nagentrecon report — target: %s\n", r.Target.URL)
	if r.Target.ServerName != "" {
		fmt.Fprintf(w, "  server:   %s %s\n", r.Target.ServerName, r.Target.ServerVer)
	}
	if r.Target.ProtocolVer != "" {
		fmt.Fprintf(w, "  protocol: %s (%s)\n", r.Target.Protocol, r.Target.ProtocolVer)
	}
	fmt.Fprintf(w, "  duration: %s\n\n", r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  no findings.")
	}
	for _, f := range r.Findings {
		badge := map[Severity]string{
			SeverityHigh:   "[HIGH]  ",
			SeverityMedium: "[MED]   ",
			SeverityLow:    "[LOW]   ",
			SeverityInfo:   "[INFO]  ",
		}[f.Severity]
		asi := ""
		if len(f.ASI) > 0 {
			asi = " (" + joinASI(f.ASI) + ")"
		}
		fmt.Fprintf(w, "  %s%s%s\n", badge, f.Title, asi)
		fmt.Fprintf(w, "          %s\n", f.Description)
		// Print evidence: matched values that triggered this finding
		if len(f.Evidence) > 0 {
			fmt.Fprintf(w, "          evidence:\n")
			// Sort evidence keys for deterministic output
			var keys []string
			for k := range f.Evidence {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				val := f.Evidence[key]
				fmt.Fprintf(w, "            %s: %v\n", key, val)
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "          fix: %s\n", f.Remediation)
		}
		fmt.Fprintln(w)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(w, "  [error] %s\n", e)
	}
}

func joinASI(refs []string) string {
	out := ""
	for i, r := range refs {
		if i > 0 {
			out += ", "
		}
		out += r
	}
	return out
}

// ASI reference table — OWASP Top 10 for Agentic Applications (2026).
// Kept here so probes/templates can cite by code without hardcoding titles
// everywhere, and so this list has exactly one place to update.
var ASITitles = map[string]string{
	"ASI01": "Agent Goal Hijack",
	"ASI02": "Tool Misuse & Exploitation",
	"ASI03": "Agent Identity & Privilege Abuse",
	"ASI04": "Insecure Inter-Agent Communication",
	"ASI05": "Memory & Context Poisoning",
	"ASI06": "Cascading Failures",
	"ASI07": "Excessive Agency",
	"ASI08": "Supply Chain & Dependency Risk",
	"ASI09": "Observability & Auditability Gaps",
	"ASI10": "Rogue Agents",
}

// WriteSARIF writes a SARIF 2.1.0 formatted report suitable for integration
// with CI/CD pipelines and code-scanning tools like GitHub Security.
func (r *Report) WriteSARIF(w io.Writer) error {
	// De-duplicate rules by finding ID
	rulesByID := make(map[string]Finding)
	for _, f := range r.Findings {
		rulesByID[f.ID] = f
	}

	// Build rules array (deduplicated)
	rules := make([]map[string]any, 0, len(rulesByID))
	for _, id := range uniqueFindingIDs(r.Findings) {
		f := rulesByID[id]
		rules = append(rules, map[string]any{
			"id": f.ID,
			"shortDescription": map[string]string{
				"text": f.Title,
			},
			"fullDescription": map[string]string{
				"text": f.Description,
			},
			"help": map[string]string{
				"text": f.Remediation,
			},
			"properties": map[string]any{
				"tags": f.ASI,
			},
		})
	}

	// Build results array (one per finding, including duplicates)
	results := make([]map[string]any, 0, len(r.Findings))
	for _, f := range r.Findings {
		results = append(results, map[string]any{
			"ruleId": f.ID,
			"level":  severityToSARIFLevel(f.Severity),
			"message": map[string]string{
				"text": f.Description,
			},
			"locations": []map[string]any{
				{
					"physicalLocation": map[string]any{
						"artifactLocation": map[string]string{
							"uri": r.Target.URL,
						},
					},
				},
			},
		})
	}

	// Build complete SARIF document
	sarifDoc := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{
			{
				"tool": map[string]any{
					"driver": map[string]any{
						"name":           "agentrecon",
						"informationUri": "https://github.com/hackwither/agentrecon",
						"version":        r.Version,
						"rules":          rules,
					},
				},
				"results": results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifDoc)
}

// findingIDs returns a list of unique finding IDs in order of first appearance
func uniqueFindingIDs(findings []Finding) []string {
	seen := make(map[string]bool)
	var ids []string
	for _, f := range findings {
		if !seen[f.ID] {
			ids = append(ids, f.ID)
			seen[f.ID] = true
		}
	}
	return ids
}

// severityToSARIFLevel maps agentrecon severity to SARIF level
func severityToSARIFLevel(sev Severity) string {
	switch sev {
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	case SeverityLow, SeverityInfo:
		return "note"
	default:
		return "note"
	}
}
