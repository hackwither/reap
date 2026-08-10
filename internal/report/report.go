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
	"reflect"
	"sort"
	"strings"
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

// ConfirmState distinguishes *why* a target counts as confirmed (or
// doesn't) — Target.Confirmed alone collapses "handshake succeeded" and
// "handshake auth-gated but still MCP-consistent" into the same bool, which
// is exactly right for ApplyConfidenceDowngrade/posture (both real states
// should skip the downgrade) but loses the distinction the report header
// and the informational auth-gate note need to draw.
type ConfirmState string

const (
	// ConfirmStateConfirmed: the handshake completed normally (e.g. HTTP 200
	// with a valid JSON-RPC initialize result).
	ConfirmStateConfirmed ConfirmState = "confirmed"
	// ConfirmStateAuthGated: initialize returned 401/403, but the response is
	// consistent with a real protocol endpoint gating the handshake behind
	// auth (problem+json, a JSON-RPC error envelope, or a Bearer challenge) —
	// treated as confirmed, not as a failure.
	ConfirmStateAuthGated ConfirmState = "confirmed_auth_gated"
	// ConfirmStateUnconfirmed: the response was inconsistent with the
	// protocol being scanned (wrong content type, decode failure, transport
	// failure) — the only state that downgrades findings.
	ConfirmStateUnconfirmed ConfirmState = "unconfirmed"
)

// Finding is one observation about a target. Findings are additive and
// read-only in nature — "the server returned X when asked Y", not "we did Z
// to the server."
type Finding struct {
	ID          string         `json:"id"` // stable slug, e.g. "mcp-unauth-tools-list"
	Title       string         `json:"title"`
	Severity    Severity       `json:"severity"`
	Confidence  string         `json:"confidence,omitempty"` // "high"|"medium"|"low" — how much this finding should be trusted, independent of severity
	Protocol    string         `json:"protocol"`             // "mcp", "a2a", "openai-functions", ...
	ASI         []string       `json:"asi_refs,omitempty"`   // OWASP Agentic Top 10 (2026) refs, e.g. ["ASI02","ASI03"]
	References  []string       `json:"references,omitempty"` // underlying standards this finding is judged against, e.g. "RFC 7636 (PKCE)"
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence,omitempty"` // raw observation, kept structured for jq/SARIF conversion
	Request     *HTTPExchange  `json:"request,omitempty"`  // the single request/response this finding is reproducible from
	Remediation string         `json:"remediation,omitempty"`
	Source      string         `json:"source"` // "builtin:mcp" or "template:<path>"
	Tags        []string       `json:"tags,omitempty"`
}

// HTTPExchange is the minimal request/response record needed for a human to
// reproduce a finding by hand — the review that prompted this field pointed
// out that a finding nobody can re-run by curling it themselves isn't
// trustworthy, no matter how well-labeled it is.
type HTTPExchange struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"` // the exact request body sent, e.g. the JSON-RPC envelope — without this, curl -X POST alone won't reproduce a body-dependent match
	StatusCode  int               `json:"status_code"`
	ContentType string            `json:"content_type,omitempty"`
	BodySize    int               `json:"body_size,omitempty"`
	Expected    string            `json:"expected,omitempty"` // what a real match would have looked like, e.g. "text/event-stream or application/json"
}

// Curl renders the request half of the exchange as a copy-pasteable
// reproduction command.
func (e *HTTPExchange) Curl() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("curl -s")
	if e.Method != "" && !strings.EqualFold(e.Method, "GET") {
		fmt.Fprintf(&b, " -X %s", e.Method)
	}
	for k, v := range e.Headers {
		fmt.Fprintf(&b, " -H %s", shellQuote(k+": "+v))
	}
	if e.Body != "" {
		fmt.Fprintf(&b, " -d %s", shellQuote(e.Body))
	}
	fmt.Fprintf(&b, " %s", shellQuote(e.URL))
	return b.String()
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Target describes what was scanned.
type Target struct {
	URL         string `json:"url"`
	Protocol    string `json:"protocol,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	ServerVer   string `json:"server_version,omitempty"`
	ProtocolVer string `json:"protocol_version,omitempty"`

	// Populated only when the target was resolved via Discovery
	// (--protocol auto) rather than assumed from a flag.
	Transport           string `json:"transport,omitempty"`
	DiscoveryMethod     string `json:"discovery_method,omitempty"`     // detector ID, or "manual"
	DiscoveryConfidence string `json:"discovery_confidence,omitempty"` // "high"/"medium"/"low"

	// Confirmed records whether the target actually completed a protocol
	// handshake (e.g. MCP's initialize returning a valid JSON-RPC result) OR
	// answered with an auth challenge that's still consistent with being a
	// real protocol endpoint (see ConfirmState), as opposed to merely being
	// assumed. An unconfirmed target means every finding below is a
	// best-effort read on a host that never proved it speaks the protocol
	// being probed — see Report.ApplyConfidenceDowngrade.
	Confirmed     bool         `json:"confirmed"`
	ConfirmState  ConfirmState `json:"confirm_state,omitempty"`
	ConfirmReason string       `json:"confirm_reason,omitempty"` // why Confirmed is false, or why an auth-gated target is still confirmed

	// Best-effort fingerprint facts captured once up front, regardless of
	// whether any probe below turns them into a finding.
	ResolvedIP string `json:"resolved_ip,omitempty"`
	TLSSummary string `json:"tls_summary,omitempty"` // e.g. "TLS 1.3 · valid · *.example.com"
	// EdgeServer is the raw HTTP Server response header, captured
	// regardless of handshake outcome. Deliberately separate from
	// ServerName/ServerVer (the MCP handshake's serverInfo, i.e. the
	// application) — this is almost always CDN/edge software (cloudflare,
	// envoy, ...) fronting the real origin, a fact about the network path,
	// not the agent implementation.
	EdgeServer string `json:"edge_server,omitempty"`
}

// Coverage summarizes how many checks ran and what they did — absence of
// findings is signal too, and a bare finding count can't distinguish
// "23 checks, 1 fired" from "1 check, 1 fired".
type Coverage struct {
	Total   int `json:"total"`
	Fired   int `json:"fired"`
	Clean   int `json:"clean"`
	Skipped int `json:"skipped"`
}

// Report is the full output of a scan run.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Target     Target    `json:"target"`
	Coverage   Coverage  `json:"coverage"`
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

// ApplyConfidenceDowngrade caps every finding's severity at info and forces
// low confidence when the target never confirmed the protocol it's being
// scanned as. This is the fix for the "x.com reported five MCP findings"
// failure mode: a scanner that fires MED findings against a plain web
// server because a handshake returned an HTML error page is not
// trustworthy, no matter how well-labeled the individual findings are.
// Deliberately blunt — every finding is downgraded uniformly, including
// ones (like TLS cert health) that are real facts about the host
// independent of protocol confirmation, because consistency here matters
// more than precision in this first pass.
func (r *Report) ApplyConfidenceDowngrade() {
	if r.Target.Confirmed {
		return
	}
	for i := range r.Findings {
		f := &r.Findings[i]
		if severityRank[f.Severity] > severityRank[SeverityInfo] {
			f.Severity = SeverityInfo
		}
		f.Confidence = "low"
		f.Tags = appendUnique(f.Tags, "target-unconfirmed")
	}
}

// MeetsSeverity reports whether any finding is at or above threshold —
// used by the CLI's --fail-on gate for pipeline use. An unrecognized or
// empty threshold (including "none") never trips.
func (r *Report) MeetsSeverity(threshold Severity) bool {
	want, ok := severityRank[threshold]
	if !ok {
		return false
	}
	for _, f := range r.Findings {
		if severityRank[f.Severity] >= want {
			return true
		}
	}
	return false
}

func appendUnique(tags []string, tag string) []string {
	for _, t := range tags {
		if t == tag {
			return tags
		}
	}
	return append(tags, tag)
}

// ComputeCoverage fills r.Coverage from perProbeFindingCounts, a map of
// probe ID to how many findings that probe added (0 for "ran clean").
// skipped is the count of probes filtered out before they ever ran (e.g.
// by transport mismatch).
func (r *Report) ComputeCoverage(perProbeFindingCounts map[string]int, skipped int) {
	r.Coverage.Skipped = skipped
	r.Coverage.Total = len(perProbeFindingCounts) + skipped
	for _, n := range perProbeFindingCounts {
		if n > 0 {
			r.Coverage.Fired++
		} else {
			r.Coverage.Clean++
		}
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

// WriteHuman writes a compact terminal-friendly summary: a target
// fingerprint block, a coverage/summary rollup, then one section per
// finding with legible (not Go-struct-dumped) evidence and a reproduction
// command.
func (r *Report) WriteHuman(w io.Writer) {
	r.WriteHumanColor(w, false)
}

// summaryLine renders the "0 crit · 0 high · 2 med · 2 info · 1 error"
// rollup — a scanner's payoff should be legible at a glance, not just
// present in the finding list below it.
func (r *Report) summaryLine() string {
	var high, med, low, info, downgraded int
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityHigh:
			high++
		case SeverityMedium:
			med++
		case SeverityLow:
			low++
		case SeverityInfo:
			info++
		}
		for _, t := range f.Tags {
			if t == "target-unconfirmed" {
				downgraded++
				break
			}
		}
	}
	line := fmt.Sprintf("%d high · %d med · %d low · %d info · %d error", high, med, low, info, len(r.Errors))
	if !r.Target.Confirmed {
		line += "   target unconfirmed"
	}
	if downgraded > 0 {
		line += fmt.Sprintf("   (%d finding(s) downgraded: unconfirmed target)", downgraded)
	}
	return line
}

// renderEvidenceValue prints an evidence value as indented, human-legible
// lines instead of relying on Go's default %v stringification — printing a
// nested map with %v produces literal "map[k:v ...]" text, and printing a
// slice (of any element type, not just []map[string]any — []string
// included) produces literal "[a b c]" text. Both are the single biggest
// "this is stdout, not a report" tell a raw recon tool can have. Uses
// reflect rather than a type switch over specific container types so this
// covers every slice/map shape a probe or template might produce, not just
// the ones anticipated when this was written.
func renderEvidenceValue(w io.Writer, indent string, v any) {
	if v == nil {
		fmt.Fprintf(w, "%s(none)\n", indent)
		return
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok { // only map[string]any is ever produced by probes/templates in practice
			fmt.Fprintf(w, "%s%v\n", indent, v)
			return
		}
		var keys []string
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if isCompoundEvidence(m[k]) {
				fmt.Fprintf(w, "%s%s:\n", indent, k)
				renderEvidenceValue(w, indent+"  ", m[k])
			} else {
				fmt.Fprintf(w, "%s%s: %v\n", indent, k, m[k])
			}
		}
	case reflect.Slice, reflect.Array:
		if rv.Len() == 0 {
			fmt.Fprintf(w, "%s(none)\n", indent)
			return
		}
		for i := 0; i < rv.Len(); i++ {
			item := rv.Index(i).Interface()
			if isCompoundEvidence(item) {
				fmt.Fprintf(w, "%s-\n", indent)
				renderEvidenceValue(w, indent+"  ", item)
			} else {
				fmt.Fprintf(w, "%s- %v\n", indent, item)
			}
		}
	default:
		fmt.Fprintf(w, "%s%v\n", indent, v)
	}
}

func isCompoundEvidence(v any) bool {
	if v == nil {
		return false
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		return true
	default:
		return false
	}
}

func humanBytes(n int) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	if n < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
}

func joinASITitled(refs []string) string {
	out := make([]string, 0, len(refs))
	for _, code := range refs {
		if title, ok := ASITitles[code]; ok {
			out = append(out, fmt.Sprintf("%s: %s", code, title))
		} else {
			out = append(out, code)
		}
	}
	return strings.Join(out, ", ")
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
						"name":           "reap",
						"informationUri": "https://github.com/hackwither/reap",
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

// severityToSARIFLevel maps reap severity to SARIF level
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
