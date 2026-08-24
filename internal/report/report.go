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

	"github.com/hackwither/reap/internal/version"
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

	// AuthState records whether capability enumeration answered anonymously,
	// required credentials, or never answered. Distinct from ConfirmState:
	// that says whether this is really an endpoint of the claimed protocol,
	// this says what it's willing to tell a stranger.
	AuthState string `json:"auth_state,omitempty"`

	// Capabilities is the enumerated surface size, when enumeration
	// succeeded. Kept out of Findings so it renders in the identification
	// block rather than sorting last as an info finding.
	Capabilities *CapabilitySummary `json:"capabilities,omitempty"`

	// RawInput preserves what the user typed, when discovery resolved it to a
	// different URL (e.g. "localhost:8080" -> "http://localhost:8080/mcp").
	RawInput string `json:"raw_input,omitempty"`
}

// Auth states for a target's enumeration surface. This is the single most
// useful recon fact about an agent endpoint, so it is a first-class field
// rather than an error string.
const (
	AuthStateOpen      = "open"       // enumeration answered without credentials
	AuthStateGated     = "auth-gated" // endpoint is live but requires credentials
	AuthStateAuthed    = "authed"     // enumeration answered, but only with supplied credentials
	AuthStateUnreached = "unreached"  // endpoint never answered at all
	AuthStateUnknown   = "unknown"    // could not determine
)

// CapabilitySummary is the headline recon payload: how much surface this
// endpoint exposed to the caller.
type CapabilitySummary struct {
	Tools     int  `json:"tools"`
	Resources int  `json:"resources"`
	Prompts   int  `json:"prompts"`
	Truncated bool `json:"truncated,omitempty"` // pagination cap hit; counts are a floor
}

// Coverage summarizes how many checks ran and what they did — absence of
// findings is signal too, and a bare finding count can't distinguish
// "23 checks, 1 fired" from "1 check, 1 fired".
//
// Errored counts checks that could not complete. It is the difference
// between "we looked and found nothing" and "we never managed to look",
// which a fired/clean split alone cannot express.
type Coverage struct {
	Total   int `json:"total"`
	Fired   int `json:"fired"`
	Clean   int `json:"clean"`
	Skipped int `json:"skipped"`
	Errored int `json:"errored,omitempty"`
}

// Probe execution outcomes, recorded per probe so a quiet report is
// interpretable.
const (
	// ProbeRan means the probe executed and reached a conclusion. Absence of
	// a finding from a probe with this status is a real negative result.
	ProbeRan = "ran"
	// ProbeNotApplicable means the probe correctly declined — a TLS check
	// against an http:// target, a session-ID check where the server issues
	// no session. Not a failure.
	ProbeNotApplicable = "not-applicable"
	// ProbeError means the probe could not complete. Absence of a finding
	// here says nothing about the target.
	ProbeError = "error"
	// ProbeAborted means the scan deadline expired before this probe ran.
	ProbeAborted = "aborted"
)

// Report completion states.
const (
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// ProbeRun records what happened to one probe during a scan.
type ProbeRun struct {
	ID       string `json:"id"`
	Status   string `json:"status"`
	Findings int    `json:"findings"`
	Detail   string `json:"detail,omitempty"`
}

// Report is the full output of a scan run.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Target     Target    `json:"target"`
	Coverage   Coverage  `json:"coverage"`

	// Status is "complete" or "incomplete". Incomplete means at least one
	// probe could not run, so absent findings are not negative results.
	Status           string `json:"status"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`

	// Findings and Probes are always non-nil so JSON consumers see [] rather
	// than null.
	Findings []Finding  `json:"findings"`
	Probes   []ProbeRun `json:"probes"`
	Errors   []string   `json:"errors,omitempty"`
}

// New builds an empty report with non-nil slices and the current tool
// version, so no caller has to remember either.
func New(rawInput, url, protocol string) *Report {
	return &Report{
		Tool:      "reap",
		Version:   version.Version,
		StartedAt: time.Now().UTC(),
		Status:    StatusComplete,
		Target: Target{
			URL:       url,
			RawInput:  rawInput,
			Protocol:  protocol,
			AuthState: AuthStateUnknown,
		},
		Findings: []Finding{},
		Probes:   []ProbeRun{},
	}
}

// RecordProbe appends a probe execution record. Any status other than
// ProbeRan or ProbeNotApplicable marks the whole report incomplete, because
// from that point on absent findings can't be read as clean.
func (r *Report) RecordProbe(id, status, detail string, findingsAdded int) {
	r.Probes = append(r.Probes, ProbeRun{ID: id, Status: status, Detail: detail, Findings: findingsAdded})
	if status == ProbeError || status == ProbeAborted {
		r.MarkIncomplete(fmt.Sprintf("probe %s: %s", id, status))
	}
}

// MarkIncomplete flags the report as not a trustworthy negative result. The
// first reason recorded wins, since it's usually the root cause.
func (r *Report) MarkIncomplete(reason string) {
	r.Status = StatusIncomplete
	if r.IncompleteReason == "" {
		r.IncompleteReason = reason
	}
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

// ComputeCoverage derives r.Coverage from the per-probe records.
//
// It reads from Probes rather than taking a tally, so the rollup and the
// per-probe detail can never disagree. filteredOut is the count of probes
// excluded before they ever ran (--include/--exclude, protocol mismatch);
// those have no ProbeRun because nothing was attempted.
func (r *Report) ComputeCoverage(filteredOut int) {
	r.Coverage = Coverage{Skipped: filteredOut, Total: len(r.Probes) + filteredOut}
	for _, p := range r.Probes {
		switch p.Status {
		case ProbeRan:
			if p.Findings > 0 {
				r.Coverage.Fired++
			} else {
				r.Coverage.Clean++
			}
		case ProbeNotApplicable:
			r.Coverage.Skipped++
		case ProbeError, ProbeAborted:
			r.Coverage.Errored++
		}
	}
}

// Rank is the comparable weight of a severity.
func (s Severity) Rank() int { return severityRank[s] }

// ParseSeverity validates a user-supplied severity name, for --fail-on and
// --min-severity, so a typo is a usage error rather than a silently
// never-tripping threshold.
func ParseSeverity(s string) (Severity, error) {
	switch Severity(strings.ToLower(strings.TrimSpace(s))) {
	case SeverityInfo:
		return SeverityInfo, nil
	case SeverityLow:
		return SeverityLow, nil
	case SeverityMedium:
		return SeverityMedium, nil
	case SeverityHigh:
		return SeverityHigh, nil
	}
	return "", fmt.Errorf("unknown severity %q (want one of: info, low, medium, high)", s)
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

// WriteSARIF writes this single report as a one-run SARIF 2.1.0 document.
func (r *Report) WriteSARIF(w io.Writer) error {
	return WriteSARIFRuns([]*Report{r}, w)
}

// WriteSARIFRuns writes one or more reports as a single SARIF 2.1.0 document
// with one run per report. Single-target and batch output share this code so
// the two formats cannot drift apart.
//
// Targets are recorded as logicalLocations, not physicalLocations. A network
// endpoint is not a file: GitHub code scanning expects artifactLocation.uri
// to be a repository-relative path, and will not render a result whose uri is
// an absolute https:// URL.
func WriteSARIFRuns(reports []*Report, w io.Writer) error {
	runs := make([]map[string]any, 0, len(reports))
	for _, rep := range reports {
		sort.SliceStable(rep.Findings, func(i, j int) bool {
			return severityRank[rep.Findings[i].Severity] > severityRank[rep.Findings[j].Severity]
		})

		rulesByID := make(map[string]Finding, len(rep.Findings))
		for _, f := range rep.Findings {
			rulesByID[f.ID] = f
		}
		rules := make([]map[string]any, 0, len(rulesByID))
		for _, id := range uniqueFindingIDs(rep.Findings) {
			f := rulesByID[id]
			tags := make([]string, 0, len(f.ASI)+len(f.Tags)+1)
			if f.Protocol != "" {
				tags = append(tags, f.Protocol)
			}
			tags = append(tags, f.ASI...)
			tags = append(tags, f.Tags...)
			rules = append(rules, map[string]any{
				"id":               f.ID,
				"shortDescription": map[string]string{"text": f.Title},
				"fullDescription":  map[string]string{"text": f.Description},
				"help":             map[string]string{"text": f.Remediation},
				"properties": map[string]any{
					"tags":              tags,
					"security-severity": sarifSecuritySeverity(f.Severity),
				},
			})
		}

		results := make([]map[string]any, 0, len(rep.Findings))
		for _, f := range rep.Findings {
			props := map[string]any{"target": rep.Target.URL, "protocol": f.Protocol}
			if f.Confidence != "" {
				props["confidence"] = f.Confidence
			}
			if repro := f.Request.Curl(); repro != "" {
				props["reproduce"] = repro
			}
			results = append(results, map[string]any{
				"ruleId":  f.ID,
				"level":   severityToSARIFLevel(f.Severity),
				"message": map[string]string{"text": f.Description},
				"locations": []map[string]any{
					{
						"logicalLocations": []map[string]any{
							{
								"name":               rep.Target.URL,
								"fullyQualifiedName": rep.Target.URL,
								"kind":               "resource",
							},
						},
					},
				},
				"properties": props,
			})
		}

		runs = append(runs, map[string]any{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "reap",
					"informationUri": "https://github.com/hackwither/reap",
					"version":        rep.Version,
					"rules":          rules,
				},
			},
			"automationDetails": map[string]any{"id": "reap/" + rep.Target.URL},
			"invocations": []map[string]any{
				{
					"executionSuccessful": rep.Status != StatusIncomplete,
					"startTimeUtc":        rep.StartedAt.Format(time.RFC3339),
					"endTimeUtc":          rep.FinishedAt.Format(time.RFC3339),
				},
			},
			"columnKind": "utf16CodeUnits",
			"results":    results,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs":    runs,
	})
}

// sarifSecuritySeverity supplies the numeric score GitHub code scanning uses
// to bucket alerts. Without it every reap alert lands in the same bucket.
func sarifSecuritySeverity(sev Severity) string {
	switch sev {
	case SeverityHigh:
		return "8.0"
	case SeverityMedium:
		return "5.0"
	case SeverityLow:
		return "3.0"
	default:
		return "0.0"
	}
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
