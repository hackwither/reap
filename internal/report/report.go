// Package report defines the shared data model every probe writes into.
//
// Every probe, whether it's a built-in Go check or a JSON template loaded at
// runtime, produces Findings. Findings are the only thing that gets
// rendered, diffed, or exported — this keeps the output format stable even
// as new protocols and checks are added.
//
// Alongside Findings, a Report carries a per-probe execution record (see
// ProbeRun). That distinction matters more for a recon tool than for a
// scanner: "I asked and the endpoint was clean" and "I never managed to ask"
// must not render as the same silence.
package report

import (
	"encoding/json"
	"fmt"
	"io"
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

// severityRank orders severities for sorting and for --fail-on threshold
// comparisons. Higher is more severe.
var severityRank = map[Severity]int{
	SeverityHigh:   3,
	SeverityMedium: 2,
	SeverityLow:    1,
	SeverityInfo:   0,
}

// Rank is the comparable weight of a severity.
func (s Severity) Rank() int { return severityRank[s] }

// ParseSeverity validates a user-supplied severity name, for --fail-on.
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

// Probe execution outcomes. Recorded per probe so a report can distinguish
// "checked, clean" from "could not check".
const (
	// ProbeRan means the probe executed and reached a conclusion. Absence of
	// a finding from a probe with this status is a real negative result.
	ProbeRan = "ran"
	// ProbeNotApplicable means the probe correctly declined to run — a TLS
	// check against an http:// target, a session-ID check where the server
	// issues no session. Not a failure.
	ProbeNotApplicable = "not-applicable"
	// ProbeError means the probe could not complete. Absence of a finding
	// here says nothing about the target.
	ProbeError = "error"
	// ProbeAborted means the scan deadline expired before this probe ran.
	ProbeAborted = "aborted"
)

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

// Report completion states.
const (
	StatusComplete   = "complete"
	StatusIncomplete = "incomplete"
)

// Finding is one observation about a target. Findings are additive and
// read-only in nature — "the server returned X when asked Y", not "we did Z
// to the server."
type Finding struct {
	ID          string         `json:"id"` // stable slug, e.g. "mcp-unauth-tools-list"
	Title       string         `json:"title"`
	Severity    Severity       `json:"severity"`
	Protocol    string         `json:"protocol"`           // "mcp", "a2a", "openapi", "*"
	ASI         []string       `json:"asi_refs,omitempty"` // OWASP Agentic Top 10 (2026) refs, e.g. ["ASI02","ASI03"]
	Description string         `json:"description"`
	Evidence    map[string]any `json:"evidence,omitempty"` // raw observation, kept structured for jq/SARIF conversion
	Remediation string         `json:"remediation,omitempty"`
	Source      string         `json:"source"` // "builtin:mcp" or "template:<path>"
	Tags        []string       `json:"tags,omitempty"`
}

// ProbeRun records what happened to one probe during a scan. Without this,
// an empty findings list is ambiguous — see the package doc.
type ProbeRun struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CapabilitySummary is the headline recon payload: how much surface this
// endpoint exposed to the caller. Kept out of Findings so it renders in the
// identification block instead of sorting last as an info finding.
type CapabilitySummary struct {
	Tools     int  `json:"tools"`
	Resources int  `json:"resources"`
	Prompts   int  `json:"prompts"`
	Truncated bool `json:"truncated,omitempty"` // pagination cap hit; counts are a floor
}

// Target describes what was scanned.
type Target struct {
	URL         string `json:"url"`
	Protocol    string `json:"protocol,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
	ServerVer   string `json:"server_version,omitempty"`
	ProtocolVer string `json:"protocol_version,omitempty"`

	// AuthState records whether capability enumeration answered anonymously,
	// required credentials, or never answered at all.
	AuthState string `json:"auth_state,omitempty"`

	// Capabilities is the enumerated surface size, when enumeration succeeded.
	Capabilities *CapabilitySummary `json:"capabilities,omitempty"`

	// Populated only when the target was resolved via Discovery
	// (--protocol auto) rather than assumed from a flag.
	Transport           string `json:"transport,omitempty"`
	DiscoveryMethod     string `json:"discovery_method,omitempty"`     // detector ID, or "manual"
	DiscoveryConfidence string `json:"discovery_confidence,omitempty"` // "high"/"medium"/"low"

	// RawInput preserves what the user typed, when discovery resolved it to a
	// different URL (e.g. "localhost:8080" -> "http://localhost:8080/mcp").
	RawInput string `json:"raw_input,omitempty"`
}

// Report is the full output of a scan run.
type Report struct {
	Tool       string    `json:"tool"`
	Version    string    `json:"version"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	Target     Target    `json:"target"`

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

func (r *Report) AddFinding(f Finding) {
	r.Findings = append(r.Findings, f)
}

func (r *Report) AddError(err error) {
	if err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
}

// RecordProbe appends a probe execution record. Any status other than
// ProbeRan or ProbeNotApplicable marks the whole report incomplete, because
// from that point on absent findings can't be read as clean.
func (r *Report) RecordProbe(id, status, detail string) {
	r.Probes = append(r.Probes, ProbeRun{ID: id, Status: status, Detail: detail})
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

// MaxSeverity returns the highest severity present, and whether any finding
// exists at all. Used to evaluate --fail-on.
func (r *Report) MaxSeverity() (Severity, bool) {
	if len(r.Findings) == 0 {
		return SeverityInfo, false
	}
	worst := r.Findings[0].Severity
	for _, f := range r.Findings[1:] {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst, true
}

// sortFindings orders findings most severe first, stably.
func (r *Report) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return r.Findings[i].Severity.Rank() > r.Findings[j].Severity.Rank()
	})
}

// WriteJSON writes the machine-readable report. This is the canonical
// output — the human summary is a view over the same data.
func (r *Report) WriteJSON(w io.Writer) error {
	r.sortFindings()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteHuman writes a compact terminal-friendly summary.
//
// The identification block comes first, deliberately. reap is a recon tool:
// what this endpoint is, which spec revision it negotiated, whether it
// answers strangers, and how much surface it exposed are the primary output.
// Severity-ranked posture findings follow.
func (r *Report) WriteHuman(w io.Writer) {
	r.sortFindings()

	fmt.Fprintf(w, "\nreap report — %s\n", r.Target.URL)
	if r.Target.RawInput != "" && r.Target.RawInput != r.Target.URL {
		fmt.Fprintf(w, "  input:      %s (resolved by discovery)\n", r.Target.RawInput)
	}

	proto := r.Target.Protocol
	if proto == "" {
		proto = "unidentified"
	}
	if r.Target.ProtocolVer != "" {
		proto = fmt.Sprintf("%s %s", proto, r.Target.ProtocolVer)
	}
	fmt.Fprintf(w, "  protocol:   %s\n", proto)
	if r.Target.Transport != "" {
		fmt.Fprintf(w, "  transport:  %s\n", r.Target.Transport)
	}
	if r.Target.ServerName != "" {
		fmt.Fprintf(w, "  server:     %s %s\n", r.Target.ServerName, r.Target.ServerVer)
	}
	if r.Target.AuthState != "" {
		fmt.Fprintf(w, "  auth:       %s\n", describeAuthState(r.Target.AuthState))
	}
	if c := r.Target.Capabilities; c != nil {
		suffix := ""
		if c.Truncated {
			suffix = " (truncated — counts are a floor)"
		}
		fmt.Fprintf(w, "  surface:    %d tools, %d resources, %d prompts%s\n", c.Tools, c.Resources, c.Prompts, suffix)
	}
	if r.Target.DiscoveryMethod != "" {
		fmt.Fprintf(w, "  discovery:  %s (confidence: %s)\n", r.Target.DiscoveryMethod, r.Target.DiscoveryConfidence)
	}
	fmt.Fprintf(w, "  duration:   %s\n", r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond))
	fmt.Fprintf(w, "  probes:     %s\n", r.probeSummary())
	if r.Status == StatusIncomplete {
		fmt.Fprintf(w, "\n  ! scan incomplete (%s) — absent findings are NOT clean results\n", r.IncompleteReason)
	}
	fmt.Fprintln(w)

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "  no findings.")
	}
	badges := map[Severity]string{
		SeverityHigh:   "[HIGH]  ",
		SeverityMedium: "[MED]   ",
		SeverityLow:    "[LOW]   ",
		SeverityInfo:   "[INFO]  ",
	}
	for _, f := range r.Findings {
		asi := ""
		if len(f.ASI) > 0 {
			asi = " (" + strings.Join(f.ASI, ", ") + ")"
		}
		fmt.Fprintf(w, "  %s%s%s\n", badges[f.Severity], f.Title, asi)
		fmt.Fprintf(w, "          %s\n", f.Description)
		if len(f.Evidence) > 0 {
			fmt.Fprintf(w, "          evidence:\n")
			keys := make([]string, 0, len(f.Evidence))
			for k := range f.Evidence {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, key := range keys {
				fmt.Fprintf(w, "            %s: %v\n", key, f.Evidence[key])
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "          fix: %s\n", f.Remediation)
		}
		fmt.Fprintln(w)
	}

	// Probes that couldn't run are listed explicitly — the whole point of
	// tracking status is that the reader sees the gaps.
	var degraded []ProbeRun
	for _, p := range r.Probes {
		if p.Status == ProbeError || p.Status == ProbeAborted {
			degraded = append(degraded, p)
		}
	}
	if len(degraded) > 0 {
		fmt.Fprintln(w, "  probes that could not complete:")
		for _, p := range degraded {
			detail := p.Detail
			if detail != "" {
				detail = ": " + detail
			}
			fmt.Fprintf(w, "    %s (%s)%s\n", p.ID, p.Status, detail)
		}
		fmt.Fprintln(w)
	}

	for _, e := range r.Errors {
		fmt.Fprintf(w, "  [error] %s\n", e)
	}
}

// probeSummary renders the per-status probe tally for the header line.
func (r *Report) probeSummary() string {
	if len(r.Probes) == 0 {
		return "none run"
	}
	counts := map[string]int{}
	for _, p := range r.Probes {
		counts[p.Status]++
	}
	parts := make([]string, 0, 4)
	for _, status := range []string{ProbeRan, ProbeNotApplicable, ProbeError, ProbeAborted} {
		if n := counts[status]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, status))
		}
	}
	return strings.Join(parts, ", ")
}

func describeAuthState(state string) string {
	switch state {
	case AuthStateOpen:
		return "open (capability enumeration answered without credentials)"
	case AuthStateGated:
		return "auth-gated (endpoint is live but requires credentials)"
	case AuthStateAuthed:
		return "authenticated (enumeration answered only with supplied credentials)"
	case AuthStateUnreached:
		return "unreached (endpoint never answered)"
	default:
		return "unknown"
	}
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
		rep.sortFindings()

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
				"properties": map[string]any{
					"target":   rep.Target.URL,
					"protocol": f.Protocol,
				},
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
			"automationDetails": map[string]any{
				"id": "reap/" + rep.Target.URL,
			},
			"invocations": []map[string]any{
				{
					"executionSuccessful": rep.Status == StatusComplete,
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

// uniqueFindingIDs returns unique finding IDs in order of first appearance.
func uniqueFindingIDs(findings []Finding) []string {
	seen := make(map[string]bool, len(findings))
	var ids []string
	for _, f := range findings {
		if !seen[f.ID] {
			ids = append(ids, f.ID)
			seen[f.ID] = true
		}
	}
	return ids
}

// severityToSARIFLevel maps reap severity to SARIF level.
func severityToSARIFLevel(sev Severity) string {
	switch sev {
	case SeverityHigh:
		return "error"
	case SeverityMedium:
		return "warning"
	default:
		return "note"
	}
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
