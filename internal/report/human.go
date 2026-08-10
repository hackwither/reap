package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiRed     = "\x1b[31m"
	ansiYellow  = "\x1b[33m"
	ansiBlue    = "\x1b[34m"
	ansiCyan    = "\x1b[36m"
	ansiGreen   = "\x1b[32m"
	ansiMagenta = "\x1b[35m"
)

type humanRenderer struct {
	w       io.Writer
	color   bool
	verbose bool
}

// WriteHumanColor writes REAP's endpoint dossier. Color affects only ANSI
// styling; the content and layout stay identical for files and pipelines.
func (r *Report) WriteHumanColor(w io.Writer, color bool) {
	r.WriteHumanDossier(w, color, true)
}

// WriteHumanDossier controls both terminal styling and detail density.
// Non-verbose mode keeps findings concise; verbose mode includes every
// reproduction command, matcher detail, expected response, and reference.
func (r *Report) WriteHumanDossier(w io.Writer, color, verbose bool) {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return severityRank[r.Findings[i].Severity] > severityRank[r.Findings[j].Severity]
	})
	h := humanRenderer{w: w, color: color, verbose: verbose}
	h.report(r)
}

func (h humanRenderer) paint(code, s string) string {
	if !h.color {
		return s
	}
	return code + s + ansiReset
}

func (h humanRenderer) section(title string) {
	fmt.Fprintf(h.w, "\n %s\n", h.paint(ansiBold+ansiCyan, title))
}

func (h humanRenderer) report(r *Report) {
	version := r.Version
	if version == "" {
		version = "dev"
	}
	fmt.Fprintf(h.w, "\n %s  %s  %s\n",
		h.paint(ansiBold+ansiMagenta, "REAP"),
		h.paint(ansiDim, "/"),
		h.paint(ansiBold, "AI AGENT RECON"))
	fmt.Fprintf(h.w, " %s\n", h.paint(ansiDim, strings.Repeat("─", 68)))
	fmt.Fprintf(h.w, " %s\n", h.paint(ansiDim, "v"+version))

	h.section("TARGET")
	fmt.Fprintf(h.w, " %s\n", h.paint(ansiBold, valueOr(r.Target.URL, "unknown")))
	var identity []string
	if r.Target.ResolvedIP != "" {
		identity = append(identity, r.Target.ResolvedIP)
	}
	if r.Target.Protocol != "" {
		proto := strings.ToUpper(r.Target.Protocol)
		if r.Target.ProtocolVer != "" {
			proto += " " + r.Target.ProtocolVer
		}
		identity = append(identity, proto)
	}
	if r.Target.Transport != "" {
		identity = append(identity, displayName(r.Target.Transport))
	}
	state := "UNCONFIRMED"
	stateColor := ansiYellow
	switch {
	case r.Target.ConfirmState == ConfirmStateAuthGated:
		state, stateColor = "CONFIRMED (AUTH-GATED)", ansiGreen
	case r.Target.Confirmed:
		state, stateColor = "CONFIRMED", ansiGreen
	}
	identity = append(identity, h.paint(ansiBold+stateColor, state))
	fmt.Fprintf(h.w, " %s\n", strings.Join(identity, "  •  "))

	h.fact("Agent", strings.TrimSpace(r.Target.ServerName+" "+r.Target.ServerVer))
	h.fact("Edge", r.Target.EdgeServer)
	h.fact("TLS", r.Target.TLSSummary)
	discovery := r.Target.DiscoveryMethod
	if r.Target.DiscoveryConfidence != "" {
		if discovery != "" {
			discovery += "  •  "
		}
		discovery += r.Target.DiscoveryConfidence + " confidence"
	}
	h.fact("Discovery", discovery)

	if !r.Target.Confirmed && r.Target.ConfirmReason != "" {
		fmt.Fprintf(h.w, "\n %s\n", h.paint(ansiBold+ansiYellow, "⚠ TARGET NOT CONFIRMED AS AN AGENT ENDPOINT"))
		fmt.Fprintf(h.w, " %s\n", r.Target.ConfirmReason)
		fmt.Fprintf(h.w, " Findings are low confidence and may describe a generic web server.\n")
	}
	if r.Target.ConfirmState == ConfirmStateAuthGated && r.Target.ConfirmReason != "" {
		fmt.Fprintf(h.w, "\n %s\n", h.paint(ansiBold+ansiCyan, "ⓘ AUTH REQUIRED"))
		fmt.Fprintf(h.w, " %s\n", r.Target.ConfirmReason)
	}

	detailHint := ""
	if !h.verbose && len(r.Findings) > 0 {
		detailHint = "  •  use -v for full evidence"
	}
	h.section(fmt.Sprintf("FINDINGS  %s", h.paint(ansiDim, fmt.Sprintf("%d matched%s", len(r.Findings), detailHint))))
	if len(r.Findings) == 0 {
		fmt.Fprintf(h.w, " %s No security findings detected.\n", h.paint(ansiGreen, "✓"))
	} else {
		for _, f := range r.Findings {
			h.finding(f)
		}
	}

	h.section("POSTURE")
	posture := r.posture()
	fmt.Fprintf(h.w, " %s\n", h.paint(ansiBold+severityColor(posture), postureLabel(posture)))
	duration := r.FinishedAt.Sub(r.StartedAt).Round(time.Millisecond)
	if r.StartedAt.IsZero() || r.FinishedAt.IsZero() {
		duration = 0
	}
	fmt.Fprintf(h.w, "\n %d checks  •  %d matched  •  %d clean  •  %d skipped  •  %s\n",
		r.Coverage.Total, r.Coverage.Fired, r.Coverage.Clean, r.Coverage.Skipped, duration)
	fmt.Fprintf(h.w, " %s\n", r.summaryLine())
	for _, e := range r.Errors {
		fmt.Fprintf(h.w, " %s %s\n", h.paint(ansiRed, "ERROR"), e)
	}
}

func (h humanRenderer) fact(label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(h.w, " %-11s %s\n", label, value)
}

// isEmptyEvidenceValue reports whether a Details row's value is nil or an
// empty/whitespace-only string — the same definition of "empty" fact()
// already uses, applied here so a dangling label with no value (e.g.
// www_authenticate: "") is skipped instead of rendered.
func isEmptyEvidenceValue(v any) bool {
	if v == nil {
		return true
	}
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s) == ""
	}
	return false
}

func (h humanRenderer) finding(f Finding) {
	severity := strings.ToUpper(string(f.Severity))
	if severity == "MEDIUM" {
		severity = "MED"
	}
	confidence := ""
	if f.Confidence != "" {
		confidence = "  " + strings.ToUpper(f.Confidence) + " CONFIDENCE"
	}
	fmt.Fprintf(h.w, "\n %s %s%s\n",
		h.paint(ansiBold+severityColor(strings.ToUpper(string(f.Severity))), severity),
		h.paint(ansiBold, f.ID),
		h.paint(ansiDim, confidence))
	fmt.Fprintf(h.w, " %s\n", h.paint(ansiBold, f.Title))
	if f.Description != "" {
		fmt.Fprintf(h.w, " %s\n", f.Description)
	}
	if f.Request != nil {
		exchange := fmt.Sprintf("%s %s → %d", f.Request.Method, f.Request.URL, f.Request.StatusCode)
		if f.Request.ContentType != "" {
			exchange += "  •  " + f.Request.ContentType
		}
		if f.Request.BodySize > 0 {
			exchange += "  •  " + humanBytes(f.Request.BodySize)
		}
		h.fact("Evidence", exchange)
		if h.verbose && f.Request.Expected != "" {
			h.fact("Expected", f.Request.Expected)
		}
		if h.verbose {
			h.fact("Reproduce", f.Request.Curl())
		}
	}
	if h.verbose && len(f.Evidence) > 0 {
		keys := make([]string, 0, len(f.Evidence))
		for key := range f.Evidence {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		var visible []string
		for _, key := range keys {
			if isEmptyEvidenceValue(f.Evidence[key]) {
				continue
			}
			if key == "status_code" && f.Request != nil && fmt.Sprintf("%v", f.Evidence[key]) == fmt.Sprintf("%d", f.Request.StatusCode) {
				continue // already shown on the Evidence line above
			}
			visible = append(visible, key)
		}
		if len(visible) > 0 {
			fmt.Fprintf(h.w, " %-11s\n", "Details")
			for _, key := range visible {
				val := f.Evidence[key]
				if isCompoundEvidence(val) {
					fmt.Fprintf(h.w, "   %s:\n", displayName(key))
					renderEvidenceValue(h.w, "     ", val)
				} else {
					fmt.Fprintf(h.w, "   %-17s %v\n", displayName(key), val)
				}
			}
		}
	}
	if len(f.ASI) > 0 {
		h.fact("OWASP", joinASITitled(f.ASI))
	}
	h.fact("Fix", f.Remediation)
	if h.verbose && len(f.References) > 0 {
		h.fact("References", strings.Join(f.References, ", "))
	}
}

func (r *Report) posture() string {
	if !r.Target.Confirmed && len(r.Findings) > 0 {
		return "INFO"
	}
	for _, severity := range []Severity{SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo} {
		for _, f := range r.Findings {
			if f.Severity == severity {
				return strings.ToUpper(string(severity))
			}
		}
	}
	if len(r.Errors) > 0 {
		return "ERROR"
	}
	return "CLEAN"
}

func severityColor(severity string) string {
	switch severity {
	case "HIGH", "ERROR":
		return ansiRed
	case "MEDIUM", "MED":
		return ansiYellow
	case "LOW":
		return ansiBlue
	case "INFO":
		return ansiCyan
	default:
		return ansiGreen
	}
}

func postureLabel(posture string) string {
	switch posture {
	case "CLEAN":
		return "CLEAN"
	case "ERROR":
		return "SCAN ERROR"
	case "INFO":
		return "INFORMATIONAL"
	default:
		return posture + " RISK"
	}
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func displayName(value string) string {
	return strings.ReplaceAll(value, "_", " ")
}
