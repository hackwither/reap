// Package template implements agentrecon's contribution format: a
// declarative, no-code way to add a new check.
//
// This is deliberately modeled on nuclei's YAML templates, but written as
// JSON for v1 so the loader has zero external dependencies (no YAML lib
// available in this build environment). Swapping the outer format to YAML
// later is a small, isolated change — see docs/WRITING_PROBES.md — the
// Template struct and matcher engine below don't change.
//
// A template describes ONE request and one or more matchers over the
// response. It cannot chain requests, cannot invoke a discovered tool, and
// cannot branch on results — that's an intentional ceiling, not a
// limitation we forgot to lift. Anything that needs more belongs in a
// hand-written Go probe (see internal/probe/mcp/checks.go) where the
// safety constraints are explicit in code, not merely in a schema.
package template

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hackwither/agentrecon/internal/probe"
	"github.com/hackwither/agentrecon/internal/report"
)

type Template struct {
	ID         string    `json:"id"`
	Protocol   string    `json:"protocol"`
	Info       Info      `json:"info"`
	Request    Request   `json:"request"`
	Matchers   []Matcher `json:"matchers"`
	MatchLogic string    `json:"match_logic,omitempty"` // "any" (default) or "all"
}

type Info struct {
	Title       string   `json:"title"`
	Severity    string   `json:"severity"` // info|low|medium|high
	ASIRefs     []string `json:"asi_refs,omitempty"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Author      string   `json:"author,omitempty"`
}

type Request struct {
	Method  string            `json:"method"`
	Params  map[string]any    `json:"params,omitempty"`
	NoAuth  bool              `json:"no_auth,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

// Matcher is a small, closed set of checks over a RawResult. Deliberately
// not Turing-complete — see the package doc for why.
type Matcher struct {
	Type string `json:"type"` // status_code | header | body_contains | json_path

	// status_code
	Equals int `json:"equals,omitempty"`

	// header
	Header   string `json:"header,omitempty"`
	Value    string `json:"value,omitempty"`
	Contains string `json:"contains,omitempty"`

	// body_contains
	AnyOf []string `json:"any_of,omitempty"`

	// json_path
	Path          string `json:"path,omitempty"`
	MinCount      int    `json:"min_count,omitempty"`
	ValueContains bool   `json:"value_contains,omitempty"` // if true, any_of does case-insensitive substring match instead of exact match
}

// LoadDir walks dir for *.json templates and returns the parsed set,
// skipping (and reporting) any file that fails to parse rather than
// aborting the whole load — one bad template shouldn't take down a scan.
func LoadDir(dir string) ([]*Template, []error) {
	var templates []*Template
	var errs []error

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".json") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}
		var t Template
		if err := json.Unmarshal(data, &t); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}
		if t.ID == "" || t.Request.Method == "" {
			errs = append(errs, fmt.Errorf("%s: template missing required id/request.method", path))
			return nil
		}
		templates = append(templates, &t)
		return nil
	})
	return templates, errs
}

// AsProbe adapts a Template to the probe.Probe interface so the CLI can
// treat built-in and template-defined checks identically.
func (t *Template) AsProbe() probe.Probe {
	return &templateProbe{t: t}
}

type templateProbe struct{ t *Template }

func (p *templateProbe) ID() string       { return p.t.ID }
func (p *templateProbe) Protocol() string { return p.t.Protocol }

func (p *templateProbe) Run(ctx context.Context, s probe.Session, r *report.Report) error {
	t := p.t
	var opts []probe.ReqOption
	if t.Request.NoAuth {
		opts = append(opts, probe.WithNoAuth())
	}
	for k, v := range t.Request.Headers {
		opts = append(opts, probe.WithHeader(k, v))
	}

	raw, err := s.Do(ctx, t.Request.Method, t.Request.Params, opts...)
	if err != nil {
		return nil // connection-level failure isn't a template match failure
	}

	var decoded any
	_ = json.Unmarshal(raw.Body, &decoded) // best-effort; body_contains/status matchers don't need this

	matchAll := strings.EqualFold(t.MatchLogic, "all")
	matched := matchAll // start true for AND, false for OR
	var matchEvidence []map[string]any

	for _, m := range t.Matchers {
		ok, ev := evalMatcher(m, raw, decoded)
		if matchAll {
			matched = matched && ok
		} else if ok {
			matched = true
		}
		if ok {
			matchEvidence = append(matchEvidence, ev)
		}
	}

	if len(t.Matchers) > 0 && !matched {
		return nil
	}

	r.AddFinding(report.Finding{
		ID:          t.ID,
		Title:       t.Info.Title,
		Severity:    report.Severity(t.Info.Severity),
		Protocol:    t.Protocol,
		ASI:         t.Info.ASIRefs,
		Description: t.Info.Description,
		Evidence:    map[string]any{"matchers": matchEvidence, "status_code": raw.StatusCode},
		Remediation: t.Info.Remediation,
		Source:      "template:" + t.ID,
		Tags:        t.Info.Tags,
	})
	return nil
}

func evalMatcher(m Matcher, raw *probe.RawResult, decoded any) (bool, map[string]any) {
	switch m.Type {
	case "status_code":
		return raw.StatusCode == m.Equals, map[string]any{"type": m.Type, "got": raw.StatusCode}

	case "header":
		got := ""
		if raw.Headers != nil {
			if vs, ok := raw.Headers[canonicalHeader(m.Header)]; ok && len(vs) > 0 {
				got = vs[0]
			}
		}
		if m.Value != "" {
			return got == m.Value, map[string]any{"type": m.Type, "header": m.Header, "got": got}
		}
		if m.Contains != "" {
			return strings.Contains(strings.ToLower(got), strings.ToLower(m.Contains)), map[string]any{"type": m.Type, "header": m.Header, "got": got}
		}
		return got != "", map[string]any{"type": m.Type, "header": m.Header, "got": got}

	case "body_contains":
		body := strings.ToLower(string(raw.Body))
		for _, needle := range m.AnyOf {
			if strings.Contains(body, strings.ToLower(needle)) {
				return true, map[string]any{"type": m.Type, "matched": needle}
			}
		}
		return false, nil

	case "json_path":
		values := resolvePath(decoded, splitPath(m.Path))
		if m.MinCount > 0 {
			return len(values) >= m.MinCount, map[string]any{"type": m.Type, "path": m.Path, "count": len(values)}
		}
		if len(m.AnyOf) > 0 {
			for _, v := range values {
				s := fmt.Sprintf("%v", v)
				for _, want := range m.AnyOf {
					if m.ValueContains {
						if strings.Contains(strings.ToLower(s), strings.ToLower(want)) {
							return true, map[string]any{"type": m.Type, "path": m.Path, "matched": s, "against": want}
						}
					} else if strings.EqualFold(s, want) {
						return true, map[string]any{"type": m.Type, "path": m.Path, "matched": s}
					}
				}
			}
			return false, nil
		}
		return len(values) > 0, map[string]any{"type": m.Type, "path": m.Path, "count": len(values)}
	}
	return false, nil
}

func canonicalHeader(h string) string {
	// Go's http.Header keys are canonicalized (e.g. "Access-Control-Allow-Origin").
	parts := strings.Split(strings.ToLower(h), "-")
	for i, p := range parts {
		if len(p) > 0 {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, ".")
}

// resolvePath walks a decoded JSON value following dotted path segments.
// "*" as a segment means "iterate every element of the current array (or
// every value of the current map) and continue resolving the remaining
// path against each" — this is what lets a template say
// "result.tools.*.name" to pull every tool's name out of a list.
func resolvePath(data any, path []string) []any {
	if len(path) == 0 {
		if data == nil {
			return nil
		}
		return []any{data}
	}
	seg, rest := path[0], path[1:]

	if seg == "*" {
		switch v := data.(type) {
		case []any:
			var out []any
			for _, item := range v {
				out = append(out, resolvePath(item, rest)...)
			}
			return out
		case map[string]any:
			var out []any
			for _, item := range v {
				out = append(out, resolvePath(item, rest)...)
			}
			return out
		}
		return nil
	}

	switch v := data.(type) {
	case map[string]any:
		next, ok := v[seg]
		if !ok {
			return nil
		}
		return resolvePath(next, rest)
	case []any:
		// allow numeric index segments, e.g. "result.tools.0.name"
		if idx, err := strconv.Atoi(seg); err == nil && idx >= 0 && idx < len(v) {
			return resolvePath(v[idx], rest)
		}
		return nil
	}
	return nil
}
