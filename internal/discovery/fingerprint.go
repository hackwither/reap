// Fingerprints are Discovery's answer to the same question templates already
// answer for Assessment: let contributors add a check without touching Go.
// A FingerprintTemplate describes one request (against a raw Candidate, not
// an established probe.Session — none exists yet at discovery time) and a
// set of matchers reused verbatim from internal/template's matcher engine.
//
// Like templates, this is deliberately not Turing-complete: one request, no
// chaining, no branching. Some signals (e.g. confirming legacy-SSE MCP by
// following the endpoint the server announces mid-stream) genuinely need a
// follow-up request — those stay hand-written Go Detectors, exactly the way
// anything needing more than one request stays a hand-written Go Probe for
// Assessment. See docs/ARCHITECTURE.md.
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/hackwither/reap/internal/probe"
	"github.com/hackwither/reap/internal/template"
)

// FPRequest describes the single raw HTTP request a fingerprint sends.
// Unlike template.Request (which dispatches a JSON-RPC method through an
// already-negotiated probe.Session), this has no Session to lean on — it
// specifies the HTTP verb directly, and optionally wraps the body as a
// JSON-RPC envelope when RPCMethod is set.
type FPRequest struct {
	HTTPMethod string            `json:"http_method"`          // GET|POST (default GET)
	RPCMethod  string            `json:"rpc_method,omitempty"` // if set, body becomes a JSON-RPC {jsonrpc,id,method,params} envelope and HTTPMethod is forced to POST
	Params     map[string]any    `json:"params,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

// FingerprintTemplate is the JSON-loadable, declarative equivalent of a
// hand-written Detector.
type FingerprintTemplate struct {
	ID         string             `json:"id"`
	Protocol   string             `json:"protocol"`
	Transport  string             `json:"transport"`
	Kinds      []CandidateKind    `json:"kinds"`
	Paths      []string           `json:"paths,omitempty"` // tried against KindHostPort candidates; KindURL uses Candidate.URL as-is
	Request    FPRequest          `json:"request"`
	Matchers   []template.Matcher `json:"matchers"`
	MatchLogic string             `json:"match_logic,omitempty"` // "any" (default) or "all"
	OnMatch    string             `json:"on_match_confidence"`   // "high"|"medium"|"low"
	Extract    map[string]string  `json:"extract,omitempty"`     // Fingerprint field name -> json_path, e.g. "server_name": "result.serverInfo.name"
}

// LoadFingerprintDir walks dir for *.json fingerprints and returns the
// parsed set, skipping (and reporting) any file that fails to parse rather
// than aborting the whole load — mirrors template.LoadDir exactly.
func LoadFingerprintDir(dir string) ([]*FingerprintTemplate, []error) {
	var out []*FingerprintTemplate
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
		var t FingerprintTemplate
		if err := json.Unmarshal(data, &t); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", path, err))
			return nil
		}
		if t.ID == "" || len(t.Kinds) == 0 {
			errs = append(errs, fmt.Errorf("%s: fingerprint missing required id/kinds", path))
			return nil
		}
		out = append(out, &t)
		return nil
	})
	return out, errs
}

// AsDetector adapts a FingerprintTemplate to the Detector interface, so the
// CLI treats hand-written Go detectors and data-driven fingerprints
// identically — the same relationship template.Template.AsProbe() has to
// probe.Probe.
func (t *FingerprintTemplate) AsDetector() Detector {
	return &fingerprintDetector{t: t}
}

type fingerprintDetector struct{ t *FingerprintTemplate }

func (d *fingerprintDetector) ID() string             { return d.t.ID }
func (d *fingerprintDetector) Kinds() []CandidateKind { return d.t.Kinds }

func (d *fingerprintDetector) Detect(ctx context.Context, c Candidate, opts DetectOptions) (*Fingerprint, error) {
	t := d.t
	for _, url := range t.candidateURLs(c) {
		raw, err := doFingerprintRequest(ctx, url, t.Request, opts)
		if err != nil {
			continue // unreachable candidate URL is not a Detector failure
		}

		var decoded any
		_ = json.Unmarshal(raw.Body, &decoded) // best-effort; body_contains/status matchers don't need this

		matchAll := strings.EqualFold(t.MatchLogic, "all")
		matched := matchAll // start true for AND, false for OR — same convention as internal/template
		var evidence []map[string]any
		for _, m := range t.Matchers {
			ok, ev := template.EvalMatcher(m, raw, decoded)
			if matchAll {
				matched = matched && ok
			} else if ok {
				matched = true
			}
			if ok {
				evidence = append(evidence, ev)
			}
		}
		if len(t.Matchers) > 0 && !matched {
			continue
		}

		matchedCandidate := c
		if matchedCandidate.URL == "" {
			matchedCandidate.URL = url
		}

		fp := &Fingerprint{
			Candidate:  matchedCandidate,
			Protocol:   t.Protocol,
			Transport:  t.Transport,
			Confidence: t.OnMatch,
			Evidence:   map[string]any{"matchers": evidence, "status_code": raw.StatusCode, "url": url},
			DetectorID: t.ID,
		}
		applyExtract(fp, t.Extract, decoded)
		return fp, nil
	}
	return nil, nil
}

// applyExtract pulls named fields (server_name, server_ver, protocol_ver)
// out of the decoded body via json_path, so a data-driven fingerprint can
// populate the same structured Fingerprint fields a hand-written Go
// detector would — confirming a match without surfacing what server it
// found would be a real loss of information, not just a cosmetic gap.
func applyExtract(fp *Fingerprint, extract map[string]string, decoded any) {
	for field, path := range extract {
		values := template.ResolveJSONPath(decoded, path)
		if len(values) == 0 {
			continue
		}
		s := fmt.Sprintf("%v", values[0])
		switch field {
		case "server_name":
			fp.ServerName = s
		case "server_ver":
			fp.ServerVer = s
		case "protocol_ver":
			fp.ProtocolVer = s
		}
	}
}

// candidateURLs returns the URL(s) to try for c, in order, stopping at the
// first one that satisfies the fingerprint's matchers. KindURL candidates
// are tried as-is; KindHostPort candidates are expanded against t.Paths (or
// the shared MCPWellKnownPaths if none given) under both http and https.
func (t *FingerprintTemplate) candidateURLs(c Candidate) []string {
	switch c.Kind {
	case KindURL:
		if c.URL == "" {
			return nil
		}
		return []string{c.URL}
	case KindHostPort:
		base := c.RawInput
		if c.Host != "" {
			if c.Port != 0 {
				base = fmt.Sprintf("%s:%d", c.Host, c.Port)
			} else {
				base = c.Host
			}
		}
		if base == "" {
			return nil
		}
		paths := t.Paths
		if len(paths) == 0 {
			paths = MCPWellKnownPaths
		}
		var urls []string
		for _, scheme := range []string{"https", "http"} {
			for _, p := range paths {
				urls = append(urls, scheme+"://"+base+p)
			}
		}
		return urls
	default:
		return nil
	}
}

func doFingerprintRequest(ctx context.Context, url string, req FPRequest, opts DetectOptions) (*probe.RawResult, error) {
	method := req.HTTPMethod
	if method == "" {
		method = http.MethodGet
	}

	var bodyReader io.Reader
	headers := make(map[string]string, len(req.Headers)+1)
	for k, v := range req.Headers {
		headers[k] = v
	}

	if req.RPCMethod != "" {
		method = http.MethodPost
		payload := map[string]any{"jsonrpc": "2.0", "id": 1, "method": req.RPCMethod}
		if req.Params != nil {
			payload["params"] = req.Params
		}
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("encode fingerprint request: %w", err)
		}
		bodyReader = bytes.NewReader(body)
		if _, ok := headers["Content-Type"]; !ok {
			headers["Content-Type"] = "application/json"
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build fingerprint request: %w", err)
	}
	for k, v := range headers {
		httpReq.Header.Set(k, v)
	}
	if opts.AuthHeader != "" {
		httpReq.Header.Set("Authorization", opts.AuthHeader)
	}

	client := &http.Client{Timeout: opts.Timeout}
	start := time.Now()
	resp, err := client.Do(httpReq)
	latency := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 4<<20) // 4MB cap, same discipline as mcp.Session.Do
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	return &probe.RawResult{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		Latency:    latency,
	}, nil
}
