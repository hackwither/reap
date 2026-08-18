package mcp

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/hackwither/reap/internal/probe"
)

// Bounds on cursor-following. A hostile or buggy server can advertise a
// nextCursor forever; recon must not become an unbounded crawl.
const (
	maxListPages = 50
	maxListItems = 5000
)

// listResult is the accumulated outcome of a paginated MCP list call.
type listResult struct {
	// Items is every element gathered across pages.
	Items []map[string]any
	// Truncated is true when a page cap stopped collection early, meaning
	// len(Items) is a floor rather than the real total.
	Truncated bool
	// Pages is how many requests were needed.
	Pages int
	// FirstStatus and FirstHeaders come from the first page, for probes that
	// care about transport-level observations rather than the payload.
	FirstStatus  int
	FirstHeaders http.Header
	// RPCError is set when the server answered with a JSON-RPC error, which
	// is a substantive answer rather than a failure.
	RPCError *rpcError
}

// OK reports whether the list call produced a usable 200 payload.
func (l *listResult) OK() bool {
	return l != nil && l.FirstStatus == http.StatusOK && l.RPCError == nil
}

// listAll performs an MCP list call, following result.nextCursor to gather
// every page.
//
// reap previously issued a single tools/list and reported whatever came back
// as the complete inventory. MCP list methods are cursor-paginated, so on any
// server with more tools than one page holds, the headline "full tool
// inventory" was silently truncated. Since capability surface is the primary
// recon output, that undercount mattered more than most bugs.
//
// itemsField names the array to collect ("tools", "resources", "prompts"). An
// empty itemsField collects every array field found in result, which is what
// the resources/prompts exposure check wants.
//
// This lives here rather than on probe.Session deliberately: paging is a
// read-only convenience over Do, and probe.Session stays minimal because it is
// the type that enforces reap's no-invoke boundary.
func listAll(ctx context.Context, s probe.Session, method, itemsField string, opts ...probe.ReqOption) (*listResult, error) {
	out := &listResult{}
	cursor := ""

	for page := 0; page < maxListPages; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}

		raw, err := s.Do(ctx, method, params, opts...)
		if err != nil {
			if page == 0 {
				return nil, err
			}
			// Lost a later page: keep what we have, but say so.
			out.Truncated = true
			return out, nil
		}
		out.Pages = page + 1
		if page == 0 {
			out.FirstStatus = raw.StatusCode
			out.FirstHeaders = raw.Headers
		}

		var envelope struct {
			Result map[string]json.RawMessage `json:"result"`
			Error  *rpcError                  `json:"error"`
		}
		if err := json.Unmarshal(raw.Body, &envelope); err != nil {
			if page == 0 {
				return out, nil // non-JSON body: caller sees FirstStatus and no items
			}
			out.Truncated = true
			return out, nil
		}
		if envelope.Error != nil {
			if page == 0 {
				out.RPCError = envelope.Error
				return out, nil
			}
			out.Truncated = true
			return out, nil
		}

		out.Items = append(out.Items, collectItems(envelope.Result, itemsField)...)
		if len(out.Items) >= maxListItems {
			out.Items = out.Items[:maxListItems]
			out.Truncated = true
			return out, nil
		}

		cursor = decodeCursor(envelope.Result["nextCursor"])
		if cursor == "" {
			return out, nil
		}
	}

	out.Truncated = true
	return out, nil
}

// collectItems pulls objects out of one result payload.
func collectItems(result map[string]json.RawMessage, itemsField string) []map[string]any {
	var items []map[string]any

	decode := func(raw json.RawMessage) {
		var arr []map[string]any
		if json.Unmarshal(raw, &arr) == nil {
			items = append(items, arr...)
		}
	}

	if itemsField != "" {
		if raw, ok := result[itemsField]; ok {
			decode(raw)
		}
		return items
	}
	for field, raw := range result {
		if field == "nextCursor" {
			continue
		}
		decode(raw)
	}
	return items
}

func decodeCursor(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

// toolNames extracts the name field from a list of tool objects.
func toolNames(items []map[string]any) []string {
	names := make([]string, 0, len(items))
	for _, t := range items {
		if n, ok := t["name"].(string); ok {
			names = append(names, n)
		}
	}
	return names
}
