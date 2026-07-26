package template

import (
	"testing"

	"github.com/hackwither/agentrecon/internal/probe"
)

func TestResolvePath(t *testing.T) {
	data := map[string]any{
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "read_file"},
				map[string]any{"name": "exec_shell"},
			},
			"serverInfo": map[string]any{"name": "example-gateway"},
		},
	}

	cases := []struct {
		path string
		want []any
	}{
		{"result.serverInfo.name", []any{"example-gateway"}},
		{"result.tools.*.name", []any{"read_file", "exec_shell"}},
		{"result.tools.0.name", []any{"read_file"}},
		{"result.nonexistent", nil},
	}

	for _, c := range cases {
		got := resolvePath(data, splitPath(c.path))
		if len(got) != len(c.want) {
			t.Fatalf("path %q: got %v, want %v", c.path, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("path %q: element %d = %v, want %v", c.path, i, got[i], c.want[i])
			}
		}
	}
}

func TestEvalMatcher_JSONPathAnyOf(t *testing.T) {
	decoded := map[string]any{
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "read_file"},
				map[string]any{"name": "exec_shell"},
			},
		},
	}
	m := Matcher{Type: "json_path", Path: "result.tools.*.name", AnyOf: []string{"exec_shell"}}
	ok, _ := evalMatcher(m, &probe.RawResult{Body: []byte(`{}`)}, decoded)
	if !ok {
		t.Fatal("expected match on exec_shell tool name, got none")
	}

	m2 := Matcher{Type: "json_path", Path: "result.tools.*.name", AnyOf: []string{"does_not_exist"}}
	ok2, _ := evalMatcher(m2, &probe.RawResult{Body: []byte(`{}`)}, decoded)
	if ok2 {
		t.Fatal("expected no match for absent tool name")
	}
}

func TestEvalMatcher_BodyContains(t *testing.T) {
	m := Matcher{Type: "body_contains", AnyOf: []string{"SECRET_KEY"}}
	ok, _ := evalMatcher(m, &probe.RawResult{Body: []byte(`{"note":"contains SECRET_KEY leak"}`)}, nil)
	if !ok {
		t.Fatal("expected body_contains match")
	}
}

// Regression test: json_path any_of must support substring matching for
// tool names like "exec_shell", which won't equal a hint word like "exec"
// exactly. This bug was caught by running the tool end-to-end against a
// mock server before shipping — see templates/mcp/high-risk-tool-names.json.
func TestEvalMatcher_JSONPath_ValueContains(t *testing.T) {
	decoded := map[string]any{
		"result": map[string]any{
			"tools": []any{
				map[string]any{"name": "exec_shell"},
				map[string]any{"name": "send_email"},
			},
		},
	}
	exact := Matcher{Type: "json_path", Path: "result.tools.*.name", AnyOf: []string{"exec"}}
	if ok, _ := evalMatcher(exact, &probe.RawResult{}, decoded); ok {
		t.Fatal("exact-match mode should NOT match 'exec_shell' against 'exec'")
	}

	substring := Matcher{Type: "json_path", Path: "result.tools.*.name", AnyOf: []string{"exec"}, ValueContains: true}
	if ok, _ := evalMatcher(substring, &probe.RawResult{}, decoded); !ok {
		t.Fatal("value_contains mode should match 'exec_shell' against 'exec'")
	}
}
