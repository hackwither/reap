package probe

// The no-invoke boundary is the load-bearing claim of this whole tool: REAP
// enumerates an agent endpoint but never calls a capability it discovers. The
// Session interface deliberately ships no InvokeTool method, but Session.Do is
// a general JSON-RPC sender, so "no invoke method" is not by itself proof that
// nothing invokes — a probe could hand Do the method "tools/call" directly, and
// a JSON template could name it as its request method.
//
// This test is that proof. It statically scans every non-test Go source file
// and every bundled template/fingerprint in the repository and fails if any of
// them references an invoking protocol method. It is the test the positioning
// promises: adding an invoking code path turns the build red.
//
// If you are here because this test failed: you (or a template) referenced a
// method that invokes a discovered capability. That is not a lint to silence.
// Enumeration only. See docs/ARCHITECTURE.md; the correct design for "is this
// tool actually callable" is a schema-only DryRunCapabilityCheck, never a real
// invoke.

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// invokeMethods are protocol methods whose only purpose is to *call* a
// discovered capability, as opposed to enumerating one. This list is the
// machine-readable definition of the boundary. Add to it as new protocols gain
// invoke semantics (A2A message/send, and so on); never remove from it.
var invokeMethods = map[string]bool{
	"tools/call": true, // MCP: execute a discovered tool
}

// dirsToSkip are trees with no first-party source to police.
var dirsToSkip = map[string]bool{
	".git":         true,
	"dist":         true,
	"bin":          true,
	"testdata":     true,
	"node_modules": true,
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not locate repo root (no go.mod found walking up)")
		}
		dir = parent
	}
}

// TestNoInvokeMethodInSource fails if any non-test Go source references an
// invoking method as a string literal. Comments are not scanned, so prose that
// mentions "tools/call" to explain the boundary is fine; only real string
// literals in code count.
func TestNoInvokeMethodInSource(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	var offenders []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if dirsToSkip[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if invokeMethods[val] {
				rel, _ := filepath.Rel(root, path)
				pos := fset.Position(lit.Pos())
				offenders = append(offenders, rel+":"+strconv.Itoa(pos.Line))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk go sources: %v", err)
	}

	if len(offenders) > 0 {
		t.Fatalf("no-invoke boundary violated: invoking method used as a string literal in first-party source.\n"+
			"REAP enumerates, it never invokes. Remove the invoke path (see docs/ARCHITECTURE.md).\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// TestNoInvokeMethodInBundledData fails if any shipped template or fingerprint
// names an invoking method as its request method. Templates run through
// Session.Do just like Go probes, so a template is an invoke path too.
func TestNoInvokeMethodInBundledData(t *testing.T) {
	root := repoRoot(t)
	var offenders []string

	for _, sub := range []string{"templates", "fingerprints"} {
		dir := filepath.Join(root, sub)
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".json") {
				return nil
			}
			raw, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			var doc any
			if jerr := json.Unmarshal(raw, &doc); jerr != nil {
				return nil // malformed JSON is a different test's problem
			}
			rel, _ := filepath.Rel(root, path)
			if method := findRequestMethod(doc); invokeMethods[method] {
				offenders = append(offenders, rel+" (method="+method+")")
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", sub, err)
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("no-invoke boundary violated: a bundled template/fingerprint requests an invoking method.\n"+
			"A template that calls a discovered capability is exactly what the boundary forbids.\n  %s",
			strings.Join(offenders, "\n  "))
	}
}

// findRequestMethod returns the first invoking method it finds under any
// "method" key, at any depth. It walks the decoded JSON so a nested
// {"request": {"method": ...}} is caught the same as a top-level one.
func findRequestMethod(node any) string {
	switch v := node.(type) {
	case map[string]any:
		if m, ok := v["method"].(string); ok && invokeMethods[m] {
			return m
		}
		for _, child := range v {
			if got := findRequestMethod(child); got != "" {
				return got
			}
		}
	case []any:
		for _, child := range v {
			if got := findRequestMethod(child); got != "" {
				return got
			}
		}
	}
	return ""
}
