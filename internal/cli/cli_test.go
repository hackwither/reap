package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectTargets_FileAndStdin(t *testing.T) {
	fileContent := "https://one.example.com/mcp\n# comment\nhttps://two.example.com/mcp\n"
	filePath := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(filePath, []byte(fileContent), 0o600); err != nil {
		t.Fatal(err)
	}

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close(); _ = w.Close(); os.Stdin = origStdin }()
	os.Stdin = r
	_, _ = w.WriteString("https://three.example.com/mcp\n")
	_ = w.Close()

	targets, err := collectTargets(&Options{TargetsFile: filePath}, os.Stdout)
	if err != nil {
		t.Fatalf("collectTargets failed: %v", err)
	}
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets, got %d", len(targets))
	}
	if targets[0] != "https://one.example.com/mcp" || targets[1] != "https://two.example.com/mcp" || targets[2] != "https://three.example.com/mcp" {
		t.Fatalf("unexpected targets: %v", targets)
	}
}

func TestParseFlags_NoScopeFileFlag(t *testing.T) {
	_, _, err := parseFlags([]string{"--scope-file", "foo"})
	if err == nil {
		t.Fatal("expected parseFlags to error on removed --scope-file flag")
	}
}

func TestRun_UnauthorizedBatchRefusesBeforeNetwork(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "targets.txt")
	if err := os.WriteFile(filePath, []byte("https://example.com/mcp\nhttps://example.org/mcp\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout := os.NewFile(uintptr(1), "/dev/null")
	stderr := os.NewFile(uintptr(2), "/dev/null")
	code := Run([]string{"--targets-file", filePath}, stdout, stderr)
	if code != 1 {
		t.Fatalf("expected exit code 1 for unauthorized batch run, got %d", code)
	}
}

func TestParseFlags_Verbose(t *testing.T) {
	opts, _, err := parseFlags([]string{"-v", "--target", "https://example.com/mcp"})
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if opts == nil {
		t.Fatal("expected options, got nil")
	}
	if !opts.Verbose {
		t.Fatal("expected verbose enabled for -v")
	}
}
