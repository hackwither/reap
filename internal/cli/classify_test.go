package cli

import (
	"testing"

	"github.com/hackwither/reap/internal/discovery"
)

// TestClassifyCandidate_BareOriginGetsPathExpansion is a regression test for
// a real discovery miss: "https://api.x.com" (a bare origin, no path) was
// classified as KindURL and tried verbatim, so well-known-path expansion
// (which only applies to KindHostPort) never ran and the real endpoint
// (.../mcp) was never found. A bare origin must classify as KindHostPort so
// expansion gets a chance.
func TestClassifyCandidate_BareOriginGetsPathExpansion(t *testing.T) {
	c := classifyCandidate("https://api.x.com")
	if c.Kind != discovery.KindHostPort {
		t.Fatalf("expected bare origin to classify as KindHostPort, got %v", c.Kind)
	}
	if c.Host != "api.x.com" {
		t.Fatalf("expected Host=api.x.com, got %q", c.Host)
	}
	if c.Port != 0 {
		t.Fatalf("expected no explicit port, got %d", c.Port)
	}
}

func TestClassifyCandidate_BareOriginWithPort(t *testing.T) {
	c := classifyCandidate("http://localhost:8080")
	if c.Kind != discovery.KindHostPort {
		t.Fatalf("expected KindHostPort, got %v", c.Kind)
	}
	if c.Host != "localhost" || c.Port != 8080 {
		t.Fatalf("expected host=localhost port=8080, got host=%q port=%d", c.Host, c.Port)
	}
}

// TestClassifyCandidate_FullEndpointURLStaysAsIs confirms a URL that
// already names a real path (the user telling reap exactly where the
// endpoint is) is NOT reclassified — expansion would be wrong here, the
// user already gave the answer.
func TestClassifyCandidate_FullEndpointURLStaysAsIs(t *testing.T) {
	c := classifyCandidate("https://api.x.com/mcp")
	if c.Kind != discovery.KindURL {
		t.Fatalf("expected KindURL for a fully-specified endpoint, got %v", c.Kind)
	}
	if c.URL != "https://api.x.com/mcp" {
		t.Fatalf("expected URL preserved as-is, got %q", c.URL)
	}
}

func TestClassifyCandidate_BareHostPortNoScheme(t *testing.T) {
	c := classifyCandidate("api.x.com:443")
	if c.Kind != discovery.KindHostPort {
		t.Fatalf("expected KindHostPort, got %v", c.Kind)
	}
	if c.RawInput != "api.x.com:443" {
		t.Fatalf("expected RawInput preserved, got %q", c.RawInput)
	}
}
