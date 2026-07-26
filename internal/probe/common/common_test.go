package common

import (
	"net/http"
	"testing"
)

func TestIsCORSWildcard(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Credentials", "true")

	wildcard, credentialed := IsCORSWildcard(headers)
	if !wildcard {
		t.Fatal("expected wildcard CORS to be detected")
	}
	if !credentialed {
		t.Fatal("expected credentialed wildcard CORS to be detected")
	}
}

func TestHasRateLimitHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-RateLimit-Remaining", "10")

	if !HasRateLimitHeader(headers) {
		t.Fatal("expected rate limit header detection")
	}
}

func TestIsPlaintextURL(t *testing.T) {
	if !IsPlaintextURL("http://example.test") {
		t.Fatal("expected plaintext URL to be true")
	}
	if IsPlaintextURL("https://example.test") {
		t.Fatal("expected HTTPS URL to be false")
	}
}
