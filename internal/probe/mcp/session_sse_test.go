package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newLegacySSEServer builds a minimal legacy-SSE MCP mock: GET /sse opens a
// stream that announces /messages as the POST endpoint, then delivers every
// POST's JSON-RPC result back over that same open stream (the async
// delivery path the legacy transport spec describes) rather than in the
// POST's own HTTP response (which answers 202 with an empty body, as real
// legacy servers commonly do).
func newLegacySSEServer(t *testing.T) *httptest.Server {
	t.Helper()
	type pendingReq struct {
		id     int
		method string
	}
	msgCh := make(chan pendingReq, 8)
	var flusher http.Flusher
	var sseWriter http.ResponseWriter

	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("ResponseWriter doesn't support flushing")
		}
		flusher = f
		sseWriter = w
		fmt.Fprintf(w, "event: endpoint\ndata: /messages\n\n")
		f.Flush()

		for {
			select {
			case req := <-msgCh:
				result := map[string]any{"jsonrpc": "2.0", "id": req.id, "result": map[string]any{"echo": req.method}}
				body, _ := json.Marshal(result)
				fmt.Fprintf(sseWriter, "event: message\ndata: %s\n\n", body)
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		msgCh <- pendingReq{id: body.ID, method: body.Method}
		w.WriteHeader(http.StatusAccepted) // no synchronous body — forces the async SSE delivery path
	})

	return httptest.NewServer(mux)
}

func TestSSESession_RoundTripsOverAsyncStream(t *testing.T) {
	srv := newLegacySSEServer(t)
	defer srv.Close()

	sess := NewSSESession(srv.URL+"/sse", "", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw, err := sess.Do(ctx, "tools/list", map[string]any{})
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	var envelope struct {
		Result struct {
			Echo string `json:"echo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		t.Fatalf("failed to decode response: %v; body=%s", err, raw.Body)
	}
	if envelope.Result.Echo != "tools/list" {
		t.Fatalf("expected echoed method 'tools/list', got %q", envelope.Result.Echo)
	}
}

func TestSSESession_SynchronousPOSTResponsePreferred(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		f := w.(http.Flusher)
		fmt.Fprintf(w, "event: endpoint\ndata: /messages\n\n")
		f.Flush()
		<-r.Context().Done()
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body.ID, "result": map[string]any{"sync": true}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess := NewSSESession(srv.URL+"/sse", "", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	raw, err := sess.Do(ctx, "initialize", map[string]any{})
	if err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	var envelope struct {
		Result struct {
			Sync bool `json:"sync"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw.Body, &envelope); err != nil {
		t.Fatalf("failed to decode response: %v; body=%s", err, raw.Body)
	}
	if !envelope.Result.Sync {
		t.Fatalf("expected the synchronous POST response body to be used, got %s", raw.Body)
	}
}

func TestSSESession_CloseStopsStream(t *testing.T) {
	streamClosed := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: endpoint\ndata: /messages\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(streamClosed)
	})
	mux.HandleFunc("/messages", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID int `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": body.ID, "result": map[string]any{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	sess := NewSSESession(srv.URL+"/sse", "", 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := sess.Do(ctx, "initialize", map[string]any{}); err != nil {
		t.Fatalf("Do failed: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	select {
	case <-streamClosed:
	case <-time.After(time.Second):
		t.Fatal("Close did not stop the SSE stream")
	}
}
