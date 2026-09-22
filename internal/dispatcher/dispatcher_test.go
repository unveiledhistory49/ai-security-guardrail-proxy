package dispatcher

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"ai-security-guardrail-proxy/internal/pipeline"
)

func TestDispatcherPassThrough(t *testing.T) {
	var receivedHeader string
	var receivedQuery string
	var receivedBody string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeader = r.Header.Get("X-Custom-Client-Header")
		receivedQuery = r.URL.RawQuery
		b, _ := io.ReadAll(r.Body)
		receivedBody = string(b)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Header", "present")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result":"ok","model":"test-vllm"}`))
	}))
	defer upstream.Close()

	disp, err := NewDispatcher(upstream.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	clientPayload := []byte(`{"messages":[{"role":"user","content":"hello"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions?model=test&temperature=0.7", nil)
	req.Header.Set("X-Custom-Client-Header", "secret-test-value")
	req.RemoteAddr = "192.168.1.100:54321"

	rec := httptest.NewRecorder()
	pc := &pipeline.PipelineContext{CleanPayload: clientPayload}
	err = disp.Forward(rec, req, pc)
	if err != nil {
		t.Fatalf("dispatcher Forward returned error: %v", err)
	}

	// Verify upstream received expected request data
	if receivedHeader != "secret-test-value" {
		t.Fatalf("expected header 'secret-test-value', got %q", receivedHeader)
	}
	if receivedQuery != "model=test&temperature=0.7" {
		t.Fatalf("expected query 'model=test&temperature=0.7', got %q", receivedQuery)
	}
	if receivedBody != string(clientPayload) {
		t.Fatalf("expected body %q, got %q", string(clientPayload), receivedBody)
	}

	// Verify downstream response
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("X-Upstream-Header") != "present" {
		t.Fatalf("expected X-Upstream-Header 'present', got %q", rec.Header().Get("X-Upstream-Header"))
	}
	var respData map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &respData); err != nil {
		t.Fatalf("failed to decode response json: %v", err)
	}
	if respData["model"] != "test-vllm" {
		t.Fatalf("expected model 'test-vllm', got %q", respData["model"])
	}
}

func TestDispatcherStreamingChunks(t *testing.T) {
	chunks := []string{
		"data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
		"data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n",
		"data: [DONE]\n\n",
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Errorf("upstream writer does not support Flusher")
			return
		}

		for _, chunk := range chunks {
			_, _ = w.Write([]byte(chunk))
			flusher.Flush()
			time.Sleep(10 * time.Millisecond)
		}
	}))
	defer upstream.Close()

	disp, err := NewDispatcher(upstream.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	pc := &pipeline.PipelineContext{CleanPayload: []byte(`{"stream":true}`)}
	err = disp.Forward(rec, req, pc)
	if err != nil {
		t.Fatalf("forwarding streaming request failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Content-Type"), "text/event-stream") {
		t.Fatalf("expected text/event-stream Content-Type, got %q", rec.Header().Get("Content-Type"))
	}

	body := rec.Body.String()
	for _, chunk := range chunks {
		if !strings.Contains(body, chunk) {
			t.Fatalf("missing chunk in response body: %q", chunk)
		}
	}
}

func TestDispatcherClientContextCancellation(t *testing.T) {
	upstreamCancelled := make(chan struct{})
	var once sync.Once

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// Wait until request context is cancelled by downstream client
		select {
		case <-r.Context().Done():
			once.Do(func() {
				close(upstreamCancelled)
			})
		case <-time.After(5 * time.Second):
			t.Errorf("timeout waiting for upstream request context cancellation")
		}
	}))
	defer upstream.Close()

	disp, err := NewDispatcher(upstream.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	// Cancel client context after a tiny delay
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	pc := &pipeline.PipelineContext{CleanPayload: []byte(`{"stream":true}`)}
	_ = disp.Forward(rec, req, pc)

	// Verify upstream received the context cancellation
	select {
	case <-upstreamCancelled:
		// Success! Upstream was notified of cancellation
	case <-time.After(2 * time.Second):
		t.Fatalf("upstream did not receive context cancellation within deadline")
	}
}

func TestDispatcherUpstreamDown(t *testing.T) {
	// Point to an invalid, unassigned local port
	disp, err := NewDispatcher("http://127.0.0.1:54321", 1*time.Second)
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()

	pc := &pipeline.PipelineContext{CleanPayload: []byte(`{}`)}
	err = disp.Forward(rec, req, pc)
	if err == nil {
		t.Fatalf("expected error when upstream is unreachable, got nil")
	}

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 Bad Gateway, got %d", rec.Code)
	}
}
