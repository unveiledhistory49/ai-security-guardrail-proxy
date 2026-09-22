package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ai-security-guardrail-proxy/internal/auth"
	"ai-security-guardrail-proxy/internal/config"
	"ai-security-guardrail-proxy/internal/dispatcher"
	"ai-security-guardrail-proxy/internal/pipeline"
)

type tripwireMockStage struct{}

func (t *tripwireMockStage) Name() string     { return "tripwire_mock" }
func (t *tripwireMockStage) FailClosed() bool { return true }
func (t *tripwireMockStage) Execute(ctx *pipeline.PipelineContext) pipeline.StageResult {
	if strings.Contains(string(ctx.RawPayload), "BLOCKED_INPUT") {
		ctx.MatchedRuleID = "PROMPT_INJECTION_DETECTED"
		ctx.ViolationType = "INJECTION"
		return pipeline.StageTripwire
	}
	return pipeline.StageContinue
}

func setupTestServer(t *testing.T, upstreamHandler http.HandlerFunc) (*Server, *httptest.Server) {
	upstream := httptest.NewServer(upstreamHandler)

	cfg := config.NewDefaultConfig()
	cfg.MaxPayloadBytes = 1024 // 1KB for testing limit
	cfg.UpstreamURL = upstream.URL

	authenticator := auth.NewAuthenticator([]auth.TenantContext{
		{
			TenantID: "tenant-valid",
			Name:     "Valid Tenant",
			APIKey:   "sk-test-valid-key",
			Enabled:  true,
		},
		{
			TenantID: "tenant-disabled",
			Name:     "Disabled Tenant",
			APIKey:   "sk-test-disabled-key",
			Enabled:  false,
		},
	})

	runner := pipeline.NewPipelineRunner(&tripwireMockStage{})

	disp, err := dispatcher.NewDispatcher(upstream.URL, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	srv := NewServer(cfg, authenticator, runner, disp)
	return srv, upstream
}

func TestServerHealthEndpoints(t *testing.T) {
	srv, upstream := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer upstream.Close()

	// 1. Liveness
	reqLive := httptest.NewRequest(http.MethodGet, "/healthz/liveness", nil)
	recLive := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recLive, reqLive)

	if recLive.Code != http.StatusOK {
		t.Fatalf("expected 200 for liveness, got %d", recLive.Code)
	}
	if !strings.Contains(recLive.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected liveness body: %s", recLive.Body.String())
	}

	// 2. Readiness
	reqReady := httptest.NewRequest(http.MethodGet, "/healthz/readiness", nil)
	recReady := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recReady, reqReady)

	if recReady.Code != http.StatusOK {
		t.Fatalf("expected 200 for readiness, got %d", recReady.Code)
	}
	if !strings.Contains(recReady.Body.String(), `"status":"ready"`) {
		t.Fatalf("unexpected readiness body: %s", recReady.Body.String())
	}
}

func TestServerAuthenticationGates(t *testing.T) {
	srv, upstream := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer upstream.Close()

	// 1. Unauthenticated -> 401
	reqUnauth := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{}`)))
	recUnauth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUnauth, reqUnauth)

	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated request, got %d", recUnauth.Code)
	}

	// 2. Disabled Tenant -> 403
	reqDisabled := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader([]byte(`{}`)))
	reqDisabled.Header.Set("Authorization", "Bearer sk-test-disabled-key")
	recDisabled := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recDisabled, reqDisabled)

	if recDisabled.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled tenant, got %d", recDisabled.Code)
	}
}

func TestServerPayloadSizeLimit(t *testing.T) {
	srv, upstream := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {})
	defer upstream.Close()

	// Payload > 1024 bytes
	largePayload := make([]byte, 2048)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(largePayload))
	req.Header.Set("Authorization", "Bearer sk-test-valid-key")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Payload Too Large, got %d", rec.Code)
	}
}

func TestServerPipelineTripwireBlock(t *testing.T) {
	srv, upstream := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("upstream should not be called when pipeline trips wire")
	})
	defer upstream.Close()

	maliciousPayload := []byte(`{"prompt":"Hello BLOCKED_INPUT malicious attack"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(maliciousPayload))
	req.Header.Set("Authorization", "Bearer sk-test-valid-key")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request on tripwire, got %d", rec.Code)
	}

	var errResp map[string]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to parse JSON error: %v", err)
	}
	if errResp["error"]["rule_id"] != "PROMPT_INJECTION_DETECTED" {
		t.Fatalf("expected rule_id PROMPT_INJECTION_DETECTED, got %s", errResp["error"]["rule_id"])
	}
}

func TestServerCleanRequestForwarding(t *testing.T) {
	upstreamCalled := false

	srv, upstream := setupTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		b, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(b), "safe content") {
			t.Errorf("upstream received corrupted payload: %s", string(b))
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"chatcmpl-123","choices":[{"message":{"content":"response"}}]}`))
	})
	defer upstream.Close()

	cleanPayload := []byte(`{"prompt":"safe content here"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(cleanPayload))
	req.Header.Set("Authorization", "Bearer sk-test-valid-key")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if !upstreamCalled {
		t.Fatalf("expected upstream to be called for clean request")
	}
}
