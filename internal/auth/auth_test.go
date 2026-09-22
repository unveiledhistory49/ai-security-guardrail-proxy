package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func sampleTenants() []TenantContext {
	return []TenantContext{
		{
			TenantID: "tenant-alpha",
			Name:     "Alpha Org",
			APIKey:   "sk-guard-alpha-1234567890abcdef",
			Enabled:  true,
		},
		{
			TenantID: "tenant-beta",
			Name:     "Beta Org",
			APIKey:   "sk-guard-beta-abcdef1234567890",
			Enabled:  true,
		},
		{
			TenantID: "tenant-disabled",
			Name:     "Disabled Org",
			APIKey:   "sk-guard-disabled-9999999999999",
			Enabled:  false,
		},
	}
}

func TestAuthValidBearer(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-guard-alpha-1234567890abcdef")

	tc, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("expected successful auth, got error: %v", err)
	}
	if tc.TenantID != "tenant-alpha" {
		t.Fatalf("expected tenant-alpha, got %s", tc.TenantID)
	}
	if !tc.Enabled {
		t.Fatalf("expected tenant to be enabled")
	}
}

func TestAuthValidXAPIKey(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("X-API-Key", "sk-guard-beta-abcdef1234567890")

	tc, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("expected successful auth, got error: %v", err)
	}
	if tc.TenantID != "tenant-beta" {
		t.Fatalf("expected tenant-beta, got %s", tc.TenantID)
	}
}

func TestAuthCaseInsensitiveBearer(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "bearer sk-guard-alpha-1234567890abcdef")

	tc, err := auth.Authenticate(req)
	if err != nil {
		t.Fatalf("expected successful auth with lowercase bearer, got: %v", err)
	}
	if tc.TenantID != "tenant-alpha" {
		t.Fatalf("expected tenant-alpha, got %s", tc.TenantID)
	}
}

func TestAuthMissingAPIKey(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	// No auth headers set

	tc, err := auth.Authenticate(req)
	if err != ErrMissingAPIKey {
		t.Fatalf("expected ErrMissingAPIKey, got: %v (tc=%v)", err, tc)
	}
}

func TestAuthInvalidAPIKey(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-guard-wrong-key-value")

	tc, err := auth.Authenticate(req)
	if err != ErrInvalidAPIKey {
		t.Fatalf("expected ErrInvalidAPIKey, got: %v (tc=%v)", err, tc)
	}
}

func TestAuthDisabledTenant(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-guard-disabled-9999999999999")

	tc, err := auth.Authenticate(req)
	if err != ErrDisabledTenant {
		t.Fatalf("expected ErrDisabledTenant, got: %v (tc=%v)", err, tc)
	}
}

func TestAuthMiddleware(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())

	handlerReached := false
	var capturedTenant *TenantContext

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerReached = true
		capturedTenant, _ = GetTenantContext(r.Context())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	middleware := auth.Middleware(nextHandler)

	// 1. Success case
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-guard-alpha-1234567890abcdef")
	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if !handlerReached || capturedTenant == nil || capturedTenant.TenantID != "tenant-alpha" {
		t.Fatalf("next handler was not called with tenant context")
	}

	// 2. Unauthorized case (missing key)
	handlerReached = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing key, got %d", rec.Code)
	}
	if handlerReached {
		t.Fatalf("handler should not have been reached on auth failure")
	}
	var errResp map[string]map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error json: %v", err)
	}
	if errResp["error"]["code"] != "unauthorized" {
		t.Fatalf("expected error code 'unauthorized', got %s", errResp["error"]["code"])
	}

	// 3. Forbidden case (disabled tenant)
	handlerReached = false
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer sk-guard-disabled-9999999999999")
	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for disabled tenant, got %d", rec.Code)
	}
	if handlerReached {
		t.Fatalf("handler should not have been reached for disabled tenant")
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to decode error json: %v", err)
	}
	if errResp["error"]["code"] != "forbidden" {
		t.Fatalf("expected error code 'forbidden', got %s", errResp["error"]["code"])
	}
}

func TestAuthConcurrentVerification(t *testing.T) {
	auth := NewAuthenticator(sampleTenants())
	const goroutines = 20
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if id%2 == 0 {
					tc, err := auth.VerifyKey("sk-guard-alpha-1234567890abcdef")
					if err != nil || tc.TenantID != "tenant-alpha" {
						t.Errorf("concurrent verify error: %v", err)
					}
				} else {
					_, err := auth.VerifyKey("sk-bogus-key")
					if err != ErrInvalidAPIKey {
						t.Errorf("expected ErrInvalidAPIKey, got %v", err)
					}
				}
			}
		}(g)
	}

	wg.Wait()
}

func TestWithAndGetTenantContext(t *testing.T) {
	ctx := context.Background()
	tc := &TenantContext{TenantID: "tenant-ctx-test", Name: "Test"}

	wrapped := WithTenantContext(ctx, tc)
	extracted, ok := GetTenantContext(wrapped)
	if !ok || extracted.TenantID != "tenant-ctx-test" {
		t.Fatalf("failed to extract tenant from context: ok=%v, extracted=%+v", ok, extracted)
	}

	// Nil context
	extractedNil, okNil := GetTenantContext(ctx)
	if okNil || extractedNil != nil {
		t.Fatalf("expected nil from bare context")
	}
}
