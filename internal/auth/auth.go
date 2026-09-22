package auth

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
)

var (
	// ErrMissingAPIKey indicates no Bearer token or X-API-Key header was provided.
	ErrMissingAPIKey = errors.New("missing API key in request")
	// ErrInvalidAPIKey indicates the provided key does not match any registered tenant.
	ErrInvalidAPIKey = errors.New("invalid API key")
	// ErrDisabledTenant indicates the tenant is registered but disabled by administrative policy.
	ErrDisabledTenant = errors.New("tenant account is disabled")
)

// TenantContext encapsulates the authenticated tenant identity and policy attributes.
type TenantContext struct {
	TenantID string `json:"tenant_id"`
	Name     string `json:"name"`
	APIKey   string `json:"api_key"`
	Enabled  bool   `json:"enabled"`
}

type contextKey struct{}

var tenantCtxKey = contextKey{}

// WithTenantContext returns a new context containing the given TenantContext.
func WithTenantContext(ctx context.Context, tc *TenantContext) context.Context {
	return context.WithValue(ctx, tenantCtxKey, tc)
}

// GetTenantContext extracts the TenantContext from the context if present.
func GetTenantContext(ctx context.Context) (*TenantContext, bool) {
	tc, ok := ctx.Value(tenantCtxKey).(*TenantContext)
	return tc, ok && tc != nil
}

// Authenticator provides multi-tenant authentication using constant-time key comparisons.
type Authenticator struct {
	mu      sync.RWMutex
	tenants []TenantContext
}

// NewAuthenticator creates an Authenticator initialized with the provided tenants.
func NewAuthenticator(tenants []TenantContext) *Authenticator {
	copied := make([]TenantContext, len(tenants))
	copy(copied, tenants)
	return &Authenticator{tenants: copied}
}

// SetTenants atomically replaces the active tenant list.
func (a *Authenticator) SetTenants(tenants []TenantContext) {
	a.mu.Lock()
	defer a.mu.Unlock()
	copied := make([]TenantContext, len(tenants))
	copy(copied, tenants)
	a.tenants = copied
}

// AddTenant registers or updates a tenant.
func (a *Authenticator) AddTenant(t TenantContext) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.tenants {
		if a.tenants[i].TenantID == t.TenantID || a.tenants[i].APIKey == t.APIKey {
			a.tenants[i] = t
			return
		}
	}
	a.tenants = append(a.tenants, t)
}

// ExtractAPIKey extracts the API key from Authorization: Bearer <key> or X-API-Key header.
func ExtractAPIKey(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token := strings.TrimSpace(parts[1])
			if token != "" {
				return token
			}
		}
	}

	xKey := r.Header.Get("X-API-Key")
	if xKey != "" {
		return strings.TrimSpace(xKey)
	}

	return ""
}

// Authenticate verifies the incoming HTTP request against registered tenants.
// Performs full constant-time verification across all tenants to prevent timing side channels.
func (a *Authenticator) Authenticate(r *http.Request) (*TenantContext, error) {
	key := ExtractAPIKey(r)
	if key == "" {
		return nil, ErrMissingAPIKey
	}

	return a.VerifyKey(key)
}

// VerifyKey checks an API key against all registered tenants in constant time.
func (a *Authenticator) VerifyKey(key string) (*TenantContext, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	keyBytes := []byte(key)
	var matched *TenantContext

	// Full scan with ConstantTimeCompare prevents timing oracle attacks
	for i := range a.tenants {
		tenantKeyBytes := []byte(a.tenants[i].APIKey)
		if subtle.ConstantTimeCompare(keyBytes, tenantKeyBytes) == 1 {
			matched = &a.tenants[i]
		}
	}

	if matched == nil {
		return nil, ErrInvalidAPIKey
	}

	if !matched.Enabled {
		return nil, ErrDisabledTenant
	}

	return matched, nil
}

// WriteAuthError formats and writes an RFC/OpenAI-compatible JSON error response.
func WriteAuthError(w http.ResponseWriter, status int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	code := "unauthorized"
	if status == http.StatusForbidden {
		code = "forbidden"
	}
	resp := map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": err.Error(),
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// Middleware returns an HTTP middleware enforcing authentication before dispatching to next.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, err := a.Authenticate(r)
		if err != nil {
			status := http.StatusUnauthorized
			if errors.Is(err, ErrDisabledTenant) {
				status = http.StatusForbidden
			}
			WriteAuthError(w, status, err)
			return
		}

		ctx := WithTenantContext(r.Context(), tc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
