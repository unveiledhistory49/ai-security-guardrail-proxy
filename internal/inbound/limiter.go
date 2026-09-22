package inbound

import (
	"encoding/json"
	"sync"
	"time"

	"ai-security-guardrail-proxy/internal/pipeline"
)

type tokenRecord struct {
	timestamp time.Time
	tokens    int
}

type tenantBucket struct {
	mu           sync.Mutex
	rpm          int
	tpm          int
	requestTimes []time.Time
	tokenRecords []tokenRecord
}

// RateLimiter manages thread-safe sliding-window rate and quota limits per tenant.
type RateLimiter struct {
	mu         sync.RWMutex
	defaultRPM int
	defaultTPM int
	tenants    map[string]*tenantBucket
	nowFunc    func() time.Time
}

// NewRateLimiter constructs a RateLimiter with default limits (0 means unlimited unless overridden).
func NewRateLimiter(defaultRPM, defaultTPM int) *RateLimiter {
	return &RateLimiter{
		defaultRPM: defaultRPM,
		defaultTPM: defaultTPM,
		tenants:    make(map[string]*tenantBucket),
		nowFunc:    time.Now,
	}
}

// Name returns the stage name.
func (r *RateLimiter) Name() string {
	return "rate_limiter"
}

// FailClosed returns true for fail-closed security.
func (r *RateLimiter) FailClosed() bool {
	return true
}

// SetNowFunc allows injecting custom clock for testing sliding window expiration.
func (r *RateLimiter) SetNowFunc(f func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nowFunc = f
}

// SetTenantLimit sets custom RPM and TPM quotas for a tenant.
func (r *RateLimiter) SetTenantLimit(tenantID string, rpm, tpm int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	bucket, exists := r.tenants[tenantID]
	if !exists {
		bucket = &tenantBucket{
			rpm: rpm,
			tpm: tpm,
		}
		r.tenants[tenantID] = bucket
		return
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	bucket.rpm = rpm
	bucket.tpm = tpm
}

// GetTenantLimit retrieves configured RPM and TPM for a tenant.
func (r *RateLimiter) GetTenantLimit(tenantID string) (rpm, tpm int) {
	r.mu.RLock()
	bucket, exists := r.tenants[tenantID]
	r.mu.RUnlock()

	if !exists {
		return r.defaultRPM, r.defaultTPM
	}

	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	return bucket.rpm, bucket.tpm
}

func (r *RateLimiter) getOrCreateBucket(tenantID string) *tenantBucket {
	r.mu.Lock()
	defer r.mu.Unlock()

	bucket, exists := r.tenants[tenantID]
	if !exists {
		bucket = &tenantBucket{
			rpm: r.defaultRPM,
			tpm: r.defaultTPM,
		}
		r.tenants[tenantID] = bucket
	}
	return bucket
}

// Execute checks tenant sliding-window rate and quota limits.
func (r *RateLimiter) Execute(ctx *pipeline.PipelineContext) pipeline.StageResult {
	bucket := r.getOrCreateBucket(ctx.TenantID)

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	// If no limits configured, pass through
	if bucket.rpm <= 0 && bucket.tpm <= 0 {
		return pipeline.StageContinue
	}

	r.mu.RLock()
	now := r.nowFunc()
	r.mu.RUnlock()

	cutoff := now.Add(-1 * time.Minute)

	// 1. Prune expired request timestamps
	validReqs := 0
	for _, t := range bucket.requestTimes {
		if !t.Before(cutoff) {
			bucket.requestTimes[validReqs] = t
			validReqs++
		}
	}
	bucket.requestTimes = bucket.requestTimes[:validReqs]

	// 2. Prune expired token records and compute active token usage
	validTokens := 0
	currentTokens := 0
	for _, rec := range bucket.tokenRecords {
		if !rec.timestamp.Before(cutoff) {
			bucket.tokenRecords[validTokens] = rec
			validTokens++
			currentTokens += rec.tokens
		}
	}
	bucket.tokenRecords = bucket.tokenRecords[:validTokens]

	// 3. Check RPM limit
	if bucket.rpm > 0 && len(bucket.requestTimes) >= bucket.rpm {
		ctx.MatchedRuleID = "RATE_LIMIT_EXCEEDED"
		ctx.ViolationType = "RATE_LIMIT"
		return pipeline.StageTripwire
	}

	// 4. Estimate tokens and check TPM limit
	estimatedTokens := EstimateTokens(ctx.CleanPayload)
	if bucket.tpm > 0 && currentTokens+estimatedTokens > bucket.tpm {
		ctx.MatchedRuleID = "RATE_LIMIT_EXCEEDED"
		ctx.ViolationType = "RATE_LIMIT"
		return pipeline.StageTripwire
	}

	// 5. Within limits: commit reservation
	bucket.requestTimes = append(bucket.requestTimes, now)
	bucket.tokenRecords = append(bucket.tokenRecords, tokenRecord{
		timestamp: now,
		tokens:    estimatedTokens,
	})

	return pipeline.StageContinue
}

// EstimateTokens calculates estimated token consumption: len(prompt)/4 * 1.33 + max_tokens.
func EstimateTokens(payload []byte) int {
	if len(payload) == 0 {
		return 1
	}

	var partial struct {
		MaxTokens int `json:"max_tokens"`
	}
	_ = json.Unmarshal(payload, &partial)

	baseTokens := int(float64(len(payload)) / 4.0 * 1.33)
	if baseTokens < 1 {
		baseTokens = 1
	}
	return baseTokens + partial.MaxTokens
}
