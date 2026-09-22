package inbound

import (
	"context"
	"sync"
	"testing"
	"time"

	"ai-security-guardrail-proxy/internal/pipeline"
)

func TestRateLimiter_RPMEnforcementAndSlidingWindow(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	tenantID := "tenant-test-rpm"
	limiter.SetTenantLimit(tenantID, 3, 0) // 3 requests per minute

	currentTime := time.Now()
	limiter.SetNowFunc(func() time.Time {
		return currentTime
	})

	// Request 1 -> Allow
	pc1 := pipeline.AcquireContext(context.Background(), tenantID, "sess-1")
	if res := limiter.Execute(pc1); res != pipeline.StageContinue {
		t.Fatalf("request 1 should be allowed, got %v", res)
	}
	pipeline.ReleaseContext(pc1)

	// Request 2 -> Allow
	pc2 := pipeline.AcquireContext(context.Background(), tenantID, "sess-2")
	if res := limiter.Execute(pc2); res != pipeline.StageContinue {
		t.Fatalf("request 2 should be allowed, got %v", res)
	}
	pipeline.ReleaseContext(pc2)

	// Request 3 -> Allow
	pc3 := pipeline.AcquireContext(context.Background(), tenantID, "sess-3")
	if res := limiter.Execute(pc3); res != pipeline.StageContinue {
		t.Fatalf("request 3 should be allowed, got %v", res)
	}
	pipeline.ReleaseContext(pc3)

	// Request 4 (same time) -> Tripwire (Exceeded 3 RPM)
	pc4 := pipeline.AcquireContext(context.Background(), tenantID, "sess-4")
	if res := limiter.Execute(pc4); res != pipeline.StageTripwire {
		t.Fatalf("request 4 should be rejected with StageTripwire, got %v", res)
	}
	if pc4.MatchedRuleID != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("expected rule RATE_LIMIT_EXCEEDED, got %s", pc4.MatchedRuleID)
	}
	if pc4.ViolationType != "RATE_LIMIT" {
		t.Fatalf("expected violation type RATE_LIMIT, got %s", pc4.ViolationType)
	}
	pipeline.ReleaseContext(pc4)

	// Advance time by 61 seconds (outside sliding window)
	currentTime = currentTime.Add(61 * time.Second)

	// Request 5 -> Allow again
	pc5 := pipeline.AcquireContext(context.Background(), tenantID, "sess-5")
	if res := limiter.Execute(pc5); res != pipeline.StageContinue {
		t.Fatalf("request 5 should be allowed after window slid, got %v", res)
	}
	pipeline.ReleaseContext(pc5)
}

func TestRateLimiter_TPMEnforcement(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	tenantID := "tenant-test-tpm"
	// Set 50 tokens per minute
	limiter.SetTenantLimit(tenantID, 100, 50)

	currentTime := time.Now()
	limiter.SetNowFunc(func() time.Time {
		return currentTime
	})

	// Request with small payload (~10 tokens)
	pcSmall := pipeline.AcquireContext(context.Background(), tenantID, "sess-sm")
	pcSmall.CleanPayload = []byte(`{"prompt":"hi"}`)
	if res := limiter.Execute(pcSmall); res != pipeline.StageContinue {
		t.Fatalf("small request should be allowed, got %v", res)
	}
	pipeline.ReleaseContext(pcSmall)

	// Request with large payload (~100 tokens, exceeds remaining 40 TPM)
	pcLarge := pipeline.AcquireContext(context.Background(), tenantID, "sess-lg")
	pcLarge.CleanPayload = make([]byte, 300) // ~100 tokens
	if res := limiter.Execute(pcLarge); res != pipeline.StageTripwire {
		t.Fatalf("large request should be rejected by TPM quota, got %v", res)
	}
	pipeline.ReleaseContext(pcLarge)
}

func TestRateLimiter_TenantIsolation(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	limiter.SetTenantLimit("tenant-limited", 1, 0)
	limiter.SetTenantLimit("tenant-unlimited", 100, 0)

	// Exhaust tenant-limited quota
	pcLim1 := pipeline.AcquireContext(context.Background(), "tenant-limited", "s1")
	if res := limiter.Execute(pcLim1); res != pipeline.StageContinue {
		t.Fatalf("expected allow for first request, got %v", res)
	}
	pipeline.ReleaseContext(pcLim1)

	pcLim2 := pipeline.AcquireContext(context.Background(), "tenant-limited", "s2")
	if res := limiter.Execute(pcLim2); res != pipeline.StageTripwire {
		t.Fatalf("expected rate limit tripwire, got %v", res)
	}
	pipeline.ReleaseContext(pcLim2)

	// Other tenant should be unaffected
	pcOther := pipeline.AcquireContext(context.Background(), "tenant-unlimited", "s3")
	if res := limiter.Execute(pcOther); res != pipeline.StageContinue {
		t.Fatalf("expected tenant-unlimited to pass unaffected, got %v", res)
	}
	pipeline.ReleaseContext(pcOther)
}

func TestRateLimiter_ConcurrentThreadSafety(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	tenantID := "tenant-concurrent"
	limiter.SetTenantLimit(tenantID, 50, 0)

	var wg sync.WaitGroup
	var allowedCount int
	var rejectedCount int
	var mu sync.Mutex

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			pc := pipeline.AcquireContext(context.Background(), tenantID, "concurrent")
			res := limiter.Execute(pc)
			mu.Lock()
			if res == pipeline.StageContinue {
				allowedCount++
			} else {
				rejectedCount++
			}
			mu.Unlock()
			pipeline.ReleaseContext(pc)
		}(i)
	}

	wg.Wait()

	if allowedCount != 50 {
		t.Fatalf("expected exactly 50 allowed requests, got %d", allowedCount)
	}
	if rejectedCount != 50 {
		t.Fatalf("expected exactly 50 rejected requests, got %d", rejectedCount)
	}
}
