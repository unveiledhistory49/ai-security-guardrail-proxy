package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMetrics_RequestsCounter(t *testing.T) {
	reg := NewRegistry()
	reg.IncRequests("tenant-1", "ALLOW", "200")
	reg.IncRequests("tenant-1", "ALLOW", "200")
	reg.IncRequests("tenant-2", "BLOCK_INBOUND", "400")

	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatalf("failed to write metrics: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, `guardrail_requests_total{action="ALLOW",status="200",tenant="tenant-1"} 2`) {
		t.Errorf("expected count 2 for tenant-1 ALLOW 200, got output:\n%s", out)
	}
	if !strings.Contains(out, `guardrail_requests_total{action="BLOCK_INBOUND",status="400",tenant="tenant-2"} 1`) {
		t.Errorf("expected count 1 for tenant-2 BLOCK_INBOUND 400, got output:\n%s", out)
	}
}

func TestMetrics_StageDurationHistogram(t *testing.T) {
	reg := NewRegistry()
	// Default buckets: 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1
	reg.ObserveStageDuration("inbound_inspection", 0.00008) // <= 0.0001
	reg.ObserveStageDuration("inbound_inspection", 0.0004)  // <= 0.0005
	reg.ObserveStageDuration("inbound_inspection", 0.003)   // <= 0.005

	var buf bytes.Buffer
	if err := reg.WritePrometheus(&buf); err != nil {
		t.Fatalf("failed to write metrics: %v", err)
	}

	out := buf.String()
	// bucket 0.0001 should have 1
	if !strings.Contains(out, `guardrail_stage_duration_seconds_bucket{le="0.0001",stage="inbound_inspection"} 1`) {
		t.Errorf("expected bucket 0.0001 to have count 1, got:\n%s", out)
	}
	// bucket 0.0005 should have 2
	if !strings.Contains(out, `guardrail_stage_duration_seconds_bucket{le="0.0005",stage="inbound_inspection"} 2`) {
		t.Errorf("expected bucket 0.0005 to have count 2, got:\n%s", out)
	}
	// bucket +Inf should have 3
	if !strings.Contains(out, `guardrail_stage_duration_seconds_bucket{le="+Inf",stage="inbound_inspection"} 3`) {
		t.Errorf("expected bucket +Inf to have count 3, got:\n%s", out)
	}
	// count should be 3
	if !strings.Contains(out, `guardrail_stage_duration_seconds_count{stage="inbound_inspection"} 3`) {
		t.Errorf("expected count 3, got:\n%s", out)
	}
}

func TestMetrics_TripwireViolationsAndCanaries(t *testing.T) {
	reg := NewRegistry()
	reg.IncTripwireViolations("SIG-001", "aho_corasick")
	reg.IncTripwireViolations("SIG-001", "aho_corasick")
	reg.IncTripwireViolations("DELIM-01", "delimiter_check")
	reg.IncCanaryDetections("tenant-prod")

	var buf bytes.Buffer
	_ = reg.WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, `guardrail_tripwire_violations_total{rule_id="SIG-001",stage="aho_corasick"} 2`) {
		t.Errorf("missing SIG-001 metric in output:\n%s", out)
	}
	if !strings.Contains(out, `guardrail_tripwire_violations_total{rule_id="DELIM-01",stage="delimiter_check"} 1`) {
		t.Errorf("missing DELIM-01 metric in output:\n%s", out)
	}
	if !strings.Contains(out, `guardrail_canary_detections_total{tenant="tenant-prod"} 1`) {
		t.Errorf("missing canary metric in output:\n%s", out)
	}
}

func TestMetrics_CircuitBreakerGauge(t *testing.T) {
	reg := NewRegistry()
	reg.SetCircuitBreakerState(2) // 2 = OPEN

	var buf bytes.Buffer
	_ = reg.WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "guardrail_circuit_breaker_state 2") {
		t.Errorf("expected circuit breaker state 2, got:\n%s", out)
	}
}

func TestMetrics_AuditRecordsCounter(t *testing.T) {
	reg := NewRegistry()
	reg.IncAuditRecords()
	reg.IncAuditRecords()
	reg.IncAuditRecords()

	var buf bytes.Buffer
	_ = reg.WritePrometheus(&buf)
	out := buf.String()

	if !strings.Contains(out, "guardrail_audit_records_total 3") {
		t.Errorf("expected audit records 3, got:\n%s", out)
	}
}

func TestMetrics_HTTPHandler(t *testing.T) {
	reg := NewRegistry()
	reg.IncRequests("tenant-test", "ALLOW", "200")
	reg.SetCircuitBreakerState(0)

	ts := httptest.NewServer(reg.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("HTTP GET /metrics failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("expected Content-Type text/plain; version=0.0.4, got %s", ct)
	}

	var body bytes.Buffer
	_, _ = body.ReadFrom(resp.Body)
	if !strings.Contains(body.String(), "guardrail_requests_total") {
		t.Errorf("expected body to contain guardrail_requests_total, got:\n%s", body.String())
	}
}
