package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ai-security-guardrail-proxy/internal/audit"
	"ai-security-guardrail-proxy/internal/metrics"
	"ai-security-guardrail-proxy/internal/outbound"
	"ai-security-guardrail-proxy/internal/pipeline"
	"ai-security-guardrail-proxy/internal/resilience"
)

var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// Dispatcher manages connection-pooled upstream proxying with SSE streaming support,
// sliding lookahead inspection, canary tripwires, circuit breaking, and telemetry.
type Dispatcher struct {
	upstreamURL       *url.URL
	upstreamAuthToken string
	client            *http.Client
	outboundEngine    *outbound.Engine
	circuitBreaker    *resilience.CircuitBreaker
	auditLedger       *audit.ChainedLedger
}

// NewDispatcher initializes a connection-pooled upstream dispatcher.
func NewDispatcher(upstreamURLStr string, idleTimeout time.Duration) (*Dispatcher, error) {
	parsedURL, err := url.Parse(upstreamURLStr)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL %q: %w", upstreamURLStr, err)
	}

	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		MaxIdleConns:          5000,
		MaxIdleConnsPerHost:   500,
		IdleConnTimeout:       idleTimeout,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	client := &http.Client{
		Transport: transport,
	}

	cb := resilience.NewCircuitBreaker(resilience.DefaultConfig())
	cb.SetOnStateChange(func(from, to resilience.State) {
		metrics.SetCircuitBreakerState(int(to))
	})

	return &Dispatcher{
		upstreamURL:    parsedURL,
		client:         client,
		outboundEngine: outbound.NewEngine(),
		circuitBreaker: cb,
	}, nil
}

// UpstreamURL returns the target upstream URL.
func (d *Dispatcher) UpstreamURL() *url.URL {
	return d.upstreamURL
}

// Client returns the underlying http.Client.
func (d *Dispatcher) Client() *http.Client {
	return d.client
}

// SetTransport allows injecting a custom RoundTripper (e.g. for testing).
func (d *Dispatcher) SetTransport(rt http.RoundTripper) {
	d.client.Transport = rt
}

// OutboundEngine returns the configured outbound inspection engine.
func (d *Dispatcher) OutboundEngine() *outbound.Engine {
	return d.outboundEngine
}

// SetOutboundEngine sets a custom outbound inspection engine.
func (d *Dispatcher) SetOutboundEngine(oe *outbound.Engine) {
	d.outboundEngine = oe
}

// CircuitBreaker returns the upstream circuit breaker.
func (d *Dispatcher) CircuitBreaker() *resilience.CircuitBreaker {
	return d.circuitBreaker
}

// SetUpstreamAuthToken sets the upstream bearer token override.
func (d *Dispatcher) SetUpstreamAuthToken(token string) {
	d.upstreamAuthToken = token
}

// SetCircuitBreaker sets a custom circuit breaker.
func (d *Dispatcher) SetCircuitBreaker(cb *resilience.CircuitBreaker) {
	d.circuitBreaker = cb
	if cb != nil {
		cb.SetOnStateChange(func(from, to resilience.State) {
			metrics.SetCircuitBreakerState(int(to))
		})
	}
}

// AuditLedger returns the configured audit ledger.
func (d *Dispatcher) AuditLedger() *audit.ChainedLedger {
	return d.auditLedger
}

// SetAuditLedger sets the audit ledger for recording transaction events.
func (d *Dispatcher) SetAuditLedger(al *audit.ChainedLedger) {
	d.auditLedger = al
}

// Forward dispatches an inbound HTTP request and payload to the upstream inference endpoint.
// It preserves headers, checks the upstream circuit breaker, inspects responses
// (SSE lookahead tripwires for streaming, secret/canary/schema scanning for synchronous),
// and guarantees downstream cancellation propagation and telemetry recording.
func (d *Dispatcher) Forward(w http.ResponseWriter, r *http.Request, pc *pipeline.PipelineContext) error {
	if pc == nil {
		pc = &pipeline.PipelineContext{
			StdContext: r.Context(),
		}
	}

	payload := pc.CleanPayload
	if len(payload) == 0 && r.Body != nil {
		payload, _ = io.ReadAll(r.Body)
	}

	// 1. Upstream Circuit Breaker Check
	if d.circuitBreaker != nil {
		if err := d.circuitBreaker.Allow(); err != nil {
			errJSON, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"code":    "CIRCUIT_OPEN",
					"message": "upstream circuit breaker is open",
				},
			})
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write(errJSON)

			if d.auditLedger != nil {
				_ = d.auditLedger.Record(pc.TenantID, pc.SessionID, "CIRCUIT_OPEN", payload, errJSON)
			}
			metrics.IncRequests(pc.TenantID, "CIRCUIT_OPEN", "503")
			metrics.IncAuditRecords()
			return err
		}
	}

	// 2. Construct destination URL
	targetURL := *d.upstreamURL
	if d.upstreamURL.Path == "" || d.upstreamURL.Path == "/" {
		targetURL.Path = r.URL.Path
	} else if strings.HasPrefix(r.URL.Path, d.upstreamURL.Path) {
		targetURL.Path = r.URL.Path
	} else {
		targetURL.Path = strings.TrimSuffix(d.upstreamURL.Path, "/") + "/" + strings.TrimPrefix(r.URL.Path, "/")
	}
	targetURL.RawQuery = r.URL.RawQuery
	targetURL.Fragment = r.URL.Fragment

	// Create upstream request bound to client's context and cancellable upon tripwire abort.
	upstreamCtx, cancelUpstream := context.WithCancel(r.Context())
	defer cancelUpstream()

	req, err := http.NewRequestWithContext(upstreamCtx, r.Method, targetURL.String(), bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Copy allowed headers
	for k, vv := range r.Header {
		if hopByHopHeaders[strings.ToLower(k)] || strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.ContentLength = int64(len(payload))

	// If upstream auth token is explicitly configured, override Authorization header
	if d.upstreamAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+d.upstreamAuthToken)
	}

	// Host header handling
	req.Host = d.upstreamURL.Host

	// Append X-Forwarded headers
	clientIP, _, splitErr := net.SplitHostPort(r.RemoteAddr)
	if splitErr == nil && clientIP != "" {
		if prior := req.Header.Get("X-Forwarded-For"); prior != "" {
			clientIP = prior + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}

	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	req.Header.Set("X-Forwarded-Proto", proto)

	// 3. Execute upstream dispatch
	resp, err := d.client.Do(req)
	if err != nil {
		if d.circuitBreaker != nil {
			d.circuitBreaker.RecordFailure()
		}

		if r.Context().Err() != nil {
			// Client disconnected; propagating cancellation cleanly
			return r.Context().Err()
		}

		errResp := map[string]any{
			"error": map[string]any{
				"code":    "upstream_unavailable",
				"message": fmt.Sprintf("failed to reach upstream target: %v", err),
			},
		}
		errJSON, _ := json.Marshal(errResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(errJSON)

		if d.auditLedger != nil {
			_ = d.auditLedger.Record(pc.TenantID, pc.SessionID, "UPSTREAM_UNAVAILABLE", payload, errJSON)
		}
		metrics.IncRequests(pc.TenantID, "UPSTREAM_UNAVAILABLE", "502")
		metrics.IncAuditRecords()
		return err
	}
	defer resp.Body.Close()

	// Update Circuit Breaker on response status code
	if resp.StatusCode >= 500 {
		if d.circuitBreaker != nil {
			d.circuitBreaker.RecordFailure()
		}
	} else {
		if d.circuitBreaker != nil {
			d.circuitBreaker.RecordSuccess()
		}
	}

	// 4. Check if response is Server-Sent Events (SSE)
	isSSE := strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream")

	if isSSE {
		for k, vv := range resp.Header {
			if hopByHopHeaders[strings.ToLower(k)] {
				continue
			}
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.WriteHeader(resp.StatusCode)

		flusher, _ := w.(http.Flusher)
		if flusher != nil {
			flusher.Flush()
		}

		streamErr := d.outboundEngine.ProcessStream(upstreamCtx, cancelUpstream, resp.Body, w, flusher, nil, pc)
		if pc != nil && pc.ViolationType == "TRIPWIRE_VIOLATION" {
			if d.auditLedger != nil {
				_ = d.auditLedger.Record(pc.TenantID, pc.SessionID, "TRIPWIRE_ABORT", payload, []byte("TRIPWIRE_ABORT"))
			}
			metrics.IncRequests(pc.TenantID, "TRIPWIRE_ABORT", "200")
			metrics.IncTripwireViolations(pc.MatchedRuleID, "outbound_stream")
			if strings.Contains(pc.MatchedRuleID, "CANARY") {
				metrics.IncCanaryDetections(pc.TenantID)
			}
			metrics.IncAuditRecords()
		} else {
			if d.auditLedger != nil {
				_ = d.auditLedger.Record(pc.TenantID, pc.SessionID, "ALLOW", payload, []byte("[STREAM_DONE]"))
			}
			metrics.IncRequests(pc.TenantID, "ALLOW", "200")
			metrics.IncAuditRecords()
			if pc != nil {
				for stageName, durUs := range pc.StageDurations {
					metrics.ObserveStageDuration(stageName, float64(durUs)/1e6)
				}
			}
		}
		return streamErr
	}

	// 5. Synchronous response: read entire body for outbound guardrail inspection
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read upstream response body: %w", err)
	}

	// Run Layer 3 Outbound Inspection (canary leak, secret leak, schema validation)
	if violation := d.outboundEngine.InspectSync(respBody, pc); violation != nil {
		if pc != nil {
			pc.MatchedRuleID = violation.RuleID
			pc.ViolationType = "POLICY_VIOLATION"
			pc.Violations = append(pc.Violations, pipeline.PolicyViolation{
				RuleID:      violation.RuleID,
				Stage:       "outbound_inspection",
				Description: violation.Message,
				Severity:    "CRITICAL",
			})
		}

		errJSON, _ := json.Marshal(map[string]any{
			"error": map[string]any{
				"code":    "POLICY_VIOLATION",
				"rule_id": violation.RuleID,
				"message": violation.Message,
			},
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write(errJSON)

		if d.auditLedger != nil {
			_ = d.auditLedger.Record(pc.TenantID, pc.SessionID, "BLOCK_OUTBOUND", payload, errJSON)
		}
		metrics.IncRequests(pc.TenantID, "BLOCK_OUTBOUND", "502")
		metrics.IncTripwireViolations(violation.RuleID, "outbound_inspection")
		if strings.Contains(violation.RuleID, "CANARY") {
			metrics.IncCanaryDetections(pc.TenantID)
		}
		metrics.IncAuditRecords()
		return errors.New("outbound policy violation detected")
	}

	// Copy allowed response headers
	for k, vv := range resp.Header {
		if hopByHopHeaders[strings.ToLower(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	w.WriteHeader(resp.StatusCode)
	_, writeErr := w.Write(respBody)

	if d.auditLedger != nil {
		_ = d.auditLedger.Record(pc.TenantID, pc.SessionID, "ALLOW", payload, respBody)
	}
	metrics.IncRequests(pc.TenantID, "ALLOW", fmt.Sprint(resp.StatusCode))
	metrics.IncAuditRecords()
	if pc != nil {
		for stageName, durUs := range pc.StageDurations {
			metrics.ObserveStageDuration(stageName, float64(durUs)/1e6)
		}
	}

	return writeErr
}
