package metrics

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

// Sub-millisecond histogram buckets for guardrail_stage_duration_seconds.
var DefaultStageDurationBuckets = []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1}

// Label represents a single key-value metric label.
type Label struct {
	Key   string
	Value string
}

func formatLabels(labels []Label) string {
	if len(labels) == 0 {
		return ""
	}
	sorted := make([]Label, len(labels))
	copy(sorted, labels)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Key < sorted[j].Key
	})

	var sb strings.Builder
	sb.WriteByte('{')
	for i, l := range sorted {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(l.Key)
		sb.WriteString(`="`)
		sb.WriteString(l.Value)
		sb.WriteByte('"')
	}
	sb.WriteByte('}')
	return sb.String()
}

func formatHistogramBucketLabels(labels []Label, le string) string {
	all := append([]Label{}, labels...)
	all = append(all, Label{Key: "le", Value: le})
	return formatLabels(all)
}

// CounterVec manages multi-dimensional Prometheus counters.
type CounterVec struct {
	mu     sync.RWMutex
	values map[string]*atomic.Uint64
}

func NewCounterVec() *CounterVec {
	return &CounterVec{
		values: make(map[string]*atomic.Uint64),
	}
}

func (cv *CounterVec) Inc(labels ...Label) {
	key := formatLabels(labels)
	cv.mu.RLock()
	val, ok := cv.values[key]
	cv.mu.RUnlock()

	if !ok {
		cv.mu.Lock()
		val, ok = cv.values[key]
		if !ok {
			val = &atomic.Uint64{}
			cv.values[key] = val
		}
		cv.mu.Unlock()
	}

	val.Add(1)
}

func (cv *CounterVec) Snapshot() map[string]uint64 {
	cv.mu.RLock()
	defer cv.mu.RUnlock()

	res := make(map[string]uint64, len(cv.values))
	for k, v := range cv.values {
		res[k] = v.Load()
	}
	return res
}

// SimpleCounter is a single-value atomic counter.
type SimpleCounter struct {
	val atomic.Uint64
}

func (sc *SimpleCounter) Inc() {
	sc.val.Add(1)
}

func (sc *SimpleCounter) Load() uint64 {
	return sc.val.Load()
}

// Gauge represents a Prometheus gauge.
type Gauge struct {
	val atomic.Int64
}

func (g *Gauge) Set(v int64) {
	g.val.Store(v)
}

func (g *Gauge) Load() int64 {
	return g.val.Load()
}

type histogramSeries struct {
	buckets []atomic.Uint64
	count   atomic.Uint64
	sumBits atomic.Uint64
}

func (hs *histogramSeries) observe(val float64, bounds []float64) {
	for i, bound := range bounds {
		if val <= bound {
			hs.buckets[i].Add(1)
		}
	}
	hs.count.Add(1)

	// Atomic add for float64 using CAS
	for {
		oldBits := hs.sumBits.Load()
		newBits := math.Float64bits(math.Float64frombits(oldBits) + val)
		if hs.sumBits.CompareAndSwap(oldBits, newBits) {
			break
		}
	}
}

// HistogramVec represents a multi-dimensional Prometheus histogram.
type HistogramVec struct {
	mu      sync.RWMutex
	bounds  []float64
	series  map[string]*histogramSeries
	rawKeys map[string][]Label
}

func NewHistogramVec(bounds []float64) *HistogramVec {
	sortedBounds := make([]float64, len(bounds))
	copy(sortedBounds, bounds)
	sort.Float64s(sortedBounds)

	return &HistogramVec{
		bounds:  sortedBounds,
		series:  make(map[string]*histogramSeries),
		rawKeys: make(map[string][]Label),
	}
}

func (hv *HistogramVec) Observe(val float64, labels ...Label) {
	key := formatLabels(labels)
	hv.mu.RLock()
	s, ok := hv.series[key]
	hv.mu.RUnlock()

	if !ok {
		hv.mu.Lock()
		s, ok = hv.series[key]
		if !ok {
			s = &histogramSeries{
				buckets: make([]atomic.Uint64, len(hv.bounds)),
			}
			hv.series[key] = s
			hv.rawKeys[key] = labels
		}
		hv.mu.Unlock()
	}

	s.observe(val, hv.bounds)
}

// Registry stores and exposes proxy metrics in Prometheus text format (0.0.4).
type Registry struct {
	requestsTotal      *CounterVec
	stageDurationSec   *HistogramVec
	tripwireViolations *CounterVec
	canaryDetections   *CounterVec
	circuitBreaker     *Gauge
	auditRecordsTotal  *SimpleCounter
}

// NewRegistry initializes an isolated metrics registry.
func NewRegistry() *Registry {
	return &Registry{
		requestsTotal:      NewCounterVec(),
		stageDurationSec:   NewHistogramVec(DefaultStageDurationBuckets),
		tripwireViolations: NewCounterVec(),
		canaryDetections:   NewCounterVec(),
		circuitBreaker:     &Gauge{},
		auditRecordsTotal:  &SimpleCounter{},
	}
}

// Global default registry used by the proxy.
var DefaultRegistry = NewRegistry()

func (r *Registry) IncRequests(tenant, action, status string) {
	r.requestsTotal.Inc(
		Label{Key: "tenant", Value: tenant},
		Label{Key: "action", Value: action},
		Label{Key: "status", Value: status},
	)
}

func (r *Registry) ObserveStageDuration(stage string, durationSec float64) {
	r.stageDurationSec.Observe(durationSec, Label{Key: "stage", Value: stage})
}

func (r *Registry) IncTripwireViolations(ruleID, stage string) {
	r.tripwireViolations.Inc(
		Label{Key: "rule_id", Value: ruleID},
		Label{Key: "stage", Value: stage},
	)
}

func (r *Registry) IncCanaryDetections(tenant string) {
	r.canaryDetections.Inc(Label{Key: "tenant", Value: tenant})
}

func (r *Registry) SetCircuitBreakerState(state int) {
	r.circuitBreaker.Set(int64(state))
}

func (r *Registry) IncAuditRecords() {
	r.auditRecordsTotal.Inc()
}

// WritePrometheus writes all metrics formatted according to Prometheus text exposition format (0.0.4).
func (r *Registry) WritePrometheus(w io.Writer) error {
	// 1. guardrail_requests_total
	fmt.Fprintln(w, "# HELP guardrail_requests_total Total number of HTTP requests processed across all stages.")
	fmt.Fprintln(w, "# TYPE guardrail_requests_total counter")
	reqSnap := r.requestsTotal.Snapshot()
	var reqKeys []string
	for k := range reqSnap {
		reqKeys = append(reqKeys, k)
	}
	sort.Strings(reqKeys)
	for _, k := range reqKeys {
		fmt.Fprintf(w, "guardrail_requests_total%s %d\n", k, reqSnap[k])
	}
	if len(reqKeys) == 0 {
		fmt.Fprintln(w, "guardrail_requests_total 0")
	}

	// 2. guardrail_stage_duration_seconds
	fmt.Fprintln(w, "# HELP guardrail_stage_duration_seconds Latency of pipeline inspection stages in seconds.")
	fmt.Fprintln(w, "# TYPE guardrail_stage_duration_seconds histogram")
	r.stageDurationSec.mu.RLock()
	var histKeys []string
	for k := range r.stageDurationSec.series {
		histKeys = append(histKeys, k)
	}
	sort.Strings(histKeys)
	for _, k := range histKeys {
		s := r.stageDurationSec.series[k]
		labels := r.stageDurationSec.rawKeys[k]

		for i, bound := range r.stageDurationSec.bounds {
			bLabel := formatHistogramBucketLabels(labels, fmt.Sprintf("%g", bound))
			fmt.Fprintf(w, "guardrail_stage_duration_seconds_bucket%s %d\n", bLabel, s.buckets[i].Load())
		}
		infLabel := formatHistogramBucketLabels(labels, "+Inf")
		fmt.Fprintf(w, "guardrail_stage_duration_seconds_bucket%s %d\n", infLabel, s.count.Load())
		fmt.Fprintf(w, "guardrail_stage_duration_seconds_sum%s %g\n", k, math.Float64frombits(s.sumBits.Load()))
		fmt.Fprintf(w, "guardrail_stage_duration_seconds_count%s %d\n", k, s.count.Load())
	}
	r.stageDurationSec.mu.RUnlock()

	// 3. guardrail_tripwire_violations_total
	fmt.Fprintln(w, "# HELP guardrail_tripwire_violations_total Total security rule tripwire violations intercepted.")
	fmt.Fprintln(w, "# TYPE guardrail_tripwire_violations_total counter")
	tripSnap := r.tripwireViolations.Snapshot()
	var tripKeys []string
	for k := range tripSnap {
		tripKeys = append(tripKeys, k)
	}
	sort.Strings(tripKeys)
	for _, k := range tripKeys {
		fmt.Fprintf(w, "guardrail_tripwire_violations_total%s %d\n", k, tripSnap[k])
	}
	if len(tripKeys) == 0 {
		fmt.Fprintln(w, "guardrail_tripwire_violations_total 0")
	}

	// 4. guardrail_canary_detections_total
	fmt.Fprintln(w, "# HELP guardrail_canary_detections_total Total canary token leak exfiltrations intercepted.")
	fmt.Fprintln(w, "# TYPE guardrail_canary_detections_total counter")
	canarySnap := r.canaryDetections.Snapshot()
	var canaryKeys []string
	for k := range canarySnap {
		canaryKeys = append(canaryKeys, k)
	}
	sort.Strings(canaryKeys)
	for _, k := range canaryKeys {
		fmt.Fprintf(w, "guardrail_canary_detections_total%s %d\n", k, canarySnap[k])
	}
	if len(canaryKeys) == 0 {
		fmt.Fprintln(w, "guardrail_canary_detections_total 0")
	}

	// 5. guardrail_circuit_breaker_state
	fmt.Fprintln(w, "# HELP guardrail_circuit_breaker_state Upstream circuit breaker state: 0=closed, 1=half-open, 2=open.")
	fmt.Fprintln(w, "# TYPE guardrail_circuit_breaker_state gauge")
	fmt.Fprintf(w, "guardrail_circuit_breaker_state %d\n", r.circuitBreaker.Load())

	// 6. guardrail_audit_records_total
	fmt.Fprintln(w, "# HELP guardrail_audit_records_total Total audit journal records generated and queued.")
	fmt.Fprintln(w, "# TYPE guardrail_audit_records_total counter")
	fmt.Fprintf(w, "guardrail_audit_records_total %d\n", r.auditRecordsTotal.Load())

	return nil
}

// Handler returns an http.Handler serving the Prometheus metrics endpoint.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_ = r.WritePrometheus(w)
	})
}

// Package-level forwarders to DefaultRegistry
func IncRequests(tenant, action, status string) {
	DefaultRegistry.IncRequests(tenant, action, status)
}

func ObserveStageDuration(stage string, durationSec float64) {
	DefaultRegistry.ObserveStageDuration(stage, durationSec)
}

func IncTripwireViolations(ruleID, stage string) {
	DefaultRegistry.IncTripwireViolations(ruleID, stage)
}

func IncCanaryDetections(tenant string) {
	DefaultRegistry.IncCanaryDetections(tenant)
}

func SetCircuitBreakerState(state int) {
	DefaultRegistry.SetCircuitBreakerState(state)
}

func IncAuditRecords() {
	DefaultRegistry.IncAuditRecords()
}

func Handler() http.Handler {
	return DefaultRegistry.Handler()
}
