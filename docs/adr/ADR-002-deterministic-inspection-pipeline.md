# ADR-002: Deterministic Inspection Pipeline Architecture

- **Status**: Accepted
- **Deciders**: Core Architecture Team
- **Date**: 2026-09-22
- **Context Files**:
  - [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md)
  - [09-ai-security-guardrail-proxy.md](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md)
  - [OPERATIONS.md](file:///root/ai-security-guardrail-proxy/docs/OPERATIONS.md)
  - [ADR-001-language-and-runtime-selection.md](file:///root/ai-security-guardrail-proxy/docs/adr/ADR-001-language-and-runtime-selection.md)

---

## 1. Context and Problem Statement

The AI Security Guardrail Proxy must enforce a rigorous, sequential chain of security controls on both inbound requests (prompts destined for LLMs) and outbound responses (tokens emitted by LLMs):

```text
[Client Inbound Payload]
       │
       ▼
[Stage 1: Token Entropy & Delimiter Bounds]
       │
       ▼
[Stage 2: Deterministic Injection Signatures]
       │
       ▼
[Stage 3: Secret Detection & PII Pseudonymization]
       │
       ▼
[Stage 4: Canary Token Injection]
       │
       ▼
[Stage 5: Token Rate Limiting & Hard Quotas]
       │
       ▼
[Upstream Model Inference]
       │
       ▼
[Stage 6: Sliding Lookahead Stream Scanner]
       │
       ▼
[Stage 7: Canary Leak & Exfiltration Filter]
       │
       ▼
[Stage 8: Output Schema & Format Validation]
       │
       ▼
[Downstream Verified Delivery]
```

To satisfy our performance and reliability targets (sub-millisecond p99 non-streaming overhead, deterministic fail-closed safety, and bounded memory consumption), the architectural design of this inspection pipeline must solve three critical problems:

1. **Memory Allocation and GC Pressure**: Standard web frameworks allocate intermediate wrapper closures, interfaces, and context key-value maps on every request. In a high-throughput proxy handling tens of thousands of requests per second, heap allocations trigger severe garbage collector churn and latency spikes.
2. **Deterministic Checkpointing & Fail-Closed Guarantees**: If any inspection filter detects an attack, encounters a parsing error, or panics, the proxy must deterministically abort the request, record an auditable cryptographic entry, and sever upstream/downstream connections without leaking uninspected bytes.
3. **Granular Per-Filter Bypass & Dry-Run Operations**: Operators must be able to put individual filters into dry-run (shadow) mode or emergency fail-open bypass during incidents without restructuring control flow or breaking downstream pipeline dependencies.

We must select the structural architecture for the request and response inspection engine.

---

## 2. Decision Drivers

1. **Zero Heap Allocations on Hot Path**: Memory for request evaluation contexts, byte slices, and intermediate inspection state must be pooled and reused via `sync.Pool`.
2. **Strict Deterministic Control Flow**: Explicit, linear execution sequence. Elimination of hidden side effects, implicit callback unwinding, and dynamic reflection-based dispatch.
3. **Deterministic Fail-Closed Semantics**: Unhandled panics, parsing failures, or deadline timeouts in any stage must default to immediate termination and connection tear-down.
4. **Independent Stage Observability**: Microsecond-precision wall-clock timing for every individual inspection filter to rapidly detect ReDoS or pathological inputs.
5. **Configurable Stage Posture (Fail-Closed vs. Fail-Open)**: Granular per-stage failure posture toggling to support emergency operational bypasses without taking down the entire proxy.
6. **Support for Shadow / Dry-Run Testing**: Ability to evaluate candidate rule changes against production traffic, emitting violation audit records without disrupting customer requests.

---

## 3. Considered Options

We evaluated three architectural patterns:

1. **Explicit Linear Stage Machine with Shared Typed `PipelineContext` (Selected)**
2. **Nested Middleware Onion Pattern (`func(http.Handler) http.Handler`)**
3. **Distributed Microservice / Sidecar Mesh Architecture**

---

## 4. Deep Technical Comparison

### 4.1 Comparison Matrix

| Architectural Dimension | Linear Stage Machine (Selected) | Nested Middleware Onion | Distributed Microservice Mesh |
| :--- | :--- | :--- | :--- |
| **Control Flow Model** | Sequential iteration over typed `[]Stage` slice | Recursive function wrapping (`next.ServeHTTP`) | Multi-hop network RPC over gRPC/HTTP |
| **Memory Allocation per Request** | **Zero bytes** (pooled `PipelineContext`) | High (closure allocations, `context.WithValue` map allocations) | Extreme (repeated serialization/deserialization) |
| **Call Stack Depth** | **Flat (2 frames)** | Deep (20–40 nested stack frames) | N/A (distributed process boundaries) |
| **Fail-Closed Guarantee** | Centralized runner catches panics and enforces abort | Decentralized; unhandled panic in inner layer can leak | High risk of partial failures and network partitions |
| **Added Latency Overhead** | **< 0.1ms total pipeline dispatch** | ~0.5ms - 1.2ms (GC and closure overhead) | 10ms - 35ms (network hops and context switches) |
| **Per-Stage Latency Probing** | Native: runner records wall-clock time per slice index | Awkward: requires wrapping each handler with custom timers | Built into service mesh (Envoy/Istio) |
| **Emergency Stage Bypass** | Trivially skipped via boolean flag in stage runner | Requires rebuilding dynamic middleware chain | Requires routing table or mesh policy updates |
| **Operational Complexity** | **Minimal: single binary, zero external daemons** | Minimal: single binary | Complex: multiple containers, service discovery, sidecars |

---

### 4.2 Detailed Evaluation of Rejected Alternatives

#### Alternative 1: Nested Middleware Onion Pattern

*Why it was considered*:
The nested middleware chain is the ubiquitous idiom in Go HTTP frameworks (e.g., Gin, Chi, Echo) and standard library wrappers (`func(http.Handler) http.Handler`).

*Why it was rejected*:
1. **Pervasive Heap Allocations via `context.WithValue`**: Passing state (such as tenant ID, extracted tokens, pseudonymization maps, and canary IDs) between nested handlers requires `context.WithValue`. Go's `context.WithValue` creates a new heap-allocated linked list node on every invocation, causing significant heap allocation churn under 20,000+ RPS.
2. **Inflexible Abortion and Stack Unwinding**: When a security violation occurs deep within an inner middleware layer (e.g., Canary Leak Detected), terminating the request requires either panicking or passing custom error flags back up through 20 layers of `defer` statements. Any buggy middleware in the chain can accidentally catch the error, write a partial HTTP header, or swallow the termination signal.
3. **Opaque Execution Tracing**: Measuring the execution duration of individual stages in a nested onion is notoriously difficult because outer middlewares measure the cumulative time of all inner middlewares. Isolating which specific filter caused a latency spike requires intrusive and error-prone boilerplate in every handler.

#### Alternative 2: Distributed Microservice / Sidecar Mesh Architecture

*Why it was considered*:
Enterprise platforms frequently separate concerns into independent services: a dedicated rate-limiting daemon, an independent DLP scanning service, and an external prompt-injection evaluation sidecar.

*Why it was rejected*:
1. **Violation of Foundational Philosophy**: Our core project specification explicitly requires **zero external daemon dependencies**. Introducing network-attached sidecars or microservices introduces failure domains, RPC timeouts, and connection pool management.
2. **Prohibitive Latency Penalty**: Hopping over loopback or UNIX sockets across three microservices (injection check $\to$ rate limiter $\to$ DLP engine) introduces serialization overhead (Protobuf/JSON) and network scheduling delays of 5ms to 20ms. This obliterates our sub-millisecond p99 latency budget.
3. **Non-Deterministic Network Failure Modes**: If the DLP sidecar experiences a network partition or OOM restart, the proxy must decide whether to stall the request or fail open. Maintaining deterministic security guarantees across a distributed network boundary is needlessly complex.

---

## 5. Decision Outcome

We select the **Explicit Linear Stage Machine with Shared Typed `PipelineContext`**.

### Positive Consequences

1. **Zero Heap Allocations**: The request context, intermediate byte buffers, token counters, and rule-matching slices are pre-allocated on a strongly typed `PipelineContext` struct managed via `sync.Pool`. Zero allocations occur during the evaluation of clean requests.
2. **Deterministic Checkpointing and Panic Recovery**: The centralized `PipelineRunner` controls execution. It wraps every stage execution in a `recover()` block. If any stage panics, the runner intercepts the panic, prevents process termination, enforces the fail-closed invariant, writes an audit record, and issues an immediate HTTP 500 or connection termination.
3. **Microsecond Profiling Built In**: The runner captures wall-clock timestamps before and after each stage invocation, updating Prometheus histograms directly with zero overhead.
4. **First-Class Dry-Run and Bypass Controls**: The runner evaluates whether a stage is enabled, configured for dry-run (shadow) evaluation, or flagged for emergency fail-open bypass before invoking the stage logic.

### Negative Consequences and Mitigations

1. **State Mutation Discipline**: Because stages share a single mutable `PipelineContext`, an errant stage could theoretically corrupt fields intended for downstream stages.
   - *Mitigation*: Strictly enforce encapsulation. Inbound stages write only to their designated result fields (`ctx.InboundSanitizedPrompt`, `ctx.CanaryID`). We mandate unit tests verifying that stages do not overwrite shared metadata.
2. **Coupling to In-Process Lifecycle**: All inspection logic must compile into the single proxy binary.
   - *Mitigation*: The `Stage` interface is modular and decoupled. Adding, testing, or replacing an inspection filter requires only implementing three methods (`Name`, `Execute`, `FailClosed`) and appending the stage to the pipeline registration list.

---

## 6. Implementation Details & Architectural Blueprints

### 6.1 Pipeline Execution Architecture

```mermaid
flowchart TD
    Req[Inbound HTTP / Stream Request] --> Acquire[Acquire PipelineContext from sync.Pool]
    Acquire --> LoopStart[Iterate []Stage Sequence]
    
    subgraph StageRunner [Centralized Pipeline Runner]
        LoopStart --> CheckBypass{Stage in Bypass Gate?}
        CheckBypass -- Yes --> RecordBypass[Record Bypass Metric] --> Advance[Advance to Next Stage]
        CheckBypass -- No --> ExecStage[Execute Stage.Execute ctx]
        
        ExecStage --> CatchPanic{Unhandled Panic?}
        CatchPanic -- Yes --> FailClosed[Enforce Fail-Closed Abort & Log Audit]
        CatchPanic -- No --> EvalResult{Evaluate StageResult}
        
        EvalResult -- StageContinue --> Advance
        EvalResult -- StageTripwire --> HandleTripwire[Enforce Policy: Terminate Socket & Emit Audit]
        EvalResult -- StageDryRun --> LogShadow[Emit Audit Violation: Continue Execution] --> Advance
    end
    
    Advance --> MoreStages{More Stages?}
    MoreStages -- Yes --> LoopStart
    MoreStages -- No --> Release[Release PipelineContext to sync.Pool]
    HandleTripwire --> Release
    FailClosed --> Release
    Release --> Resp[Complete Request / Stream]
```

---

### 6.2 Core Stage and Context Specification

```go
package pipeline

import (
	"context"
	"sync"
	"time"
)

// StageResult defines the deterministic outcome of an inspection stage.
type StageResult int

const (
	StageContinue StageResult = iota // Inspection passed clean; continue pipeline
	StageTripwire                    // Security rule violated; abort request immediately
	StageDryRun                      // Rule violated in shadow mode; record audit, continue
	StageBypass                      // Stage skipped via authorized emergency bypass
)

// Stage defines the contract for an in-process deterministic inspection filter.
type Stage interface {
	Name() string
	Execute(ctx *PipelineContext) StageResult
	FailClosed() bool
}

// PipelineContext contains all mutable state for a single request evaluation.
// Allocated from sync.Pool to ensure zero heap allocations per transaction.
type PipelineContext struct {
	// Request Metadata
	StdContext    context.Context
	TenantID      string
	SessionID     string
	IsStreaming   bool
	StartTime     time.Time

	// Raw and Processed Buffers
	RawPayload    []byte
	CleanPayload  []byte
	
	// Stateful Inspection Outputs
	CanaryToken   string
	MatchedRuleID string
	ViolationType string
	
	// Stage Durations in Microseconds
	StageDurations map[string]int64
}

// ContextPool manages reusable PipelineContext structs.
var ContextPool = sync.Pool{
	New: func() any {
		return &PipelineContext{
			RawPayload:     make([]byte, 0, 16384),
			CleanPayload:   make([]byte, 0, 16384),
			StageDurations: make(map[string]int64, 16),
		}
	},
}

func AcquireContext(ctx context.Context, tenantID, sessionID string) *PipelineContext {
	pc := ContextPool.Get().(*PipelineContext)
	pc.StdContext = ctx
	pc.TenantID = tenantID
	pc.SessionID = sessionID
	pc.StartTime = time.Now()
	pc.RawPayload = pc.RawPayload[:0]
	pc.CleanPayload = pc.CleanPayload[:0]
	pc.CanaryToken = ""
	pc.MatchedRuleID = ""
	pc.ViolationType = ""
	clear(pc.StageDurations)
	return pc
}

func ReleaseContext(pc *PipelineContext) {
	// Zero out sensitive data from buffers before returning to pool
	for i := range pc.RawPayload {
		pc.RawPayload[i] = 0
	}
	for i := range pc.CleanPayload {
		pc.CleanPayload[i] = 0
	}
	pc.RawPayload = pc.RawPayload[:0]
	pc.CleanPayload = pc.CleanPayload[:0]
	pc.StdContext = nil
	ContextPool.Put(pc)
}
```

---

### 6.3 Linear Pipeline Runner Implementation

```go
package pipeline

import (
	"fmt"
	"time"
)

// PipelineRunner executes an ordered sequence of stages deterministically.
type PipelineRunner struct {
	stages []Stage
}

func NewPipelineRunner(stages []Stage) *PipelineRunner {
	return &PipelineRunner{stages: stages}
}

// Execute runs all stages sequentially, enforcing fail-closed invariant on panics or violations.
func (pr *PipelineRunner) Execute(ctx *PipelineContext) (StageResult, error) {
	for _, stage := range pr.stages {
		stageName := stage.Name()
		start := time.Now()

		var result StageResult
		var stageErr error

		// Defensive execution: prevent unhandled stage panics from crashing process
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErr = fmt.Errorf("stage %s panicked: %v", stageName, r)
					if stage.FailClosed() {
						result = StageTripwire
					} else {
						result = StageBypass
					}
				}
			}()
			result = stage.Execute(ctx)
		}()

		durationUs := time.Since(start).Microseconds()
		ctx.StageDurations[stageName] = durationUs

		// Immediate tripwire termination
		if result == StageTripwire {
			if stageErr != nil {
				return StageTripwire, stageErr
			}
			return StageTripwire, fmt.Errorf("security violation in stage %s: rule %s", stageName, ctx.MatchedRuleID)
		}

		// Dry-run violations continue execution but record telemetry
		if result == StageDryRun {
			// Record metric: guardrail_shadow_violations_total{stage=stageName}
			continue
		}
	}

	return StageContinue, nil
}
```

---

## 7. References

- [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md): Small composable components, explicit systems over magic, zero fake scale.
- [09-ai-security-guardrail-proxy.md](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md): Deterministic inspection engine and security model.
- [OPERATIONS.md](file:///root/ai-security-guardrail-proxy/docs/OPERATIONS.md): Operational Runbooks and Emergency Fail-Open Bypass.
