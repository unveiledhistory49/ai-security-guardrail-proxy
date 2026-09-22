package pipeline

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// StageResult defines the deterministic outcome of a pipeline inspection stage.
type StageResult int

const (
	// StageContinue indicates the stage passed inspection; continue down the pipeline.
	StageContinue StageResult = iota
	// StageTripwire indicates a critical policy or safety violation; abort pipeline immediately.
	StageTripwire
	// StageDryRun indicates a violation occurred in shadow mode; record violation and continue.
	StageDryRun
	// StageBypass indicates the stage was bypassed via configuration or emergency override; continue.
	StageBypass
)

// String returns the string representation of a StageResult.
func (s StageResult) String() string {
	switch s {
	case StageContinue:
		return "StageContinue"
	case StageTripwire:
		return "StageTripwire"
	case StageDryRun:
		return "StageDryRun"
	case StageBypass:
		return "StageBypass"
	default:
		return fmt.Sprintf("StageResult(%d)", int(s))
	}
}

// Stage defines the contract for an in-process deterministic inspection filter.
type Stage interface {
	Name() string
	Execute(ctx *PipelineContext) StageResult
	FailClosed() bool
}

// PolicyViolation captures structured violation details during inspection.
type PolicyViolation struct {
	RuleID      string `json:"rule_id"`
	Stage       string `json:"stage"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Shadow      bool   `json:"shadow"`
}

// PipelineContext contains all mutable state for a single request evaluation.
// Allocated and recycled via sync.Pool to ensure zero heap allocations per transaction.
type PipelineContext struct {
	// Request Metadata
	StdContext  context.Context
	TenantID    string
	SessionID   string
	RequestID   string
	IsStreaming bool
	StartTime   time.Time

	// Raw and Processed Buffers (reused from pool)
	RawPayload   []byte
	CleanPayload []byte

	// Stateful Inspection Outputs
	CanaryToken   string
	MatchedRuleID string
	ViolationType string
	Violations    []PolicyViolation

	// Microsecond Wall-Clock Timing for Each Stage
	StageDurations map[string]int64

	// Upstream Response Metadata
	UpstreamStatus int
}

// MaxReusableBufferCapacity sets an upper threshold (16MB) to prevent pathological
// memory retention in sync.Pool.
const MaxReusableBufferCapacity = 16 * 1024 * 1024

// ContextPool manages reusable PipelineContext objects.
var ContextPool = sync.Pool{
	New: func() any {
		return &PipelineContext{
			RawPayload:     make([]byte, 0, 16384),
			CleanPayload:   make([]byte, 0, 16384),
			StageDurations: make(map[string]int64, 16),
			Violations:     make([]PolicyViolation, 0, 8),
		}
	},
}

// AcquireContext retrieves a clean PipelineContext from sync.Pool.
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
	pc.IsStreaming = false
	pc.UpstreamStatus = 0
	pc.Violations = pc.Violations[:0]
	clear(pc.StageDurations)
	return pc
}

// ReleaseContext securely resets and returns a PipelineContext to sync.Pool.
func ReleaseContext(pc *PipelineContext) {
	if pc == nil {
		return
	}

	// Security zeroization: wipe payload memory before returning to pool
	for i := range pc.RawPayload {
		pc.RawPayload[i] = 0
	}
	for i := range pc.CleanPayload {
		pc.CleanPayload[i] = 0
	}

	// Discard buffers that grew beyond safe threshold to avoid memory bloat
	if cap(pc.RawPayload) > MaxReusableBufferCapacity {
		pc.RawPayload = make([]byte, 0, 16384)
	} else {
		pc.RawPayload = pc.RawPayload[:0]
	}

	if cap(pc.CleanPayload) > MaxReusableBufferCapacity {
		pc.CleanPayload = make([]byte, 0, 16384)
	} else {
		pc.CleanPayload = pc.CleanPayload[:0]
	}

	pc.Violations = pc.Violations[:0]
	pc.StdContext = nil
	pc.CanaryToken = ""
	pc.MatchedRuleID = ""
	pc.ViolationType = ""
	clear(pc.StageDurations)

	ContextPool.Put(pc)
}

// PipelineRunner executes an ordered sequence of stages deterministically.
type PipelineRunner struct {
	stages []Stage
}

// NewPipelineRunner constructs a new runner with the provided stages.
func NewPipelineRunner(stages ...Stage) *PipelineRunner {
	return &PipelineRunner{stages: stages}
}

// AddStage registers an additional stage to the runner pipeline.
func (pr *PipelineRunner) AddStage(stage Stage) {
	pr.stages = append(pr.stages, stage)
}

// Stages returns the current registered stages.
func (pr *PipelineRunner) Stages() []Stage {
	return pr.stages
}

// Execute runs all stages sequentially, enforcing fail-closed invariant on panics or violations.
func (pr *PipelineRunner) Execute(ctx *PipelineContext) (StageResult, error) {
	for _, stage := range pr.stages {
		stageName := stage.Name()
		start := time.Now()

		var result StageResult
		var panicked bool
		var panicVal any

		// Defensive execution: recover from stage panics and enforce fail-closed/bypass policy
		func() {
			defer func() {
				if r := recover(); r != nil {
					panicked = true
					panicVal = r
				}
			}()
			result = stage.Execute(ctx)
		}()

		durationUs := time.Since(start).Microseconds()
		ctx.StageDurations[stageName] = durationUs

		if panicked {
			if stage.FailClosed() {
				return StageTripwire, fmt.Errorf("stage %q panicked (fail-closed): %v", stageName, panicVal)
			}
			// Fail-open / bypass posture on panic
			continue
		}

		switch result {
		case StageTripwire:
			return StageTripwire, fmt.Errorf("security violation in stage %q: rule=%s violation=%s",
				stageName, ctx.MatchedRuleID, ctx.ViolationType)
		case StageDryRun:
			// Record dry-run / shadow violation and continue pipeline
			ctx.Violations = append(ctx.Violations, PolicyViolation{
				RuleID:      ctx.MatchedRuleID,
				Stage:       stageName,
				Description: ctx.ViolationType,
				Severity:    "shadow",
				Shadow:      true,
			})
			continue
		case StageBypass:
			continue
		case StageContinue:
			continue
		default:
			if stage.FailClosed() {
				return StageTripwire, fmt.Errorf("stage %q returned unrecognized result %v (fail-closed)", stageName, result)
			}
			continue
		}
	}

	return StageContinue, nil
}
