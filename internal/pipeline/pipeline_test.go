package pipeline

import (
	"context"
	"errors"
	"testing"
	"time"
)

type mockStage struct {
	name       string
	failClosed bool
	executeFn  func(ctx *PipelineContext) StageResult
}

func (m *mockStage) Name() string                     { return m.name }
func (m *mockStage) FailClosed() bool                 { return m.failClosed }
func (m *mockStage) Execute(ctx *PipelineContext) StageResult {
	if m.executeFn != nil {
		return m.executeFn(ctx)
	}
	return StageContinue
}

func TestPipelineStageOrdering(t *testing.T) {
	var executionOrder []string

	s1 := &mockStage{
		name:       "stage1",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			executionOrder = append(executionOrder, "stage1")
			return StageContinue
		},
	}
	s2 := &mockStage{
		name:       "stage2",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			executionOrder = append(executionOrder, "stage2")
			return StageContinue
		},
	}
	s3 := &mockStage{
		name:       "stage3",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			executionOrder = append(executionOrder, "stage3")
			return StageContinue
		},
	}

	runner := NewPipelineRunner(s1, s2, s3)
	ctx := AcquireContext(context.Background(), "t1", "s1")
	defer ReleaseContext(ctx)

	res, err := runner.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}

	if len(executionOrder) != 3 ||
		executionOrder[0] != "stage1" ||
		executionOrder[1] != "stage2" ||
		executionOrder[2] != "stage3" {
		t.Fatalf("stages executed in unexpected order: %v", executionOrder)
	}

	// Verify microsecond timings were recorded
	for _, name := range []string{"stage1", "stage2", "stage3"} {
		if _, ok := ctx.StageDurations[name]; !ok {
			t.Fatalf("timing for %s was not recorded", name)
		}
	}
}

func TestPipelineTripwireHaltsExecution(t *testing.T) {
	var executed []string

	s1 := &mockStage{
		name:       "stage1",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			executed = append(executed, "stage1")
			return StageContinue
		},
	}
	s2 := &mockStage{
		name:       "stage2_tripwire",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			executed = append(executed, "stage2_tripwire")
			ctx.MatchedRuleID = "RULE_SQLI"
			ctx.ViolationType = "INJECTION_DETECTED"
			return StageTripwire
		},
	}
	s3 := &mockStage{
		name:       "stage3_unreached",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			executed = append(executed, "stage3_unreached")
			return StageContinue
		},
	}

	runner := NewPipelineRunner(s1, s2, s3)
	ctx := AcquireContext(context.Background(), "t1", "s1")
	defer ReleaseContext(ctx)

	res, err := runner.Execute(ctx)
	if err == nil {
		t.Fatalf("expected error from tripwire stage, got nil")
	}
	if res != StageTripwire {
		t.Fatalf("expected StageTripwire, got %v", res)
	}

	if len(executed) != 2 {
		t.Fatalf("expected exactly 2 stages executed, got %d (%v)", len(executed), executed)
	}
	if executed[0] != "stage1" || executed[1] != "stage2_tripwire" {
		t.Fatalf("unexpected executed stages: %v", executed)
	}
}

func TestPipelinePanicFailClosed(t *testing.T) {
	sPanic := &mockStage{
		name:       "panicking_stage",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			panic("unexpected nil pointer dereference in stage")
		},
	}

	runner := NewPipelineRunner(sPanic)
	ctx := AcquireContext(context.Background(), "t1", "s1")
	defer ReleaseContext(ctx)

	res, err := runner.Execute(ctx)
	if err == nil {
		t.Fatalf("expected error on panic with fail-closed, got nil")
	}
	if res != StageTripwire {
		t.Fatalf("expected StageTripwire on panic with fail-closed, got %v", res)
	}
}

func TestPipelinePanicFailOpen(t *testing.T) {
	var s2Ran bool

	sPanic := &mockStage{
		name:       "panicking_stage_fail_open",
		failClosed: false,
		executeFn: func(ctx *PipelineContext) StageResult {
			panic("transient failure in non-critical stage")
		},
	}
	s2 := &mockStage{
		name:       "stage2",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			s2Ran = true
			return StageContinue
		},
	}

	runner := NewPipelineRunner(sPanic, s2)
	ctx := AcquireContext(context.Background(), "t1", "s1")
	defer ReleaseContext(ctx)

	res, err := runner.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error on fail-open panic: %v", err)
	}
	if res != StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}
	if !s2Ran {
		t.Fatalf("expected stage2 to run after fail-open panic in stage 1")
	}
}

func TestPipelineDryRunAndBypass(t *testing.T) {
	sDryRun := &mockStage{
		name:       "shadow_stage",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			ctx.MatchedRuleID = "SHADOW_RULE_1"
			ctx.ViolationType = "SHADOW_ALERT"
			return StageDryRun
		},
	}
	sBypass := &mockStage{
		name:       "bypassed_stage",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			return StageBypass
		},
	}
	sFinal := &mockStage{
		name:       "final_stage",
		failClosed: true,
		executeFn: func(ctx *PipelineContext) StageResult {
			return StageContinue
		},
	}

	runner := NewPipelineRunner(sDryRun, sBypass, sFinal)
	ctx := AcquireContext(context.Background(), "t1", "s1")
	defer ReleaseContext(ctx)

	res, err := runner.Execute(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}
	if len(ctx.Violations) != 1 {
		t.Fatalf("expected 1 shadow violation recorded, got %d", len(ctx.Violations))
	}
	if ctx.Violations[0].RuleID != "SHADOW_RULE_1" || !ctx.Violations[0].Shadow {
		t.Fatalf("shadow violation mismatch: %+v", ctx.Violations[0])
	}
}

func TestContextPoolReuseAndZeroization(t *testing.T) {
	ctx := AcquireContext(context.Background(), "tenant-xyz", "session-123")
	ctx.RawPayload = append(ctx.RawPayload, []byte("super-secret-api-key-here")...)
	ctx.CleanPayload = append(ctx.CleanPayload, []byte("sanitized-content")...)
	ctx.StageDurations["stageA"] = 42
	ctx.CanaryToken = "CANARY-123"
	ctx.MatchedRuleID = "RULE-X"
	ctx.ViolationType = "SECRET_LEAK"

	// Retain pointer to slice backing array to verify zeroization
	rawBacking := ctx.RawPayload[:len(ctx.RawPayload)]

	ReleaseContext(ctx)

	// Verify backing array was zeroized
	for i, b := range rawBacking {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroized (found %d)", i, b)
		}
	}

	// Acquire again from pool
	ctx2 := AcquireContext(context.Background(), "tenant-new", "session-456")
	defer ReleaseContext(ctx2)

	if ctx2.TenantID != "tenant-new" {
		t.Fatalf("expected tenant-new, got %s", ctx2.TenantID)
	}
	if len(ctx2.RawPayload) != 0 {
		t.Fatalf("expected reset RawPayload length 0, got %d", len(ctx2.RawPayload))
	}
	if len(ctx2.CleanPayload) != 0 {
		t.Fatalf("expected reset CleanPayload length 0, got %d", len(ctx2.CleanPayload))
	}
	if ctx2.CanaryToken != "" {
		t.Fatalf("expected empty canary token, got %s", ctx2.CanaryToken)
	}
	if len(ctx2.StageDurations) != 0 {
		t.Fatalf("expected empty stage durations, got %v", ctx2.StageDurations)
	}
}

func BenchmarkPipelineExecution(b *testing.B) {
	s1 := &mockStage{name: "stage1", failClosed: true}
	s2 := &mockStage{name: "stage2", failClosed: true}
	runner := NewPipelineRunner(s1, s2)
	bg := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctx := AcquireContext(bg, "bench-tenant", "bench-session")
		_, err := runner.Execute(ctx)
		if err != nil {
			b.Fatal(err)
		}
		ReleaseContext(ctx)
	}
}

// Ensure mockStage implements Stage interface at compile-time.
var _ Stage = (*mockStage)(nil)
var _ = errors.New
var _ = time.Second
