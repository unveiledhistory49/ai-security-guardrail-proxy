package outbound

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"ai-security-guardrail-proxy/internal/pipeline"
)

// chunkReader returns pre-defined chunks on each Read call.
type chunkReader struct {
	chunks [][]byte
	idx    int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if c.idx >= len(c.chunks) {
		return 0, io.EOF
	}
	chunk := c.chunks[c.idx]
	c.idx++
	n := copy(p, chunk)
	return n, nil
}

type mockFlusher struct {
	flushCount int
}

func (m *mockFlusher) Flush() {
	m.flushCount++
}

func TestLookahead_PatternSplitAcrossTwoChunks(t *testing.T) {
	engine := NewEngine()
	activeCanary := "SEC-CNR-1234567890abcdef"

	pc := &pipeline.PipelineContext{
		CanaryToken: activeCanary,
	}

	// Chunk 1 has the prefix "The secret is SEC-"
	// Chunk 2 has the suffix "CNR-1234567890abcdef"
	cr := &chunkReader{
		chunks: [][]byte{
			[]byte("The secret is SEC-"),
			[]byte("CNR-1234567890abcdef and should never leak."),
		},
	}

	outBuf := &bytes.Buffer{}
	flusher := &mockFlusher{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.ProcessStream(ctx, cancel, cr, outBuf, flusher, nil, pc)
	if err == nil {
		t.Fatalf("expected tripwire error, got nil")
	}
	if !errors.Is(err, ErrTripwireViolation) {
		t.Fatalf("expected ErrTripwireViolation, got %v", err)
	}

	output := outBuf.String()

	// 1. Verify SSE error frame is emitted
	if !strings.Contains(output, "event: error") {
		t.Fatalf("expected SSE error frame, got: %q", output)
	}
	if !strings.Contains(output, "CANARY_LEAK_DETECTED") {
		t.Fatalf("expected CANARY_LEAK_DETECTED in output, got: %q", output)
	}
	if !strings.Contains(output, "data: [DONE]") {
		t.Fatalf("expected [DONE] in error output, got: %q", output)
	}

	// 2. Verify zero canary bytes reach client
	if strings.Contains(output, "SEC-CNR-") {
		t.Fatalf("canary token leaked to client: %q", output)
	}
	if strings.Contains(output, "1234567890abcdef") {
		t.Fatalf("canary suffix leaked to client: %q", output)
	}

	// 3. Verify violation recorded on PipelineContext
	if pc.MatchedRuleID != RuleCanaryLeakDetected {
		t.Fatalf("expected MatchedRuleID %q, got %q", RuleCanaryLeakDetected, pc.MatchedRuleID)
	}
}

func TestLookahead_PatternSplitAcrossThreeChunks(t *testing.T) {
	engine := NewEngine()
	activeCanary := "SEC-CNR-9876543210fedcba"

	pc := &pipeline.PipelineContext{
		CanaryToken: activeCanary,
	}

	// Split canary across 3 chunks: "SEC-", "CNR-9876", "543210fedcba"
	cr := &chunkReader{
		chunks: [][]byte{
			[]byte("Intro text: SEC-"),
			[]byte("CNR-9876"),
			[]byte("543210fedcba is the canary."),
		},
	}

	outBuf := &bytes.Buffer{}
	flusher := &mockFlusher{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.ProcessStream(ctx, cancel, cr, outBuf, flusher, nil, pc)
	if err == nil {
		t.Fatalf("expected tripwire error for 3-chunk canary split, got nil")
	}

	output := outBuf.String()
	if !strings.Contains(output, "CANARY_LEAK_DETECTED") {
		t.Fatalf("expected CANARY_LEAK_DETECTED, got: %q", output)
	}
	if strings.Contains(output, "SEC-CNR-") {
		t.Fatalf("canary bytes leaked to downstream: %q", output)
	}
}

func TestLookahead_SecretSplitAcrossChunks(t *testing.T) {
	engine := NewEngine()
	pc := &pipeline.PipelineContext{}

	// Split AWS key AKIAIOSFODNN7EXAMPLE across 2 chunks: "AKIA" and "IOSFODNN7EXAMPLE"
	// with padding so buffer accumulates past LookaheadWindowSize
	cr := &chunkReader{
		chunks: [][]byte{
			[]byte("Deploying cloud infrastructure with AWS root key: AKIA"),
			[]byte("IOSFODNN7EXAMPLE to access our prod S3 buckets now."),
		},
	}

	outBuf := &bytes.Buffer{}
	flusher := &mockFlusher{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.ProcessStream(ctx, cancel, cr, outBuf, flusher, nil, pc)
	if err == nil {
		t.Fatalf("expected tripwire error for split AWS key, got nil")
	}

	output := outBuf.String()
	if !strings.Contains(output, "OUTBOUND_SECRET_LEAK") {
		t.Fatalf("expected OUTBOUND_SECRET_LEAK, got: %q", output)
	}
	if strings.Contains(output, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("AWS key leaked to downstream: %q", output)
	}
}

func TestLookahead_CleanStreamPassThrough(t *testing.T) {
	engine := NewEngine()
	pc := &pipeline.PipelineContext{}

	chunks := [][]byte{
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n"),
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n"),
		[]byte("data: {\"choices\":[{\"delta\":{\"content\":\"! Have a great day.\"}}]}\n\n"),
		[]byte("data: [DONE]\n\n"),
	}

	cr := &chunkReader{chunks: chunks}
	outBuf := &bytes.Buffer{}
	flusher := &mockFlusher{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.ProcessStream(ctx, cancel, cr, outBuf, flusher, nil, pc)
	if err != nil {
		t.Fatalf("expected clean stream to succeed, got: %v", err)
	}

	expected := string(bytes.Join(chunks, nil))
	actual := outBuf.String()
	if actual != expected {
		t.Fatalf("expected clean output %q, got %q", expected, actual)
	}

	if flusher.flushCount == 0 {
		t.Fatalf("expected at least one flush call, got 0")
	}
}

func TestLookahead_ShortCleanStreamFlushesOnEOF(t *testing.T) {
	engine := NewEngine()
	pc := &pipeline.PipelineContext{}

	// Stream smaller than LookaheadWindowSize (128 bytes)
	cr := &chunkReader{
		chunks: [][]byte{
			[]byte("data: short\n\n"),
		},
	}

	outBuf := &bytes.Buffer{}
	flusher := &mockFlusher{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.ProcessStream(ctx, cancel, cr, outBuf, flusher, nil, pc)
	if err != nil {
		t.Fatalf("expected short clean stream to pass on EOF, got: %v", err)
	}

	if outBuf.String() != "data: short\n\n" {
		t.Fatalf("expected %q, got %q", "data: short\n\n", outBuf.String())
	}
}

func TestLookahead_SecretAtTailDetectedOnEOF(t *testing.T) {
	engine := NewEngine()
	pc := &pipeline.PipelineContext{}

	// Secret is located in short stream (< 128 bytes) right before EOF
	cr := &chunkReader{
		chunks: [][]byte{
			[]byte("secret: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"),
		},
	}

	outBuf := &bytes.Buffer{}
	flusher := &mockFlusher{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := engine.ProcessStream(ctx, cancel, cr, outBuf, flusher, nil, pc)
	if err == nil {
		t.Fatalf("expected tripwire error on EOF tail scan, got nil")
	}

	output := outBuf.String()
	if !strings.Contains(output, "OUTBOUND_SECRET_LEAK") {
		t.Fatalf("expected OUTBOUND_SECRET_LEAK error frame, got: %q", output)
	}
	if strings.Contains(output, "sk-proj-") {
		t.Fatalf("OpenAI key leaked to downstream: %q", output)
	}
}

var _ = http.StatusOK
