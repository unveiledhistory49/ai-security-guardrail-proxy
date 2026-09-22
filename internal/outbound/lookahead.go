package outbound

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"ai-security-guardrail-proxy/internal/pipeline"
)

const (
	// LookaheadWindowSize (W) is the sliding inspection window capacity (128 bytes).
	LookaheadWindowSize = 128

	// OverlapMarginSize (L) is the lookahead overlap margin retained between flushes (64 bytes).
	OverlapMarginSize = 64
)

// ErrTripwireViolation indicates the stream was terminated due to a tripwire trigger.
var ErrTripwireViolation = errors.New("outbound security tripwire triggered: stream aborted")

// InspectionViolation details a security policy violation found in an outbound buffer.
type InspectionViolation struct {
	RuleID  string
	Message string
}

// StreamInspector evaluates a window buffer for canary tokens or leaked secrets.
type StreamInspector interface {
	Inspect(window []byte) *InspectionViolation
}

// StreamInspectorFunc adapts a function signature to the StreamInspector interface.
type StreamInspectorFunc func(window []byte) *InspectionViolation

// Inspect implements StreamInspector.
func (f StreamInspectorFunc) Inspect(window []byte) *InspectionViolation {
	return f(window)
}

// FormatSSEErrorFrame constructs an RFC-compliant SSE error event followed by [DONE].
func FormatSSEErrorFrame(ruleID, message string) []byte {
	return []byte(fmt.Sprintf("event: error\ndata: {\"error\":{\"code\":\"TRIPWIRE_VIOLATION\",\"rule_id\":%q,\"message\":%q}}\n\ndata: [DONE]\n\n", ruleID, message))
}

// SlidingWindowTransformer inspects streaming chunks with a sliding lookahead window.
// It guarantees zero-byte leakage for sensitive patterns of length K <= L spanning chunk boundaries.
type SlidingWindowTransformer struct {
	windowSize  int
	overlapSize int
	inspector   StreamInspector
}

// NewSlidingWindowTransformer initializes a transformer with default W=128, L=64.
func NewSlidingWindowTransformer(inspector StreamInspector) *SlidingWindowTransformer {
	return NewSlidingWindowTransformerWithConfig(LookaheadWindowSize, OverlapMarginSize, inspector)
}

// NewSlidingWindowTransformerWithConfig initializes a transformer with custom parameters.
func NewSlidingWindowTransformerWithConfig(windowSize, overlapSize int, inspector StreamInspector) *SlidingWindowTransformer {
	if windowSize <= 0 {
		windowSize = LookaheadWindowSize
	}
	if overlapSize <= 0 {
		overlapSize = OverlapMarginSize
	}
	return &SlidingWindowTransformer{
		windowSize:  windowSize,
		overlapSize: overlapSize,
		inspector:   inspector,
	}
}

// TransformStream reads raw SSE chunks from upstreamBody, validates them through the sliding
// lookahead window, flushes clean bytes downstream, and immediately severs the connection on tripwire detection.
func (t *SlidingWindowTransformer) TransformStream(
	ctx context.Context,
	cancelUpstream context.CancelFunc,
	upstreamBody io.Reader,
	downstreamWriter io.Writer,
	flusher http.Flusher,
	rawConn net.Conn,
	pc *pipeline.PipelineContext,
) error {
	defer func() {
		if cancelUpstream != nil {
			cancelUpstream()
		}
	}()

	if flusher == nil {
		if f, ok := downstreamWriter.(http.Flusher); ok {
			flusher = f
		}
	}

	windowBuf := make([]byte, 0, t.windowSize*4)
	readBuf := make([]byte, 256)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, readErr := upstreamBody.Read(readBuf)
		if n > 0 {
			windowBuf = append(windowBuf, readBuf[:n]...)

			// When accumulated buffer exceeds LookaheadWindowSize, inspect and release safe head
			for len(windowBuf) >= t.windowSize {
				if t.inspector != nil {
					if violation := t.inspector.Inspect(windowBuf); violation != nil {
						t.executeTripwireAbort(downstreamWriter, flusher, rawConn, cancelUpstream, pc, violation)
						return ErrTripwireViolation
					}
				}

				// Flushable bytes formula: max(0, len(buffer) - L)
				flushable := len(windowBuf) - t.overlapSize
				if flushable > 0 {
					if _, writeErr := downstreamWriter.Write(windowBuf[:flushable]); writeErr != nil {
						return writeErr
					}
					if flusher != nil {
						flusher.Flush()
					}

					// Slide window: retain trailing overlap margin at head of buffer
					copy(windowBuf, windowBuf[flushable:])
					windowBuf = windowBuf[:t.overlapSize]
				} else {
					break
				}
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				// Stream EOF / completion: inspect remaining buffer and flush final clean bytes
				if len(windowBuf) > 0 {
					if t.inspector != nil {
						if violation := t.inspector.Inspect(windowBuf); violation != nil {
							t.executeTripwireAbort(downstreamWriter, flusher, rawConn, cancelUpstream, pc, violation)
							return ErrTripwireViolation
						}
					}
					if _, writeErr := downstreamWriter.Write(windowBuf); writeErr != nil {
						return writeErr
					}
					if flusher != nil {
						flusher.Flush()
					}
					windowBuf = windowBuf[:0]
				}
				return nil
			}
			return readErr
		}
	}
}

// executeTripwireAbort terminates the downstream stream immediately, emits the RFC-compliant
// SSE error event, cancels upstream context, and forcefully closes the TCP socket.
func (t *SlidingWindowTransformer) executeTripwireAbort(
	w io.Writer,
	flusher http.Flusher,
	rawConn net.Conn,
	cancelUpstream context.CancelFunc,
	pc *pipeline.PipelineContext,
	violation *InspectionViolation,
) {
	// 1. Immediately cancel upstream request context to terminate zombie GPU compute
	if cancelUpstream != nil {
		cancelUpstream()
	}

	// 2. Record structured violation on PipelineContext
	if pc != nil {
		pc.MatchedRuleID = violation.RuleID
		pc.ViolationType = "TRIPWIRE_VIOLATION"
		pc.Violations = append(pc.Violations, pipeline.PolicyViolation{
			RuleID:      violation.RuleID,
			Stage:       "outbound_stream_transformer",
			Description: violation.Message,
			Severity:    "CRITICAL",
		})
	}

	// 3. Inject RFC-compliant SSE error frame and [DONE]
	if w != nil {
		frame := FormatSSEErrorFrame(violation.RuleID, violation.Message)
		_, _ = w.Write(frame)
		if flusher != nil {
			flusher.Flush()
		}
	}

	// 4. Forcefully close TCP socket to prevent buffered bytes in kernel queues from leaking
	if rawConn != nil {
		_ = rawConn.Close()
	} else if rw, ok := w.(http.ResponseWriter); ok {
		rc := http.NewResponseController(rw)
		if c, _, err := rc.Hijack(); err == nil && c != nil {
			_ = c.Close()
		}
	}
}
