package outbound

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"ai-security-guardrail-proxy/internal/pipeline"
)

// Engine coordinates Layer 3 outbound inspection: sliding lookahead streaming transformer,
// canary token tripwires, credential DLP scanning, and JSON schema validation.
type Engine struct {
	canaryDetector  *CanaryDetector
	dlpScanner      *DLPScanner
	schemaValidator *SchemaValidator
}

// NewEngine constructs a default outbound guardrail engine.
func NewEngine() *Engine {
	return &Engine{
		canaryDetector:  NewCanaryDetector(),
		dlpScanner:      NewDLPScanner(),
		schemaValidator: NewSchemaValidator(),
	}
}

// CanaryDetector returns the underlying CanaryDetector.
func (e *Engine) CanaryDetector() *CanaryDetector {
	return e.canaryDetector
}

// DLPScanner returns the underlying DLPScanner.
func (e *Engine) DLPScanner() *DLPScanner {
	return e.dlpScanner
}

// SchemaValidator returns the underlying SchemaValidator.
func (e *Engine) SchemaValidator() *SchemaValidator {
	return e.schemaValidator
}

// InspectWindow evaluates a byte slice for active canary tokens and secret leakage.
func (e *Engine) InspectWindow(window []byte, activeCanary string) *InspectionViolation {
	if matched, ruleID, msg := e.canaryDetector.Detect(window, activeCanary); matched {
		return &InspectionViolation{RuleID: ruleID, Message: msg}
	}
	if matched, ruleID, msg := e.dlpScanner.Detect(window); matched {
		return &InspectionViolation{RuleID: ruleID, Message: msg}
	}
	return nil
}

// InspectSync evaluates a synchronous response body for canary leakage, secret leakage,
// and JSON schema compliance.
func (e *Engine) InspectSync(body []byte, pc *pipeline.PipelineContext) *InspectionViolation {
	activeCanary := ""
	if pc != nil {
		activeCanary = pc.CanaryToken
	}

	// 1. Canary Token Tripwire Check
	if matched, ruleID, msg := e.canaryDetector.Detect(body, activeCanary); matched {
		return &InspectionViolation{RuleID: ruleID, Message: msg}
	}

	// 2. Secret and Credential DLP Check
	if matched, ruleID, msg := e.dlpScanner.Detect(body); matched {
		return &InspectionViolation{RuleID: ruleID, Message: msg}
	}

	// 3. JSON Schema & Tool Call Validation
	if err := e.schemaValidator.Validate(body); err != nil {
		return &InspectionViolation{
			RuleID:  RuleSchemaValidationFailed,
			Message: fmt.Sprintf("Outbound JSON schema validation failed: %v", err),
		}
	}

	return nil
}

// ProcessStream attaches a sliding lookahead window transformer to an outbound SSE stream.
func (e *Engine) ProcessStream(
	ctx context.Context,
	cancelUpstream context.CancelFunc,
	upstreamBody io.Reader,
	downstreamWriter io.Writer,
	flusher http.Flusher,
	rawConn net.Conn,
	pc *pipeline.PipelineContext,
) error {
	activeCanary := ""
	if pc != nil {
		activeCanary = pc.CanaryToken
	}

	inspector := StreamInspectorFunc(func(window []byte) *InspectionViolation {
		return e.InspectWindow(window, activeCanary)
	})

	transformer := NewSlidingWindowTransformer(inspector)
	return transformer.TransformStream(ctx, cancelUpstream, upstreamBody, downstreamWriter, flusher, rawConn, pc)
}
