package outbound

import (
	"bytes"
)

const (
	// CanaryPrefix identifies the prefix for all generated canary tokens.
	CanaryPrefix = "SEC-CNR-"

	// RuleCanaryLeakDetected is the rule identifier for canary token exfiltration.
	RuleCanaryLeakDetected = "CANARY_LEAK_DETECTED"

	// MsgCanaryLeakDetected is the standard message for canary tripwire violations.
	MsgCanaryLeakDetected = "Response stream aborted due to canary token detection"
)

// CanaryDetector inspects byte slices for active or general canary tokens.
type CanaryDetector struct{}

// NewCanaryDetector constructs a new CanaryDetector.
func NewCanaryDetector() *CanaryDetector {
	return &CanaryDetector{}
}

// Detect checks if the data contains the session's active canary token or the general prefix.
// Returns matched, ruleID, and description message.
func (c *CanaryDetector) Detect(data []byte, activeCanary string) (bool, string, string) {
	if activeCanary != "" && bytes.Contains(data, []byte(activeCanary)) {
		return true, RuleCanaryLeakDetected, MsgCanaryLeakDetected
	}
	if bytes.Contains(data, []byte(CanaryPrefix)) {
		return true, RuleCanaryLeakDetected, MsgCanaryLeakDetected
	}
	return false, "", ""
}
