package outbound

import (
	"testing"
)

func TestCanaryDetector_ActiveCanaryMatch(t *testing.T) {
	detector := NewCanaryDetector()
	activeCanary := "SEC-CNR-9f8e7d6c5b4a3210"

	payload := []byte("The model system prompt leaked: SEC-CNR-9f8e7d6c5b4a3210 strictly confidential")
	matched, ruleID, msg := detector.Detect(payload, activeCanary)

	if !matched {
		t.Fatalf("expected canary match for active token, got false")
	}
	if ruleID != RuleCanaryLeakDetected {
		t.Fatalf("expected rule ID %q, got %q", RuleCanaryLeakDetected, ruleID)
	}
	if msg != MsgCanaryLeakDetected {
		t.Fatalf("expected message %q, got %q", MsgCanaryLeakDetected, msg)
	}
}

func TestCanaryDetector_PrefixCanaryMatch(t *testing.T) {
	detector := NewCanaryDetector()
	activeCanary := "SEC-CNR-other-session-1234"

	// Data has general SEC-CNR- prefix even if not matching active token
	payload := []byte("Found SEC-CNR-abcdef0123456789 in completions")
	matched, ruleID, _ := detector.Detect(payload, activeCanary)

	if !matched {
		t.Fatalf("expected canary match on prefix SEC-CNR-, got false")
	}
	if ruleID != RuleCanaryLeakDetected {
		t.Fatalf("expected rule ID %q, got %q", RuleCanaryLeakDetected, ruleID)
	}
}

func TestCanaryDetector_BenignTextPasses(t *testing.T) {
	detector := NewCanaryDetector()
	activeCanary := "SEC-CNR-9f8e7d6c5b4a3210"

	payload := []byte("Here is a clean response with nothing secret. The bird is a yellow canary in a coal mine.")
	matched, _, _ := detector.Detect(payload, activeCanary)

	if matched {
		t.Fatalf("expected no match on benign text, got true")
	}
}

func TestCanaryDetector_NonStreamingResponse(t *testing.T) {
	detector := NewCanaryDetector()
	activeCanary := "SEC-CNR-1122334455667788"

	jsonBody := []byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"Secret code: SEC-CNR-1122334455667788"}}]}`)
	matched, ruleID, _ := detector.Detect(jsonBody, activeCanary)

	if !matched {
		t.Fatalf("expected canary match in non-streaming JSON body, got false")
	}
	if ruleID != RuleCanaryLeakDetected {
		t.Fatalf("expected %q, got %q", RuleCanaryLeakDetected, ruleID)
	}
}
