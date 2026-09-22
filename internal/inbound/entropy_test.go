package inbound

import (
	"context"
	"math"
	"strings"
	"testing"

	"ai-security-guardrail-proxy/internal/pipeline"
)

func TestShannonEntropy_Calculation(t *testing.T) {
	// 1. Identical bytes: entropy = 0.0
	zeros := []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	hZeros := ShannonEntropy(zeros)
	if math.Abs(hZeros-0.0) > 0.0001 {
		t.Fatalf("expected entropy 0.0 for identical bytes, got %f", hZeros)
	}

	// 2. English sentence: expected 3.5 <= H <= 4.5
	english := []byte("The quick brown fox jumps over the lazy dog in the warm summer afternoon.")
	hEnglish := ShannonEntropy(english)
	if hEnglish < 3.5 || hEnglish > 4.5 {
		t.Fatalf("expected English entropy between 3.5 and 4.5, got %f", hEnglish)
	}

	// 3. Base64 encoded payload: expected H >= 5.0
	b64 := []byte("VGhpcyBpcyBhbiBhZHZlcnNhcmlhbCBwcm9tcHQgaW5qZWN0aW9uIHBheWxvYWQgYmFzZTY0IGVuY29kZWQgdG8gZXZhZGUgZmlsdGVycw==")
	hB64 := ShannonEntropy(b64)
	if hB64 < 4.8 {
		t.Fatalf("expected Base64 entropy >= 4.8, got %f", hB64)
	}
}

func TestEntropyAnalyzer_LowEntropyRepetition(t *testing.T) {
	analyzer := NewEntropyAnalyzer()

	// 200 identical characters: token repetition attack
	repetition := strings.Repeat("A", 200)
	payload := `{"messages":[{"role":"user","content":"` + repetition + `"}]}`

	pc := pipeline.AcquireContext(context.Background(), "test-tenant", "test-session")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(payload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(payload)...)

	res := analyzer.Execute(pc)
	if res != pipeline.StageTripwire {
		t.Fatalf("expected StageTripwire on token repetition, got %v", res)
	}
	if pc.MatchedRuleID != "ENTROPY_LOW_REPETITION" {
		t.Fatalf("expected ENTROPY_LOW_REPETITION, got %s", pc.MatchedRuleID)
	}
}

func TestEntropyAnalyzer_HighEntropyObfuscation(t *testing.T) {
	analyzer := NewEntropyAnalyzer()

	b64Obfuscation := "VGhpcyBpcyBhbiBhZHZlcnNhcmlhbCBwcm9tcHQgaW5qZWN0aW9uIHBheWxvYWQgYmFzZTY0IGVuY29kZWQgdG8gZXZhZGUgZmlsdGVycw=="
	payload := `{"messages":[{"role":"user","content":"Execute: ` + b64Obfuscation + `"}]}`

	pc := pipeline.AcquireContext(context.Background(), "test-tenant", "test-session")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(payload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(payload)...)

	res := analyzer.Execute(pc)
	if res != pipeline.StageTripwire {
		t.Fatalf("expected StageTripwire on high-entropy obfuscation, got %v", res)
	}
	if pc.MatchedRuleID != "ENTROPY_HIGH_OBFUSCATION" {
		t.Fatalf("expected ENTROPY_HIGH_OBFUSCATION, got %s", pc.MatchedRuleID)
	}
}

func TestEntropyAnalyzer_SourceCodePasses(t *testing.T) {
	analyzer := NewEntropyAnalyzer()

	codePayload := `{"messages":[{"role":"user","content":"def calculate_fibonacci(n):\n    if n <= 1:\n        return n\n    return calculate_fibonacci(n-1) + calculate_fibonacci(n-2)\n"}]}`

	pc := pipeline.AcquireContext(context.Background(), "test-tenant", "test-session")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(codePayload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(codePayload)...)

	res := analyzer.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue for valid source code, got %v", res)
	}
	if pc.MatchedRuleID != "" {
		t.Fatalf("expected empty rule on valid code, got %s", pc.MatchedRuleID)
	}
}

func TestEntropyAnalyzer_BenignPromptPasses(t *testing.T) {
	analyzer := NewEntropyAnalyzer()

	benignPayload := `{"messages":[{"role":"user","content":"Could you please help me understand how cellular respiration generates ATP?"}]}`

	pc := pipeline.AcquireContext(context.Background(), "test-tenant", "test-session")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(benignPayload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(benignPayload)...)

	res := analyzer.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue for benign text, got %v", res)
	}
}
