package inbound

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ai-security-guardrail-proxy/internal/pipeline"
)

func TestCanarySynthesizer_TokenFormatAndUniqueness(t *testing.T) {
	synthesizer := NewCanarySynthesizer(DefaultCanarySeed)

	token1 := synthesizer.GenerateToken("tenant-1", "session-a")
	token2 := synthesizer.GenerateToken("tenant-1", "session-a")
	token3 := synthesizer.GenerateToken("tenant-2", "session-b")

	if !strings.HasPrefix(token1, "SEC-CNR-") {
		t.Fatalf("expected prefix SEC-CNR-, got %s", token1)
	}
	if len(token1) != 24 {
		t.Fatalf("expected canary token length 24, got %d (%s)", len(token1), token1)
	}
	if token1 == token2 {
		t.Fatalf("expected unique tokens across sequential invocations: %s == %s", token1, token2)
	}
	if token1 == token3 {
		t.Fatalf("expected different tokens for different tenants: %s == %s", token1, token3)
	}
}

func TestCanarySynthesizer_InjectIntoExistingSystemMessage(t *testing.T) {
	synthesizer := NewCanarySynthesizer(DefaultCanarySeed)

	payload := `{"messages":[{"role":"system","content":"Base instructions."},{"role":"user","content":"Hi"}]}`

	pc := pipeline.AcquireContext(context.Background(), "tenant-canary", "session-canary-1")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(payload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(payload)...)

	res := synthesizer.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}

	if pc.CanaryToken == "" || !strings.HasPrefix(pc.CanaryToken, "SEC-CNR-") {
		t.Fatalf("expected valid CanaryToken on context, got %q", pc.CanaryToken)
	}

	var parsed map[string]any
	if err := json.Unmarshal(pc.CleanPayload, &parsed); err != nil {
		t.Fatalf("failed to unmarshal modified CleanPayload: %v", err)
	}

	msgs := parsed["messages"].([]any)
	sysMsg := msgs[0].(map[string]any)
	sysContent := sysMsg["content"].(string)

	if !strings.Contains(sysContent, "Base instructions.") {
		t.Errorf("original system message content lost: %s", sysContent)
	}
	if !strings.Contains(sysContent, pc.CanaryToken) {
		t.Errorf("canary token not found in system content: %s", sysContent)
	}
}

func TestCanarySynthesizer_PrependNewSystemMessage(t *testing.T) {
	synthesizer := NewCanarySynthesizer(DefaultCanarySeed)

	// User message only, no system message
	payload := `{"messages":[{"role":"user","content":"Hello"}]}`

	pc := pipeline.AcquireContext(context.Background(), "tenant-canary", "session-canary-2")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(payload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(payload)...)

	res := synthesizer.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}

	var parsed map[string]any
	if err := json.Unmarshal(pc.CleanPayload, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	msgs := parsed["messages"].([]any)
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages after system message prepended, got %d", len(msgs))
	}

	firstMsg := msgs[0].(map[string]any)
	if firstMsg["role"] != "system" {
		t.Fatalf("expected prepended message to have role 'system', got %v", firstMsg["role"])
	}
	if !strings.Contains(firstMsg["content"].(string), pc.CanaryToken) {
		t.Fatalf("expected prepended system message to contain canary token %s", pc.CanaryToken)
	}
}

func TestCanarySynthesizer_InjectIntoPromptField(t *testing.T) {
	synthesizer := NewCanarySynthesizer(DefaultCanarySeed)

	payload := `{"prompt":"Translate to French"}`

	pc := pipeline.AcquireContext(context.Background(), "tenant-canary", "session-canary-3")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(payload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(payload)...)

	res := synthesizer.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}

	var parsed map[string]any
	if err := json.Unmarshal(pc.CleanPayload, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	prompt := parsed["prompt"].(string)
	if !strings.Contains(prompt, pc.CanaryToken) {
		t.Fatalf("canary not found in prompt: %s", prompt)
	}
	if !strings.Contains(prompt, "Translate to French") {
		t.Fatalf("original prompt content lost: %s", prompt)
	}
}
