package inbound

import (
	"encoding/json"
	"math"
	"strings"

	"ai-security-guardrail-proxy/internal/pipeline"
)

const (
	// DefaultHighEntropyThreshold marks the boundary for packed/base64 obfuscation.
	DefaultHighEntropyThreshold = 4.8
	// DefaultLowEntropyThreshold marks token repetition DoS attacks.
	DefaultLowEntropyThreshold = 1.0
	// MinLengthForLowEntropy enforces bounds so short benign inputs aren't flagged.
	MinLengthForLowEntropy = 100
	// WindowSize for sliding lookahead entropy calculation.
	EntropyWindowSize = 128
	// WindowStep for sliding lookahead entropy calculation.
	EntropyWindowStep = 32
)

// EntropyAnalyzer calculates Shannon entropy over request prompts
// to flag obfuscated high-entropy injections and token repetition DoS attacks.
type EntropyAnalyzer struct {
	highThreshold float64
	lowThreshold  float64
}

// NewEntropyAnalyzer initializes an EntropyAnalyzer with standard bounds.
func NewEntropyAnalyzer() *EntropyAnalyzer {
	return &EntropyAnalyzer{
		highThreshold: DefaultHighEntropyThreshold,
		lowThreshold:  DefaultLowEntropyThreshold,
	}
}

// Name returns the stage name.
func (e *EntropyAnalyzer) Name() string {
	return "entropy_analyzer"
}

// FailClosed returns true to guarantee fail-closed security.
func (e *EntropyAnalyzer) FailClosed() bool {
	return true
}

// Execute computes Shannon entropy over prompt strings.
func (e *EntropyAnalyzer) Execute(ctx *pipeline.PipelineContext) pipeline.StageResult {
	if len(ctx.CleanPayload) == 0 {
		return pipeline.StageContinue
	}

	texts := extractInspectableTexts(ctx.CleanPayload)

	for _, text := range texts {
		data := []byte(text)

		// 1. Low Entropy Check for Token Repetition DoS
		if len(data) >= MinLengthForLowEntropy {
			h := ShannonEntropy(data)
			if h <= e.lowThreshold {
				ctx.MatchedRuleID = "ENTROPY_LOW_REPETITION"
				ctx.ViolationType = "DOS_REPETITION: abnormally low entropy"
				return pipeline.StageTripwire
			}
		}

		// 2. High Entropy Check for Obfuscated Injections (Base64/Hex/Shellcode)
		if e.hasHighEntropyAnomaly(text) {
			ctx.MatchedRuleID = "ENTROPY_HIGH_OBFUSCATION"
			ctx.ViolationType = "OBFUSCATION: abnormally high entropy in non-code text"
			return pipeline.StageTripwire
		}
	}

	return pipeline.StageContinue
}

// ShannonEntropy calculates H(X) = -sum(P(b) * log2(P(b))) for a byte sequence.
func ShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	var counts [256]int
	for _, b := range data {
		counts[b]++
	}

	n := float64(len(data))
	var entropy float64

	for _, count := range counts {
		if count > 0 {
			p := float64(count) / n
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (e *EntropyAnalyzer) hasHighEntropyAnomaly(text string) bool {
	// If text is legitimate source code, skip high-entropy rejection
	if isCodeText(text) {
		return false
	}

	// Check individual tokens: long contiguous alphanumeric/base64 tokens
	tokens := strings.Fields(text)
	for _, tok := range tokens {
		if len(tok) >= 40 && isLikelyBase64OrHex(tok) {
			h := ShannonEntropy([]byte(tok))
			if h >= e.highThreshold {
				return true
			}
		}
	}

	// Check sliding window across text for continuous high-entropy packed sections
	data := []byte(text)
	if len(data) >= EntropyWindowSize {
		for i := 0; i+EntropyWindowSize <= len(data); i += EntropyWindowStep {
			chunk := data[i : i+EntropyWindowSize]
			chunkStr := string(chunk)
			spaces := strings.Count(chunkStr, " ")
			if spaces <= 2 && isLikelyBase64OrHex(chunkStr) {
				h := ShannonEntropy(chunk)
				if h >= e.highThreshold && !isCodeText(chunkStr) {
					return true
				}
			}
		}
	}

	return false
}

func isLikelyBase64OrHex(tok string) bool {
	// Check if token contains predominantly base64 or hex characters without spaces
	base64Count := 0
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '=' || c == '_' || c == '-' {
			base64Count++
		}
	}
	return float64(base64Count)/float64(len(tok)) >= 0.95
}

func isCodeText(text string) bool {
	codeKeywords := []string{
		"def ", "function ", "func ", "import ", "class ", "return ",
		"var ", "let ", "const ", "public ", "private ", "void ", "int ",
		"package ", "struct ", "echo ", "console.log", "print(", "<?php",
		"#include", "using namespace", "SELECT ", "FROM ", "WHERE ",
	}

	keywordMatches := 0
	for _, kw := range codeKeywords {
		if strings.Contains(text, kw) {
			keywordMatches++
			if keywordMatches >= 2 {
				return true
			}
		}
	}

	// Also check for code-like punctuation density (braces, semicolons, parentheses)
	if len(text) > 40 {
		var punctuation int
		for i := 0; i < len(text); i++ {
			c := text[i]
			if c == '{' || c == '}' || c == ';' || c == '(' || c == ')' || c == '[' || c == ']' || c == '=' {
				punctuation++
			}
		}
		// Code typically has high punctuation count combined with spaces and newlines
		spaces := strings.Count(text, " ") + strings.Count(text, "\n") + strings.Count(text, "\t")
		if keywordMatches >= 1 && punctuation >= 3 && spaces >= 4 {
			return true
		}
	}

	return false
}

func extractInspectableTexts(payload []byte) []string {
	var results []string

	// Try OpenAI Chat Completion format
	var chatReq struct {
		Prompt   any `json:"prompt"`
		Messages []struct {
			Role    string `json:"role"`
			Content any    `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(payload, &chatReq); err == nil {
		for _, msg := range chatReq.Messages {
			if strContent, ok := msg.Content.(string); ok && strContent != "" {
				results = append(results, strContent)
			}
		}
		if strPrompt, ok := chatReq.Prompt.(string); ok && strPrompt != "" {
			results = append(results, strPrompt)
		}
	}

	// Fallback to raw payload string if no structured messages found
	if len(results) == 0 {
		results = append(results, string(payload))
	}

	return results
}
