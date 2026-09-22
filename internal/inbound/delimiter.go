package inbound

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"ai-security-guardrail-proxy/internal/pipeline"
)

// Dangerous Unicode runes: Zero-width characters and Bidirectional override/isolate markers.
var dangerousRunes = map[rune]bool{
	0x200B: true, // Zero Width Space (ZWSP)
	0x200C: true, // Zero Width Non-Joiner (ZWNJ)
	0x200D: true, // Zero Width Joiner (ZWJ)
	0x200E: true, // Left-to-Right Mark (LRM)
	0x200F: true, // Right-to-Left Mark (RLM)
	0xFEFF: true, // Zero Width No-Break Space / BOM
	0x202A: true, // Left-to-Right Embedding (LRE)
	0x202B: true, // Right-to-Left Embedding (RLE)
	0x202C: true, // Pop Directional Formatting (PDF)
	0x202D: true, // Left-to-Right Override (LRO)
	0x202E: true, // Right-to-Left Override (RLO)
	0x2066: true, // Left-to-Right Isolate (LRI)
	0x2067: true, // Right-to-Left Isolate (RLI)
	0x2068: true, // First Strong Isolate (FSI)
	0x2069: true, // Pop Directional Isolate (PDI)
}

// Escaped representations of dangerous unicode characters often seen in JSON payloads.
var dangerousJSONEscapes = []string{
	`\u200b`, `\u200B`,
	`\u200c`, `\u200C`,
	`\u200d`, `\u200D`,
	`\u200e`, `\u200E`,
	`\u200f`, `\u200F`,
	`\ufeff`, `\uFEFF`,
	`\u202a`, `\u202A`,
	`\u202b`, `\u202B`,
	`\u202c`, `\u202C`,
	`\u202d`, `\u202D`,
	`\u202e`, `\u202E`,
	`\u2066`,
	`\u2067`,
	`\u2068`,
	`\u2069`,
}

// Framing tokens that attackers use to break out of user prompt contexts.
var unauthorizedFramingTokens = []string{
	"<|im_start|>",
	"<|im_end|>",
	"[inst]",
	"[/inst]",
	"<<sys>>",
	"<</sys>>",
	"<s>",
	"</s>",
	"<|endoftext|>",
}

// DelimiterSanitizer strips bidirectional overrides, zero-width spaces,
// and rejects unauthorized prompt framing tokens.
type DelimiterSanitizer struct{}

// NewDelimiterSanitizer constructs a new DelimiterSanitizer stage.
func NewDelimiterSanitizer() *DelimiterSanitizer {
	return &DelimiterSanitizer{}
}

// Name returns the unique stage identifier.
func (d *DelimiterSanitizer) Name() string {
	return "delimiter_sanitizer"
}

// FailClosed returns true to guarantee fail-closed behavior on unhandled panics.
func (d *DelimiterSanitizer) FailClosed() bool {
	return true
}

// Execute performs Unicode sanitization and delimiter breakout inspection.
func (d *DelimiterSanitizer) Execute(ctx *pipeline.PipelineContext) pipeline.StageResult {
	if len(ctx.CleanPayload) == 0 {
		return pipeline.StageContinue
	}

	// 1. Strip raw dangerous Unicode runes
	sanitized := StripDangerousRunes(ctx.CleanPayload)

	// 2. Strip escaped representations from JSON strings
	for _, esc := range dangerousJSONEscapes {
		if bytes.Contains(sanitized, []byte(esc)) {
			sanitized = bytes.ReplaceAll(sanitized, []byte(esc), nil)
		}
	}

	// Update CleanPayload with the sanitized byte sequence
	ctx.CleanPayload = sanitized

	// 3. Normalize escaped angle brackets and brackets to detect obfuscated framing tokens
	normalizedStr := strings.ToLower(string(sanitized))
	normalizedStr = strings.ReplaceAll(normalizedStr, `\u003c`, "<")
	normalizedStr = strings.ReplaceAll(normalizedStr, `\u003e`, ">")
	normalizedStr = strings.ReplaceAll(normalizedStr, `\u005b`, "[")
	normalizedStr = strings.ReplaceAll(normalizedStr, `\u005d`, "]")

	// 4. Scan for unauthorized model prompt framing tokens
	for _, token := range unauthorizedFramingTokens {
		if strings.Contains(normalizedStr, token) {
			ctx.MatchedRuleID = "DELIMITER_BREAKOUT"
			ctx.ViolationType = "FRAMING_TOKEN: " + token
			return pipeline.StageTripwire
		}
	}

	return pipeline.StageContinue
}

// StripDangerousRunes removes zero-width characters and bidirectional overrides.
func StripDangerousRunes(input []byte) []byte {
	var buf bytes.Buffer
	buf.Grow(len(input))

	i := 0
	for i < len(input) {
		r, size := utf8.DecodeRune(input[i:])
		if r == utf8.RuneError && size == 1 {
			// Copy invalid byte directly
			buf.WriteByte(input[i])
			i++
			continue
		}
		if !dangerousRunes[r] {
			buf.Write(input[i : i+size])
		}
		i += size
	}

	return buf.Bytes()
}
