package inbound

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"ai-security-guardrail-proxy/internal/pipeline"
)

// Precompiled linear-time DFA regular expressions (RE2, zero backtracking, ReDoS-immune)
var (
	// AWS Access Key ID (AKIA, ASIA, etc. followed by 16 alphanumeric characters)
	ReAWSAccessKey = regexp.MustCompile(`\b(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`)

	// GitHub Personal Access Token
	ReGitHubToken = regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b`)

	// OpenAI API Key
	ReOpenAIKey = regexp.MustCompile(`\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b|\bsk-proj-[a-zA-Z0-9_\-]{40,}\b|\bsk-[a-zA-Z0-9]{32,}\b`)

	// RSA / EC / DSA / OpenSSH Private Key Header
	RePrivateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`)

	// Database Connection URIs (postgres, mysql, mongodb, redis)
	ReDatabaseURI = regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s"'>\\]+\b`)

	// US Social Security Number (SSN) candidates
	ReSSN = regexp.MustCompile(`\b\d{3}[- ]\d{2}[- ]\d{4}\b`)

	// Credit Card PAN candidates
	ReCreditCard = regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b|\b(?:\d{4}[- ]){3}\d{4}\b`)
)

// SessionMapping stores bidirectional entity substitutions for a session.
type SessionMapping struct {
	mu         sync.RWMutex
	forwardMap map[string]string // raw -> pseudonym
	reverseMap map[string][]byte // pseudonym -> raw (zeroized on destroy)
}

// SessionVault manages in-memory session-scoped pseudonymization mappings with zeroization.
type SessionVault struct {
	mu       sync.RWMutex
	sessions map[string]*SessionMapping
}

// NewSessionVault constructs an in-memory session vault.
func NewSessionVault() *SessionVault {
	return &SessionVault{
		sessions: make(map[string]*SessionMapping),
	}
}

// GlobalSessionVault is the shared vault for pseudonymization.
var GlobalSessionVault = NewSessionVault()

func (v *SessionVault) getOrCreateSession(sessionKey string) *SessionMapping {
	v.mu.Lock()
	defer v.mu.Unlock()

	sm, exists := v.sessions[sessionKey]
	if !exists {
		sm = &SessionMapping{
			forwardMap: make(map[string]string),
			reverseMap: make(map[string][]byte),
		}
		v.sessions[sessionKey] = sm
	}
	return sm
}

// Store registers a raw secret and returns its deterministic pseudonym for this session.
func (v *SessionVault) Store(sessionKey, rawSecret string) string {
	sm := v.getOrCreateSession(sessionKey)

	sm.mu.Lock()
	defer sm.mu.Unlock()

	if pseudo, exists := sm.forwardMap[rawSecret]; exists {
		return pseudo
	}

	seq := len(sm.forwardMap) + 1
	pseudo := fmt.Sprintf("[REDACTED_SECRET_%d]", seq)
	sm.forwardMap[rawSecret] = pseudo
	sm.reverseMap[pseudo] = []byte(rawSecret)

	return pseudo
}

// Resolve looks up the original raw secret from its pseudonym.
func (v *SessionVault) Resolve(sessionKey, pseudo string) ([]byte, bool) {
	v.mu.RLock()
	sm, exists := v.sessions[sessionKey]
	v.mu.RUnlock()

	if !exists {
		return nil, false
	}

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	raw, found := sm.reverseMap[pseudo]
	return raw, found
}

// Destroy zeroes all sensitive memory and removes the session from the vault.
func (v *SessionVault) Destroy(sessionKey string) {
	v.mu.Lock()
	sm, exists := v.sessions[sessionKey]
	delete(v.sessions, sessionKey)
	v.mu.Unlock()

	if !exists {
		return
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Memory zeroization: overwrite all sensitive byte slices with zeroes
	for _, raw := range sm.reverseMap {
		for i := range raw {
			raw[i] = 0
		}
	}
	clear(sm.forwardMap)
	clear(sm.reverseMap)
}

// DLPScanner is a deterministic RE2-based secret and PII scanner and redactor.
type DLPScanner struct {
	vault *SessionVault
}

// NewDLPScanner initializes a DLPScanner with the specified or global vault.
func NewDLPScanner(vault ...*SessionVault) *DLPScanner {
	v := GlobalSessionVault
	if len(vault) > 0 && vault[0] != nil {
		v = vault[0]
	}
	return &DLPScanner{
		vault: v,
	}
}

// Name returns the stage name.
func (d *DLPScanner) Name() string {
	return "dlp_scanner"
}

// FailClosed returns true to guarantee fail-closed posture.
func (d *DLPScanner) FailClosed() bool {
	return true
}

// Execute scans CleanPayload for secrets and PII and redacts them in-place with pseudonyms.
func (d *DLPScanner) Execute(ctx *pipeline.PipelineContext) pipeline.StageResult {
	if len(ctx.CleanPayload) == 0 {
		return pipeline.StageContinue
	}

	sessionKey := ctx.TenantID
	if ctx.SessionID != "" {
		sessionKey = ctx.TenantID + ":" + ctx.SessionID
	}

	// 1. Scan and redact AWS Access Keys
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, ReAWSAccessKey, "AWS_ACCESS_KEY", nil)

	// 2. Scan and redact GitHub Tokens
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, ReGitHubToken, "GITHUB_TOKEN", nil)

	// 3. Scan and redact OpenAI API Keys
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, ReOpenAIKey, "OPENAI_API_KEY", nil)

	// 4. Scan and redact Private Key Headers
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, RePrivateKey, "PRIVATE_KEY_HEADER", nil)

	// 5. Scan and redact Database Connection URIs
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, ReDatabaseURI, "DATABASE_CONNECTION_URI", nil)

	// 6. Scan and redact Social Security Numbers (with SSA validator)
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, ReSSN, "US_SSN", IsValidSSN)

	// 7. Scan and redact Credit Card PANs (with inline Luhn validator)
	ctx.CleanPayload = d.redactMatches(sessionKey, ctx, ReCreditCard, "CREDIT_CARD_PAN", VerifyLuhn)

	return pipeline.StageContinue
}

func (d *DLPScanner) redactMatches(
	sessionKey string,
	ctx *pipeline.PipelineContext,
	re *regexp.Regexp,
	ruleName string,
	validator func(string) bool,
) []byte {
	matches := re.FindAll(ctx.CleanPayload, -1)
	if len(matches) == 0 {
		return ctx.CleanPayload
	}

	result := ctx.CleanPayload
	seenInPass := make(map[string]bool)

	for _, m := range matches {
		strMatch := string(m)
		if seenInPass[strMatch] {
			continue
		}
		seenInPass[strMatch] = true

		if validator != nil && !validator(strMatch) {
			continue
		}

		// Store secret in session vault and obtain deterministic pseudonym
		pseudonym := d.vault.Store(sessionKey, strMatch)

		// Redact in CleanPayload
		result = bytes.ReplaceAll(result, m, []byte(pseudonym))

		// Record violation telemetry
		ctx.Violations = append(ctx.Violations, pipeline.PolicyViolation{
			RuleID:      ruleName,
			Stage:       "dlp_scanner",
			Description: fmt.Sprintf("Redacted sensitive pattern %s with %s", ruleName, pseudonym),
			Severity:    "medium",
			Shadow:      false,
		})
	}

	return result
}

// IsValidSSN verifies SSA validity criteria in O(1):
// Area must not be 000, 666, or 900-999; Group must not be 00; Serial must not be 0000.
func IsValidSSN(match string) bool {
	digits := strings.ReplaceAll(strings.ReplaceAll(match, "-", ""), " ", "")
	if len(digits) != 9 {
		return false
	}
	area := digits[:3]
	group := digits[3:5]
	serial := digits[5:]

	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}
	if group == "00" {
		return false
	}
	if serial == "0000" {
		return false
	}
	return true
}

// VerifyLuhn implements the Luhn checksum formula in O(1) time and zero allocations.
func VerifyLuhn(number string) bool {
	var digits [24]int
	nDigits := 0

	for i := 0; i < len(number); i++ {
		c := number[i]
		if c >= '0' && c <= '9' {
			if nDigits >= len(digits) {
				return false
			}
			digits[nDigits] = int(c - '0')
			nDigits++
		} else if c == '-' || c == ' ' {
			continue
		} else {
			return false
		}
	}

	if nDigits < 13 || nDigits > 19 {
		return false
	}

	sum := 0
	alternate := false

	for i := nDigits - 1; i >= 0; i-- {
		d := digits[i]
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}

	return sum%10 == 0
}
