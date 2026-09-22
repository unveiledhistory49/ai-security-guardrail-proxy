package inbound

import (
	"context"
	"strings"
	"testing"

	"ai-security-guardrail-proxy/internal/pipeline"
)

func TestVerifyLuhn(t *testing.T) {
	tests := []struct {
		number string
		valid  bool
	}{
		// Valid cards
		{"4532015112830366", true},       // Visa
		{"4532-0151-1283-0366", true},  // Visa with dashes
		{"5424180123456789", true},       // MasterCard
		{"378282246310005", true},        // Amex
		// Invalid cards
		{"4532015112830367", false},      // Checksum off by 1
		{"1234567890123456", false},      // Random 16 digits
		{"123", false},                   // Too short
		{"letters-in-card", false},       // Non-digit
	}

	for _, tc := range tests {
		got := VerifyLuhn(tc.number)
		if got != tc.valid {
			t.Errorf("VerifyLuhn(%q) = %v; want %v", tc.number, got, tc.valid)
		}
	}
}

func TestIsValidSSN(t *testing.T) {
	tests := []struct {
		ssn   string
		valid bool
	}{
		{"123-45-6789", true},
		{"219 45 7890", true},
		{"000-45-6789", false}, // area 000 invalid
		{"666-45-6789", false}, // area 666 invalid
		{"900-45-6789", false}, // area 9xx invalid
		{"123-00-6789", false}, // group 00 invalid
		{"123-45-0000", false}, // serial 0000 invalid
		{"123-45", false},      // too short
	}

	for _, tc := range tests {
		got := IsValidSSN(tc.ssn)
		if got != tc.valid {
			t.Errorf("IsValidSSN(%q) = %v; want %v", tc.ssn, got, tc.valid)
		}
	}
}

func TestDLPScanner_RedactSecrets(t *testing.T) {
	vault := NewSessionVault()
	scanner := NewDLPScanner(vault)

	secretsPayload := `{"messages":[{"role":"user","content":"` +
		`AWS: AKIAIOSFODNN7EXAMPLE, ` +
		`GitHub: ghp_123456789012345678901234567890123456, ` +
		`OpenAI: sk-proj-123456789012345678901234567890123456789012345678, ` +
		`DB: postgres://admin:secretPass@db.internal:5432/mydb, ` +
		`Key: -----BEGIN RSA PRIVATE KEY-----"}]}`

	pc := pipeline.AcquireContext(context.Background(), "tenant-dlp", "session-dlp-1")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(secretsPayload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(secretsPayload)...)

	res := scanner.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue after redaction, got %v", res)
	}

	cleanStr := string(pc.CleanPayload)

	// Ensure raw secrets were removed
	if strings.Contains(cleanStr, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS key was not redacted: %s", cleanStr)
	}
	if strings.Contains(cleanStr, "ghp_123456789012345678901234567890123456") {
		t.Errorf("GitHub token was not redacted: %s", cleanStr)
	}
	if strings.Contains(cleanStr, "sk-proj-123456789012345678901234567890123456789012345678") {
		t.Errorf("OpenAI key was not redacted: %s", cleanStr)
	}
	if strings.Contains(cleanStr, "postgres://admin:secretPass@db.internal:5432/mydb") {
		t.Errorf("Database URI was not redacted: %s", cleanStr)
	}
	if strings.Contains(cleanStr, "-----BEGIN RSA PRIVATE KEY-----") {
		t.Errorf("Private key header was not redacted: %s", cleanStr)
	}

	// Ensure pseudonyms are present
	if !strings.Contains(cleanStr, "[REDACTED_SECRET_") {
		t.Errorf("CleanPayload does not contain pseudonym markers: %s", cleanStr)
	}

	// Verify violations recorded
	if len(pc.Violations) < 5 {
		t.Fatalf("expected at least 5 violations recorded, got %d", len(pc.Violations))
	}
}

func TestDLPScanner_RedactPII(t *testing.T) {
	vault := NewSessionVault()
	scanner := NewDLPScanner(vault)

	piiPayload := `{"messages":[{"role":"user","content":"Patient John Doe SSN 123-45-6789 paid with Visa 4532-0151-1283-0366."}]}`

	pc := pipeline.AcquireContext(context.Background(), "tenant-dlp", "session-dlp-2")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(piiPayload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(piiPayload)...)

	res := scanner.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue after PII redaction, got %v", res)
	}

	cleanStr := string(pc.CleanPayload)
	if strings.Contains(cleanStr, "123-45-6789") {
		t.Errorf("SSN was not redacted: %s", cleanStr)
	}
	if strings.Contains(cleanStr, "4532-0151-1283-0366") {
		t.Errorf("Credit card was not redacted: %s", cleanStr)
	}
	if !strings.Contains(cleanStr, "[REDACTED_SECRET_") {
		t.Errorf("Pseudonym markers missing: %s", cleanStr)
	}
}

func TestSessionVault_Zeroization(t *testing.T) {
	vault := NewSessionVault()
	sessionKey := "tenant-test:session-123"

	pseudo := vault.Store(sessionKey, "my-super-secret-key")
	if pseudo != "[REDACTED_SECRET_1]" {
		t.Fatalf("expected [REDACTED_SECRET_1], got %s", pseudo)
	}

	raw, found := vault.Resolve(sessionKey, pseudo)
	if !found || string(raw) != "my-super-secret-key" {
		t.Fatalf("expected my-super-secret-key, got %s (found=%v)", string(raw), found)
	}

	// Destroy session and verify zeroization
	vault.Destroy(sessionKey)

	_, foundAfter := vault.Resolve(sessionKey, pseudo)
	if foundAfter {
		t.Fatalf("expected session to be purged after Destroy")
	}

	// Verify that underlying raw slice was zeroed
	for _, b := range raw {
		if b != 0 {
			t.Fatalf("expected memory byte to be zeroed, got %d", b)
		}
	}
}

func TestDLPScanner_DeterministicPseudonym(t *testing.T) {
	vault := NewSessionVault()
	scanner := NewDLPScanner(vault)

	// Same secret repeated twice in payload
	payload := `{"messages":[{"role":"user","content":"First AKIAIOSFODNN7EXAMPLE and second AKIAIOSFODNN7EXAMPLE"}]}`

	pc := pipeline.AcquireContext(context.Background(), "tenant-dlp", "session-rep")
	defer pipeline.ReleaseContext(pc)

	pc.RawPayload = append(pc.RawPayload, []byte(payload)...)
	pc.CleanPayload = append(pc.CleanPayload, []byte(payload)...)

	res := scanner.Execute(pc)
	if res != pipeline.StageContinue {
		t.Fatalf("expected StageContinue, got %v", res)
	}

	cleanStr := string(pc.CleanPayload)
	// Both should be replaced by [REDACTED_SECRET_1]
	count := strings.Count(cleanStr, "[REDACTED_SECRET_1]")
	if count != 2 {
		t.Fatalf("expected exactly 2 occurrences of [REDACTED_SECRET_1], got %d in: %s", count, cleanStr)
	}
}
