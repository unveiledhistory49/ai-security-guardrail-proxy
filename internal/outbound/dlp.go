package outbound

import (
	"regexp"
)

const (
	// RuleOutboundSecretLeak identifies secret leakage in outbound responses.
	RuleOutboundSecretLeak = "OUTBOUND_SECRET_LEAK"

	// Specific rule IDs for granular audit reporting
	RuleAWSKeyLeak     = "OUTBOUND_SECRET_AWS_KEY"
	RuleGitHubTokenLeak = "OUTBOUND_SECRET_GITHUB_TOKEN"
	RuleOpenAIKeyLeak  = "OUTBOUND_SECRET_OPENAI_KEY"
	RulePrivateKeyLeak = "OUTBOUND_SECRET_PRIVATE_KEY"
	RuleDatabaseURILeak = "OUTBOUND_SECRET_DATABASE_URI"
)

// Precompiled linear-time DFA regular expressions (RE2, zero backtracking, ReDoS-immune)
var (
	// AWS Access Key ID (AKIA, ASIA, etc. followed by 16 alphanumeric characters)
	reAWSAccessKey = regexp.MustCompile(`\b(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`)

	// GitHub Personal Access Token (classic ghp_ and fine-grained github_pat_)
	reGitHubToken = regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{50,})\b`)

	// OpenAI Secret API Key
	reOpenAIKey = regexp.MustCompile(`\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b|\bsk-proj-[a-zA-Z0-9_\-]{40,}\b|\bsk-[a-zA-Z0-9]{32,}\b`)

	// RSA / EC / DSA / OpenSSH Private Key Header
	rePrivateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`)

	// Database Connection URIs (postgres, mysql, mongodb, redis)
	reDatabaseURI = regexp.MustCompile(`\b(?:postgres|postgresql|mysql|mongodb|redis)://[^\s"'>\\]+\b`)
)

// DLPScanner scans outbound buffers for sensitive credentials and API keys.
type DLPScanner struct{}

// NewDLPScanner constructs a new outbound DLPScanner.
func NewDLPScanner() *DLPScanner {
	return &DLPScanner{}
}

// Detect checks if the data contains any known secret patterns.
// Returns matched, ruleID, and description message.
func (d *DLPScanner) Detect(data []byte) (bool, string, string) {
	if reAWSAccessKey.Match(data) {
		return true, RuleOutboundSecretLeak, "Response stream aborted due to AWS access key leak"
	}
	if reGitHubToken.Match(data) {
		return true, RuleOutboundSecretLeak, "Response stream aborted due to GitHub token leak"
	}
	if reOpenAIKey.Match(data) {
		return true, RuleOutboundSecretLeak, "Response stream aborted due to OpenAI key leak"
	}
	if rePrivateKey.Match(data) {
		return true, RuleOutboundSecretLeak, "Response stream aborted due to private key leak"
	}
	if reDatabaseURI.Match(data) {
		return true, RuleOutboundSecretLeak, "Response stream aborted due to database connection URI leak"
	}
	return false, "", ""
}
