package outbound

import (
	"testing"
)

func TestOutboundDLP_AWSAccessKey(t *testing.T) {
	scanner := NewDLPScanner()

	samples := []struct {
		name    string
		payload string
	}{
		{"standard_akia", "Here is your AWS credentials: AKIAIOSFODNN7EXAMPLE for S3."},
		{"asia_temp_key", "Temporary credential: ASIAIOSFODNN7EXAMPLE."},
	}

	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			matched, ruleID, _ := scanner.Detect([]byte(tc.payload))
			if !matched {
				t.Fatalf("expected AWS key detection, got false")
			}
			if ruleID != RuleOutboundSecretLeak {
				t.Fatalf("expected %q, got %q", RuleOutboundSecretLeak, ruleID)
			}
		})
	}
}

func TestOutboundDLP_GitHubToken(t *testing.T) {
	scanner := NewDLPScanner()

	samples := []struct {
		name    string
		payload string
	}{
		{"classic_pat", "git token: ghp_123456789012345678901234567890123456 in repo"},
		{"fine_grained", "token: github_pat_11AAAAAAA0123456789ABC_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZA"},
	}

	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			matched, ruleID, _ := scanner.Detect([]byte(tc.payload))
			if !matched {
				t.Fatalf("expected GitHub token detection, got false")
			}
			if ruleID != RuleOutboundSecretLeak {
				t.Fatalf("expected %q, got %q", RuleOutboundSecretLeak, ruleID)
			}
		})
	}
}

func TestOutboundDLP_OpenAIKey(t *testing.T) {
	scanner := NewDLPScanner()

	samples := []struct {
		name    string
		payload string
	}{
		{"project_key", "OpenAI key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"},
		{"legacy_key", "OpenAI API Key: sk-12345678901234567890abcdefghij12345678901234567890"},
	}

	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			matched, ruleID, _ := scanner.Detect([]byte(tc.payload))
			if !matched {
				t.Fatalf("expected OpenAI key detection, got false")
			}
			if ruleID != RuleOutboundSecretLeak {
				t.Fatalf("expected %q, got %q", RuleOutboundSecretLeak, ruleID)
			}
		})
	}
}

func TestOutboundDLP_PrivateKeyHeader(t *testing.T) {
	scanner := NewDLPScanner()

	samples := []struct {
		name    string
		payload string
	}{
		{"rsa_private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"},
		{"ec_private_key", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----"},
		{"generic_private_key", "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...\n-----END PRIVATE KEY-----"},
		{"openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...\n-----END OPENSSH PRIVATE KEY-----"},
	}

	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			matched, ruleID, _ := scanner.Detect([]byte(tc.payload))
			if !matched {
				t.Fatalf("expected private key detection, got false")
			}
			if ruleID != RuleOutboundSecretLeak {
				t.Fatalf("expected %q, got %q", RuleOutboundSecretLeak, ruleID)
			}
		})
	}
}

func TestOutboundDLP_DatabaseURI(t *testing.T) {
	scanner := NewDLPScanner()

	samples := []struct {
		name    string
		payload string
	}{
		{"postgres", "Connect via postgres://admin:supersecret@db.internal:5432/prod"},
		{"mysql", "MySQL connection: mysql://root:pass123@10.0.0.1:3306/users"},
		{"mongodb", "Mongo: mongodb://user:pass@mongo-primary:27017/analytics"},
		{"redis", "Cache: redis://:redis_secret_password@redis-master:6379/0"},
	}

	for _, tc := range samples {
		t.Run(tc.name, func(t *testing.T) {
			matched, ruleID, _ := scanner.Detect([]byte(tc.payload))
			if !matched {
				t.Fatalf("expected Database URI detection, got false")
			}
			if ruleID != RuleOutboundSecretLeak {
				t.Fatalf("expected %q, got %q", RuleOutboundSecretLeak, ruleID)
			}
		})
	}
}

func TestOutboundDLP_BenignDataPasses(t *testing.T) {
	scanner := NewDLPScanner()

	cleanPayloads := []string{
		"Here is a Python function calculating Fibonacci numbers.",
		"Use https://api.github.com/v3 to query public repositories.",
		"Postgres is a powerful open-source object-relational database system.",
		"The AWS access key ID format is AKIA followed by 16 alphanumeric characters, for example: AKIA (none provided).",
	}

	for _, p := range cleanPayloads {
		matched, _, _ := scanner.Detect([]byte(p))
		if matched {
			t.Fatalf("expected benign data to pass without match, but matched: %q", p)
		}
	}
}
