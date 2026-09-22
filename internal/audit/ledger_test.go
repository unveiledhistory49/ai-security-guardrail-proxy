package audit

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuditLedger_RecordChainingAndVerify(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.log")
	key := []byte("test-hmac-key-12345678901234567890")

	ledger, err := NewChainedLedger(logPath, key, "node-test-1")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	records := []struct {
		tenant  string
		session string
		action  string
		req     []byte
		resp    []byte
	}{
		{"tenant-1", "sess-1", "ALLOW", []byte("hello world"), []byte("response 1")},
		{"tenant-1", "sess-2", "BLOCK_INBOUND", []byte("ignore instructions"), []byte("blocked")},
		{"tenant-2", "sess-3", "RATE_LIMIT", []byte("spamming"), []byte("rate limited")},
		{"tenant-2", "sess-4", "TRIPWIRE_ABORT", []byte("canary prompt"), []byte("abort frame")},
	}

	for _, r := range records {
		if err := ledger.Record(r.tenant, r.session, r.action, r.req, r.resp); err != nil {
			t.Fatalf("failed to record entry: %v", err)
		}
	}

	if err := ledger.Close(); err != nil {
		t.Fatalf("failed to close ledger: %v", err)
	}

	valid, count, err := VerifyChain(logPath, key)
	if err != nil {
		t.Fatalf("VerifyChain returned error: %v", err)
	}
	if !valid {
		t.Fatalf("VerifyChain returned false")
	}

	// 1 Genesis record + 4 entries = 5 records
	if count != 5 {
		t.Fatalf("expected 5 verified records, got %d", count)
	}
}

func TestAuditLedger_PrivacyInvariant_NoPlaintextLeak(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "privacy_audit.log")
	key := []byte("secret-key-32b")

	ledger, err := NewChainedLedger(logPath, key, "node-priv-1")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	secretPrompt := "super-confidential-user-prompt-12345"
	secretCompletion := "super-confidential-model-completion-67890"

	if err := ledger.Record("tenant-x", "sess-x", "ALLOW", []byte(secretPrompt), []byte(secretCompletion)); err != nil {
		t.Fatalf("failed to record: %v", err)
	}

	_ = ledger.Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log file: %v", err)
	}

	if bytes.Contains(content, []byte(secretPrompt)) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: plaintext prompt found in audit ledger!")
	}
	if bytes.Contains(content, []byte(secretCompletion)) {
		t.Fatalf("CRITICAL SECURITY VIOLATION: plaintext completion found in audit ledger!")
	}
}

func TestAuditLedger_AsyncRingBuffer_HighThroughput(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "concurrent_audit.log")
	key := []byte("concurrent-hmac-key")

	ledger, err := NewChainedLedger(logPath, key, "node-perf-1")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	numProducers := 10
	recordsPerProducer := 100
	var wg sync.WaitGroup

	start := time.Now()
	for p := 0; p < numProducers; p++ {
		wg.Add(1)
		go func(pid int) {
			defer wg.Done()
			for r := 0; r < recordsPerProducer; r++ {
				tenant := fmt.Sprintf("tenant-%d", pid)
				action := "ALLOW"
				if r%2 == 0 {
					action = "BLOCK_INBOUND"
				}
				req := []byte(fmt.Sprintf("request-%d-%d", pid, r))
				resp := []byte(fmt.Sprintf("response-%d-%d", pid, r))

				for {
					err := ledger.Record(tenant, "sess", action, req, resp)
					if err == nil {
						break
					}
					time.Sleep(100 * time.Microsecond)
				}
			}
		}(p)
	}

	wg.Wait()
	_ = ledger.Close()
	t.Logf("1000 concurrent records enqueued and flushed in %v", time.Since(start))

	valid, count, err := VerifyChain(logPath, key)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if !valid {
		t.Fatalf("verification failed on high throughput ledger")
	}

	expectedCount := uint64(1 + numProducers*recordsPerProducer) // 1 Genesis + 1000 records = 1001
	if count != expectedCount {
		t.Fatalf("expected %d records, verified %d", expectedCount, count)
	}
}

func TestAuditLedger_TamperDetection_ModifiedField(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "tamper_field.log")
	key := []byte("tamper-key")

	ledger, err := NewChainedLedger(logPath, key, "node-1")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	_ = ledger.Record("tenant-A", "sess-1", "ALLOW", []byte("req1"), []byte("resp1"))
	_ = ledger.Record("tenant-B", "sess-2", "ALLOW", []byte("req2"), []byte("resp2"))
	_ = ledger.Close()

	// Tamper: modify tenant in second record ("tenant-B" -> "tenant-C")
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	tampered := strings.Replace(string(content), `"tenant":"tenant-B"`, `"tenant":"tenant-C"`, 1)
	if err := os.WriteFile(logPath, []byte(tampered), 0600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	valid, count, err := VerifyChain(logPath, key)
	if valid {
		t.Fatalf("expected verification to fail after field tampering, but it passed!")
	}
	if err == nil {
		t.Fatalf("expected error from VerifyChain on tampered log")
	}
	t.Logf("Tamper caught successfully at count %d: %v", count, err)
}

func TestAuditLedger_TamperDetection_ModifiedHash(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "tamper_hash.log")
	key := []byte("tamper-key")

	ledger, err := NewChainedLedger(logPath, key, "node-1")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	_ = ledger.Record("tenant-A", "sess-1", "ALLOW", []byte("req1"), []byte("resp1"))
	_ = ledger.Record("tenant-A", "sess-2", "ALLOW", []byte("req2"), []byte("resp2"))
	_ = ledger.Close()

	// Tamper: alter one byte of the hash in record 1
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d", len(lines))
	}

	// Corrupt first non-genesis line's hash
	lines[1] = strings.Replace(lines[1], `"hash":"a`, `"hash":"b`, 1)
	if lines[1] == strings.Split(strings.TrimSpace(string(content)), "\n")[1] {
		// If 'a' wasn't at the start, replace last char of hash
		idx := strings.LastIndex(lines[1], `"hash":"`)
		if idx != -1 {
			target := lines[1][idx+8 : idx+10]
			lines[1] = strings.Replace(lines[1], target, "ff", 1)
		}
	}

	_ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)

	valid, _, err := VerifyChain(logPath, key)
	if valid {
		t.Fatalf("expected verification to fail after hash tampering")
	}
	if err == nil {
		t.Fatalf("expected tamper error")
	}
	t.Logf("Tampered hash detected: %v", err)
}

func TestAuditLedger_TamperDetection_SequenceDiscontinuity(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "tamper_seq.log")
	key := []byte("tamper-key")

	ledger, err := NewChainedLedger(logPath, key, "node-1")
	if err != nil {
		t.Fatalf("failed to create ledger: %v", err)
	}

	_ = ledger.Record("tenant-A", "sess-1", "ALLOW", []byte("req1"), []byte("resp1"))
	_ = ledger.Record("tenant-A", "sess-2", "ALLOW", []byte("req2"), []byte("resp2"))
	_ = ledger.Record("tenant-A", "sess-3", "ALLOW", []byte("req3"), []byte("resp3"))
	_ = ledger.Close()

	// Tamper: delete record 2 (middle entry)
	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	// lines[0] = genesis, lines[1] = seq 1, lines[2] = seq 2, lines[3] = seq 3
	tamperedLines := []string{lines[0], lines[1], lines[3]}
	_ = os.WriteFile(logPath, []byte(strings.Join(tamperedLines, "\n")+"\n"), 0600)

	valid, _, err := VerifyChain(logPath, key)
	if valid {
		t.Fatalf("expected verification to fail after deleting record")
	}
	if err == nil {
		t.Fatalf("expected sequence discontinuity or prev_hash error")
	}
	t.Logf("Deleted record detected: %v", err)
}

func TestAuditLedger_ReopenExistingJournal(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "reopen.log")
	key := []byte("reopen-key")

	// Session 1: write 3 records
	l1, err := NewChainedLedger(logPath, key, "node-1")
	if err != nil {
		t.Fatalf("failed to create l1: %v", err)
	}
	_ = l1.Record("tenant-1", "s1", "ALLOW", []byte("q1"), []byte("a1"))
	_ = l1.Record("tenant-1", "s2", "ALLOW", []byte("q2"), []byte("a2"))
	_ = l1.Close()

	// Session 2: reopen same journal, write 2 more records
	l2, err := NewChainedLedger(logPath, key, "node-1")
	if err != nil {
		t.Fatalf("failed to reopen l2: %v", err)
	}
	if l2.LastSequence() != 2 {
		t.Fatalf("expected l2 last sequence to be 2, got %d", l2.LastSequence())
	}
	_ = l2.Record("tenant-1", "s3", "ALLOW", []byte("q3"), []byte("a3"))
	_ = l2.Record("tenant-1", "s4", "ALLOW", []byte("q4"), []byte("a4"))
	_ = l2.Close()

	// Verify entire chained log (Genesis + 4 records = 5)
	valid, count, err := VerifyChain(logPath, key)
	if err != nil {
		t.Fatalf("VerifyChain error: %v", err)
	}
	if !valid {
		t.Fatalf("verification failed on reopened journal")
	}
	if count != 5 {
		t.Fatalf("expected 5 verified records, got %d", count)
	}
}
