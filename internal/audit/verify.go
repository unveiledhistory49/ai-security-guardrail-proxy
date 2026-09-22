package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// VerifyChain sequentially recomputes and verifies the cryptographic HMAC-SHA256
// hash chain from genesis to the head of the log file.
// Returns (true, totalVerified, nil) on complete validity.
// Returns (false, verifiedBeforeError, error) if any record, sequence ID, previous hash, or entry hash was tampered with.
func VerifyChain(logPath string, hmacKey []byte) (bool, uint64, error) {
	if len(hmacKey) == 0 {
		hmacKey = DefaultHMACKey
	}

	file, err := os.Open(logPath)
	if err != nil {
		return false, 0, fmt.Errorf("failed to open audit log file %q: %w", logPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	var (
		prevHash      string
		lastSeq       uint64
		verifiedCount uint64
		hasRecords    bool
	)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		var rec AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return false, verifiedCount, fmt.Errorf("malformed JSON in audit log at record %d: %w", verifiedCount+1, err)
		}

		hasRecords = true

		if rec.SequenceID == 0 {
			// Genesis verification: H0 = SHA256("GENESIS" || NodeID || BootEpoch)
			expectedH0 := ComputeGenesisHash(rec.NodeID, rec.BootEpoch)
			if rec.EntryHash != expectedH0 {
				return false, verifiedCount, fmt.Errorf("tamper detected: genesis hash mismatch at seq 0: expected %s, found %s", expectedH0, rec.EntryHash)
			}
			prevHash = rec.EntryHash
			lastSeq = 0
			verifiedCount++
			continue
		}

		// If journal started without genesis (e.g. rotated log chunk), trust initial previous hash
		if verifiedCount == 0 {
			prevHash = rec.PrevHash
			lastSeq = rec.SequenceID - 1
		}

		// 1. Verify sequence monotonicity
		if rec.SequenceID != lastSeq+1 {
			return false, verifiedCount, fmt.Errorf("tamper detected: sequence discontinuity at record %d: expected seq %d, found %d", verifiedCount+1, lastSeq+1, rec.SequenceID)
		}

		// 2. Verify cryptographic hash chain pointer
		if rec.PrevHash != prevHash {
			return false, verifiedCount, fmt.Errorf("tamper detected: previous hash mismatch at seq %d: expected %s, found %s", rec.SequenceID, prevHash, rec.PrevHash)
		}

		// 3. Verify entry HMAC-SHA256 signature
		expectedHash := ComputeEntryHash(
			hmacKey,
			rec.PrevHash,
			rec.SequenceID,
			rec.Timestamp,
			rec.TenantID,
			rec.Action,
			rec.RequestHash,
			rec.ResponseHash,
		)

		if rec.EntryHash != expectedHash {
			return false, verifiedCount, fmt.Errorf("tamper detected: HMAC entry hash invalid at seq %d: expected %s, found %s", rec.SequenceID, expectedHash, rec.EntryHash)
		}

		prevHash = rec.EntryHash
		lastSeq = rec.SequenceID
		verifiedCount++
	}

	if err := scanner.Err(); err != nil {
		return false, verifiedCount, fmt.Errorf("failed reading audit log: %w", err)
	}

	if !hasRecords {
		return true, 0, nil
	}

	return true, verifiedCount, nil
}
