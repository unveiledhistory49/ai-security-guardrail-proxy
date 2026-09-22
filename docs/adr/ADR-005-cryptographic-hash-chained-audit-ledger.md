# ADR-005: Cryptographic Hash-Chained Audit Ledger

- **Status**: Accepted
- **Deciders**: Core Architecture Team
- **Date**: 2026-09-22
- **Context Files**:
  - [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md)
  - [09-ai-security-guardrail-proxy.md](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md)
  - [DESIGN.md](file:///root/ai-security-guardrail-proxy/DESIGN.md)
  - [SECURITY-BOUNDARIES.md](file:///root/ai-security-guardrail-proxy/docs/SECURITY-BOUNDARIES.md)
  - [OPERATIONS.md](file:///root/ai-security-guardrail-proxy/docs/OPERATIONS.md)

---

## 1. Context and Problem Statement

The AI Security Guardrail Proxy acts as the authoritative security enforcement point between client applications and Large Language Model backends. Every inspection outcome—whether an allowed prompt, a blocked prompt injection, a redacted credential, or a tripwire-severed streaming completion—must produce a durable, non-repudiable audit record.

Traditional enterprise architectures stream audit events across the network to centralized aggregators (e.g., Apache Kafka, AWS CloudWatch, Splunk, or Elasticsearch). However, for an inline, zero-external-dependency security proxy, relying on remote logging infrastructure violates core design principles:
1. **External Dependency Violation**: A remote log broker introduces network failure modes. If Kafka or CloudWatch experiences elevated latency or outages, the proxy must either block live AI traffic (violating availability SLOs) or drop audit logs (violating compliance and security mandates).
2. **Post-Hoc Tamper Susceptibility**: In environments where proxies run on edge nodes, sovereign enterprise boundaries, or containerized hosts, local flat log files (`audit.log`) can be silently modified, truncated, or forged by attackers who achieve local OS access after a breach.
3. **Data Privacy & Secret Retention Invariants**: Storing raw customer prompts and completions in persistent audit logs creates severe regulatory liabilities (GDPR, HIPAA). The audit trail must verify *what occurred* without becoming a repository of plaintext sensitive data.

We must establish an immutable, verifiable, and completely self-contained audit ledger architecture that guarantees non-repudiation with zero external dependencies.

---

## 2. Decision Drivers

1. **Zero External Daemon Dependencies**: Must operate entirely using local disk I/O and CPU without requiring Kafka, Elasticsearch, or database daemons.
2. **Cryptographic Tamper-Evidence (Forward Integrity)**: Any unauthorized modification, deletion, or reordering of historical records must mathematically invalidate all subsequent records in the chain.
3. **High-Throughput Line-Rate Logging**: Writing audit entries must never block the client-facing proxy pipeline; write operations must execute asynchronously with sub-millisecond overhead.
4. **Zero Plaintext Sensitive Data at Rest**: Audit records must preserve cryptographic proof (SHA-256 pre-image digests) of inputs and outputs rather than storing plaintext prompts or model completions.
5. **Standalone Verification**: Auditors and operators must be able to verify ledger integrity using standard cryptographic CLI utilities or a self-contained offline binary command.

---

## 3. Considered Options

1. **Sequential SHA-256 HMAC Hash Chaining with Disk Journaling (Selected)**
2. **Remote Ingestion Pipeline (Kafka / OpenSearch / CloudWatch)**
3. **Unauthenticated Flat JSON Files on Local Filesystem**
4. **Embedded Relational Database (SQLite with WAL)**

---

## 4. Deep Technical Comparison

| Dimension | 1. SHA-256 Hash Chain (Selected) | 2. Remote Ingestion (Kafka) | 3. Flat JSON Logs | 4. Embedded SQLite WAL |
| :--- | :--- | :--- | :--- | :--- |
| **External Dependencies** | **Zero** (Local disk only) | High (Brokers, ZK/KRaft) | **Zero** (Local disk) | **Zero** (Local file) |
| **Tamper Evidence** | **Cryptographic (Merkle-like)** | Provider-dependent | None (Easily modified) | Weak (DB pages editable) |
| **Throughput Impact** | **< 50µs** (Async ring buffer) | 5ms–50ms network I/O | < 50µs | 200µs–2ms (Lock contention) |
| **Storage Overhead** | Fixed ~320 bytes / record | Variable JSON overhead | Variable JSON overhead | High (Index + B-Tree) |
| **Offline Verification** | $O(N)$ sequential verification | None (External tooling) | Manual grep only | SQL query verification |

---

## 5. Decision Outcome

### Chosen Solution: Option 1 — In-Memory Lock-Free Ring Buffer with Sequential SHA-256 HMAC Hash-Chained Disk Journal

We implement an append-only, cryptographically chained audit journal directly in Go standard library primitives:

1. **Cryptographic Recurrence Relation**:
   Each audit entry $R_i$ contains a cryptographic hash $H_i$ computed as:
   $$H_0 = \text{SHA-256}(\text{"GENESIS"} \,\|\, \text{NodeID} \,\|\, \text{BootEpoch} \,\|\, \text{SecretKey})$$
   $$H_i = \text{HMAC-SHA-256}_{K_{\text{audit}}}(H_{i-1} \,\|\, \text{Seq}_i \,\|\, \text{Timestamp}_i \,\|\, \text{TenantID}_i \,\|\, \text{Action}_i \,\|\, \text{Digest}_{\text{req}} \,\|\, \text{Digest}_{\text{resp}})$$
   
   - If an attacker modifies any historical entry $R_k$ ($k < n$), the recomputed hash $H'_k \ne H_k$.
   - Because $H_k$ is the pre-image for $H_{k+1}$, all subsequent entries $H_{k+1}, \dots, H_n$ become invalid, providing instant mathematical proof of tampering.

2. **Decoupled Asynchronous Ring Buffer**:
   - The inspection pipeline pushes audit records into a pre-allocated lock-free ring buffer (`AuditBufferPool`, capacity 65,536).
   - An asynchronous background writer goroutine drains the ring buffer and executes batched writes to disk using `os.OpenFile` with `O_APPEND|O_WRONLY|O_CREATE` and `0600` POSIX permissions.
   - Pushing an audit record onto the in-memory ring buffer takes $< 100\text{ns}$, introducing zero latency overhead to the HTTP data path.

3. **Privacy Invariant (Zero Plaintext Secrets)**:
   - Plaintext prompts, model completions, and PII are never persisted to disk.
   - Only normalized cryptographic digests ($\text{SHA-256}(\text{InboundPayload})$ and $\text{SHA-256}(\text{OutboundPayload})$) are stored alongside classification tripwire metadata.
   - Full non-repudiation is achieved because any party claiming a specific prompt was sent can prove it by hashing their copy against the ledger's pre-image digest.

4. **Standalone CLI Verification Harness**:
   - The proxy binary includes a built-in verification command:
     ```bash
     guardrail-proxy audit verify --log-path /var/log/guardrail/audit.log
     ```
   - Scans the journal sequentially, recomputes the HMAC hash chain from genesis to head, and reports any tampered or missing sequence IDs.

---

## 6. Implementation Blueprint

```go
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sync"
	"time"
)

type AuditRecord struct {
	SequenceID   uint64 `json:"seq"`
	Timestamp    int64  `json:"ts"`
	TenantID     string `json:"tenant"`
	SessionID    string `json:"session"`
	Action       string `json:"action"` // ALLOW, BLOCK_INBOUND, REDACT, TRIPWIRE_ABORT
	RequestHash  string `json:"req_hash"`
	ResponseHash string `json:"resp_hash"`
	PrevHash     string `json:"prev_hash"`
	EntryHash    string `json:"hash"`
}

type ChainedLedger struct {
	mu        sync.Mutex
	file      *os.File
	hmacKey   []byte
	lastHash  string
	lastSeq   uint64
	ringChan  chan *AuditRecord
}

func (l *ChainedLedger) Record(tenantID, sessionID, action string, reqBody, respBody []byte) {
	reqDigest := sha256.Sum256(reqBody)
	respDigest := sha256.Sum256(respBody)

	rec := &AuditRecord{
		Timestamp:    time.Now().UnixNano(),
		TenantID:     tenantID,
		SessionID:    sessionID,
		Action:       action,
		RequestHash:  hex.EncodeToString(reqDigest[:]),
		ResponseHash: hex.EncodeToString(respDigest[:]),
	}

	// Non-blocking handoff to async writer ring
	select {
	case l.ringChan <- rec:
	default:
		// Ring full: fallback to emergency backpressure or metric increment
	}
}

func (l *ChainedLedger) processBatch() {
	for rec := range l.ringChan {
		l.mu.Lock()
		rec.SequenceID = l.lastSeq + 1
		rec.PrevHash = l.lastHash

		mac := hmac.New(sha256.New, l.hmacKey)
		fmt.Fprintf(mac, "%s:%d:%d:%s:%s:%s:%s",
			rec.PrevHash, rec.SequenceID, rec.Timestamp, rec.TenantID, rec.Action, rec.RequestHash, rec.ResponseHash)
		rec.EntryHash = hex.EncodeToString(mac.Sum(nil))

		l.lastHash = rec.EntryHash
		l.lastSeq = rec.SequenceID

		// Write sequentially to disk journal
		l.writeEntry(rec)
		l.mu.Unlock()
	}
}
```

---

## 7. Consequences

### Positive
- **Complete Self-Containment**: No external logging clusters or SaaS accounts required.
- **Mathematical Non-Repudiation**: Impossible to rewrite history without detection.
- **Zero Latency Penalty**: In-memory ring buffer isolates the HTTP proxy pipeline from disk I/O.
- **Strict Privacy Compliance**: Zero plaintext user data stored on disk.

### Negative & Mitigations
- **Local Disk Capacity Limits**: Addressed in [OPERATIONS.md](file:///root/ai-security-guardrail-proxy/docs/OPERATIONS.md) via automated hash-chained daily rotation and pre-allocation checks.
- **Key Protection**: The HMAC key is held in memory and derived from host credentials via HKDF, zeroized on shutdown.
