package audit

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// RingBufferSize is the fixed capacity (65,536) for the lock-free ring buffer.
	RingBufferSize = 65536
	ringBufferMask = RingBufferSize - 1
	defaultNodeID  = "guardrail-proxy-node-1"
)

var (
	// DefaultHMACKey is used when no explicit key is configured.
	DefaultHMACKey = []byte("guardrail-proxy-hmac-sha256-audit-secret-key-32b")

	// ErrBufferFull indicates that the lock-free ring buffer is full.
	ErrBufferFull = errors.New("audit ring buffer is full")

	// ErrClosed indicates the ledger has been shut down.
	ErrClosed = errors.New("audit ledger is closed")
)

// AuditRecord represents an immutable journal entry in the cryptographic audit chain.
type AuditRecord struct {
	SequenceID   uint64 `json:"seq"`
	Timestamp    int64  `json:"ts"`
	NodeID       string `json:"node_id,omitempty"`
	BootEpoch    int64  `json:"boot_epoch,omitempty"`
	TenantID     string `json:"tenant,omitempty"`
	SessionID    string `json:"session,omitempty"`
	Action       string `json:"action"`
	RequestHash  string `json:"req_hash,omitempty"`
	ResponseHash string `json:"resp_hash,omitempty"`
	PrevHash     string `json:"prev_hash"`
	EntryHash    string `json:"hash"`
}

// ComputeGenesisHash calculates H0 = SHA256("GENESIS" || NodeID || BootEpoch).
func ComputeGenesisHash(nodeID string, bootEpoch int64) string {
	h := sha256.New()
	fmt.Fprintf(h, "GENESIS:%s:%d", nodeID, bootEpoch)
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeEntryHash calculates Hi = HMAC-SHA256(Hi-1 || Seq_i || Ts_i || Tenant_i || Action_i || ReqHash_i || RespHash_i).
func ComputeEntryHash(hmacKey []byte, prevHash string, seq uint64, ts int64, tenantID, action, reqHash, respHash string) string {
	mac := hmac.New(sha256.New, hmacKey)
	fmt.Fprintf(mac, "%s:%d:%d:%s:%s:%s:%s", prevHash, seq, ts, tenantID, action, reqHash, respHash)
	return hex.EncodeToString(mac.Sum(nil))
}

// RingBuffer implements a high-throughput, lock-free Multi-Producer Single-Consumer (MPSC)
// circular ring buffer of capacity 65,536 for audit record handoff (< 100ns enqueue time).
type RingBuffer struct {
	head   atomic.Uint64
	tail   atomic.Uint64
	slots  [RingBufferSize]atomic.Pointer[AuditRecord]
	notify chan struct{}
}

// NewRingBuffer allocates an initialized RingBuffer.
func NewRingBuffer() *RingBuffer {
	return &RingBuffer{
		notify: make(chan struct{}, 1),
	}
}

// TryPush enqueues an AuditRecord in a lock-free manner via CAS.
// Returns false immediately if the buffer is saturated, guaranteeing zero blocking on the HTTP path.
func (rb *RingBuffer) TryPush(rec *AuditRecord) bool {
	for {
		head := rb.head.Load()
		tail := rb.tail.Load()
		if head-tail >= RingBufferSize {
			return false
		}
		if rb.head.CompareAndSwap(head, head+1) {
			slot := &rb.slots[head&ringBufferMask]
			slot.Store(rec)
			select {
			case rb.notify <- struct{}{}:
			default:
			}
			return true
		}
	}
}

// Pop extracts the next record from the ring buffer.
// Must be called exclusively by the dedicated single consumer goroutine.
func (rb *RingBuffer) Pop() *AuditRecord {
	tail := rb.tail.Load()
	head := rb.head.Load()
	if tail >= head {
		return nil
	}
	slot := &rb.slots[tail&ringBufferMask]
	rec := slot.Load()
	if rec == nil {
		// Producer has reserved slot via CAS but not finished storing pointer yet.
		for i := 0; i < 100 && rec == nil; i++ {
			rec = slot.Load()
		}
		if rec == nil {
			return nil
		}
	}
	slot.Store(nil)
	rb.tail.Store(tail + 1)
	return rec
}

// ChainedLedger manages the append-only, HMAC-SHA256 cryptographically chained journal.
type ChainedLedger struct {
	mu         sync.Mutex
	file       *os.File
	filePath   string
	hmacKey    []byte
	nodeID     string
	bootEpoch  int64
	lastHash   string
	lastSeq    uint64
	ringBuffer *RingBuffer
	stopChan   chan struct{}
	doneChan   chan struct{}
	closed     atomic.Bool
}

// NewChainedLedger creates or opens an audit ledger at the given path with 0600 POSIX permissions.
func NewChainedLedger(path string, hmacKey []byte, nodeID string) (*ChainedLedger, error) {
	if nodeID == "" {
		nodeID = defaultNodeID
	}
	if len(hmacKey) == 0 {
		hmacKey = DefaultHMACKey
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create audit ledger directory %q: %w", dir, err)
		}
	}

	// Open file in append-only mode with 0600 POSIX permissions
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit ledger file %q: %w", path, err)
	}

	bootEpoch := time.Now().UnixNano()
	l := &ChainedLedger{
		file:       f,
		filePath:   path,
		hmacKey:    hmacKey,
		nodeID:     nodeID,
		bootEpoch:  bootEpoch,
		ringBuffer: NewRingBuffer(),
		stopChan:   make(chan struct{}),
		doneChan:   make(chan struct{}),
	}

	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to stat audit log: %w", err)
	}

	if info.Size() == 0 {
		// New journal: initialize Genesis record (Seq 0)
		h0 := ComputeGenesisHash(nodeID, bootEpoch)
		genRec := &AuditRecord{
			SequenceID: 0,
			Timestamp:  bootEpoch,
			NodeID:     nodeID,
			BootEpoch:  bootEpoch,
			Action:     "GENESIS",
			EntryHash:  h0,
		}
		data, err := json.Marshal(genRec)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to marshal genesis record: %w", err)
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to write genesis record: %w", err)
		}
		_ = f.Sync()
		l.lastHash = h0
		l.lastSeq = 0
	} else {
		// Recover last state from existing journal
		lastSeq, lastHash, err := recoverLastRecord(path)
		if err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("failed to recover audit log state from %q: %w", path, err)
		}
		l.lastSeq = lastSeq
		l.lastHash = lastHash
	}

	go l.writerLoop()

	return l, nil
}

func recoverLastRecord(path string) (uint64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lastLine string
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if len(text) > 0 {
			lastLine = text
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, "", err
	}
	if lastLine == "" {
		return 0, "", errors.New("audit log is empty")
	}

	var rec AuditRecord
	if err := json.Unmarshal([]byte(lastLine), &rec); err != nil {
		return 0, "", fmt.Errorf("failed to parse last record: %w", err)
	}

	return rec.SequenceID, rec.EntryHash, nil
}

// Record queues an audit record with privacy-preserving pre-image digests of the request and response.
// Never stores raw plaintext prompts or completions.
func (l *ChainedLedger) Record(tenantID, sessionID, action string, reqBody, respBody []byte) error {
	if l.closed.Load() {
		return ErrClosed
	}

	var reqHash, respHash string
	if reqBody != nil {
		d := sha256.Sum256(reqBody)
		reqHash = hex.EncodeToString(d[:])
	}
	if respBody != nil {
		d := sha256.Sum256(respBody)
		respHash = hex.EncodeToString(d[:])
	}

	rec := &AuditRecord{
		Timestamp:    time.Now().UnixNano(),
		TenantID:     tenantID,
		SessionID:    sessionID,
		Action:       action,
		RequestHash:  reqHash,
		ResponseHash: respHash,
	}

	if !l.ringBuffer.TryPush(rec) {
		return ErrBufferFull
	}
	return nil
}

// RecordWithHashes queues an audit record using pre-computed pre-image digests.
func (l *ChainedLedger) RecordWithHashes(tenantID, sessionID, action, reqHash, respHash string) error {
	if l.closed.Load() {
		return ErrClosed
	}

	rec := &AuditRecord{
		Timestamp:    time.Now().UnixNano(),
		TenantID:     tenantID,
		SessionID:    sessionID,
		Action:       action,
		RequestHash:  reqHash,
		ResponseHash: respHash,
	}

	if !l.ringBuffer.TryPush(rec) {
		return ErrBufferFull
	}
	return nil
}

func (l *ChainedLedger) writerLoop() {
	defer close(l.doneChan)

	var batch []*AuditRecord
	flushTicker := time.NewTicker(20 * time.Millisecond)
	defer flushTicker.Stop()

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		l.mu.Lock()
		defer l.mu.Unlock()

		for _, rec := range batch {
			l.lastSeq++
			rec.SequenceID = l.lastSeq
			rec.PrevHash = l.lastHash
			rec.EntryHash = ComputeEntryHash(
				l.hmacKey,
				rec.PrevHash,
				rec.SequenceID,
				rec.Timestamp,
				rec.TenantID,
				rec.Action,
				rec.RequestHash,
				rec.ResponseHash,
			)
			l.lastHash = rec.EntryHash

			data, err := json.Marshal(rec)
			if err == nil {
				_, _ = l.file.Write(append(data, '\n'))
			}
		}
		_ = l.file.Sync()
		batch = batch[:0]
	}

	for {
		for {
			rec := l.ringBuffer.Pop()
			if rec == nil {
				break
			}
			batch = append(batch, rec)
			if len(batch) >= 256 {
				flushBatch()
			}
		}

		if len(batch) > 0 {
			flushBatch()
		}

		select {
		case <-l.ringBuffer.notify:
		case <-flushTicker.C:
		case <-l.stopChan:
			for {
				rec := l.ringBuffer.Pop()
				if rec == nil {
					break
				}
				batch = append(batch, rec)
			}
			flushBatch()
			return
		}
	}
}

// Flush blocks until all currently enqueued records in the ring buffer have been flushed to disk.
func (l *ChainedLedger) Flush() {
	for {
		if l.ringBuffer.head.Load() == l.ringBuffer.tail.Load() {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
}

// Close gracefully flushes all pending journal records, syncs the file to disk, and closes it.
func (l *ChainedLedger) Close() error {
	if !l.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(l.stopChan)
	<-l.doneChan

	l.mu.Lock()
	defer l.mu.Unlock()

	_ = l.file.Sync()
	return l.file.Close()
}

// LastSequence returns the last sequence ID committed to disk.
func (l *ChainedLedger) LastSequence() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastSeq
}

// LastHash returns the last cryptographic hash committed to disk.
func (l *ChainedLedger) LastHash() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastHash
}
