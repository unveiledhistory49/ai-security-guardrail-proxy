# AI Security Guardrail Proxy

[![Go Version](https://img.shields.io/badge/Go-1.23.6-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20External-brightgreen)]()
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)]()

A high-performance, deterministic AI security reverse proxy engineered to govern inbound prompts and outbound model streaming completions. Operates directly in the network data path with **zero external runtime dependencies** (pure Go 1.23+ standard library).

> **Architectural Thesis:** *"AI proposes. Deterministic systems enforce. Zero external dependencies."*

---

## Technical Specifications & Documentation

The system is designed and documented in accordance with [00-PROJECT-PHILOSOPHY.md](file:///root/company-project-specs/00-PROJECT-PHILOSOPHY.md) and [09-ai-security-guardrail-proxy.md](file:///root/company-project-specs/09-ai-security-guardrail-proxy.md).

- **Master Design Document**: [DESIGN.md](file:///root/ai-security-guardrail-proxy/DESIGN.md)
- **Deep Architecture Specification**: [docs/ARCHITECTURE.md](file:///root/ai-security-guardrail-proxy/docs/ARCHITECTURE.md)
- **Security Boundaries & Cryptographic Invariants**: [docs/SECURITY-BOUNDARIES.md](file:///root/ai-security-guardrail-proxy/docs/SECURITY-BOUNDARIES.md)
- **STRIDE Threat Model & Attack Trees**: [docs/THREAT-MODEL.md](file:///root/ai-security-guardrail-proxy/docs/THREAT-MODEL.md)
- **Failure Modes & Effects Analysis (FMEA)**: [docs/FAILURE-MODES.md](file:///root/ai-security-guardrail-proxy/docs/FAILURE-MODES.md)
- **Service Level Objectives & Prometheus Catalog**: [docs/SLO.md](file:///root/ai-security-guardrail-proxy/docs/SLO.md)
- **Operational Runbooks & Production Hardening**: [docs/OPERATIONS.md](file:///root/ai-security-guardrail-proxy/docs/OPERATIONS.md)
- **Architectural Decision Records (ADRs)**:
  - [ADR-001: Zero-Dependency Go Runtime](file:///root/ai-security-guardrail-proxy/docs/adr/ADR-001-language-and-runtime-selection.md)
  - [ADR-002: Deterministic Linear Inspection Pipeline](file:///root/ai-security-guardrail-proxy/docs/adr/ADR-002-deterministic-inspection-pipeline.md)
  - [ADR-003: Sliding-Lookahead SSE Tripwires](file:///root/ai-security-guardrail-proxy/docs/adr/ADR-003-streaming-chunk-inspection-and-tripwires.md)
  - [ADR-004: Canary Token & Pseudonymization Lifecycle](file:///root/ai-security-guardrail-proxy/docs/adr/ADR-004-canary-token-and-pseudonymization-lifecycle.md)
  - [ADR-005: Cryptographic Hash-Chained Audit Ledger](file:///root/ai-security-guardrail-proxy/docs/adr/ADR-005-cryptographic-hash-chained-audit-ledger.md)

---

## System Architecture

```text
Client Application
       │ (HTTP/1.1 or HTTP/2)
       ▼
+─────────────────────────────────────────────────────────────+
|               AI Security Guardrail Proxy                   |
|                                                             |
|  [Ingress & Authentication]                                 |
|   ├─ Constant-time API key verification (subtle.Compare)    |
|   └─ Tenant context resolution & MaxPayload clamping        |
|                                                             |
|  [Inbound Inspection Engine - O(N) Deterministic]           |
|   ├─ Sliding-window rate & quota limiter (RPM/TPM)          |
|   ├─ Unicode NFKC & zero-width delimiter sanitizer          |
|   ├─ Aho-Corasick multi-pattern injection matcher           |
|   ├─ Shannon entropy bounds analyzer (obfuscation/DoS)      |
|   ├─ Linear RE2 secret & PII redaction (Luhn mod-10)        |
|   └─ Cryptographic HMAC-SHA256 canary token synthesizer     |
|                                                             |
|  [Dispatcher & Resilience]                                  |
|   ├─ Upstream Circuit Breaker (Closed / Open / Half-Open)   |
|   ├─ Immediate client context cancellation propagation      |
|   └─ Connection-pooled HTTP/1.1 & HTTP/2 transport          |
|                                                             |
|  [Outbound Guardrail Engine - Streaming Lookahead]          |
|   ├─ Sliding lookahead window (W=128B, L=64B)               |
|   ├─ Active canary token exfiltration tripwire              |
|   ├─ Outbound secret & credential leak detection            |
|   ├─ Violent TCP socket termination on tripwire             |
|   └─ Output JSON and tool call schema validation            |
|                                                             |
|  [Cryptographic Audit & Telemetry]                          |
|   ├─ Lock-free async ring buffer (capacity 65,536)          |
|   ├─ Append-only HMAC-SHA256 hash-chained disk journal      |
|   ├─ Zero plaintext prompt retention (pre-image digests)    |
|   └─ Prometheus text format telemetry endpoint (/metrics)   |
+─────────────────────────────────────────────────────────────+
       │
       ▼
Upstream LLM Endpoint (Ollama, vLLM, or Cloud API)
```

---

## Core Capabilities Across the 4 Layers

### Layer 1: Core Proxy & Multi-Tenant Authentication
- Standard library HTTP/1.1 and HTTP/2 proxy listener.
- Timing-attack-resistant constant-time API key verification via `crypto/subtle`.
- Zero-heap allocation request context pooling via `sync.Pool` (`0 B/op, 0 allocs/op`).
- Explicit memory zeroization (`memzero`) on recycled buffers.

### Layer 2: Inbound Deterministic Engine
- **Delimiter Sanitizer**: Strips Unicode bidirectional overrides and zero-width spaces; blocks prompt framing breakout tags (`<|im_start|>`, `[INST]`, `<<SYS>>`).
- **Aho-Corasick Matcher**: $O(N+M)$ single-pass DFA with dense `[256]uint32` transition tables detecting prompt-injection signatures with zero allocations.
- **Entropy Analyzer**: Computes Shannon entropy $H(X)$ to block Base64/hex obfuscated injections ($H \ge 4.8$) and token repetition DoS attacks ($H \le 1.0$).
- **Deterministic DLP**: RE2 regular expressions scanning for AWS keys, GitHub tokens, OpenAI keys, private keys, database URIs, and credit card PANs (with inline $O(1)$ Luhn verification).
- **Canary Token Synthesizer**: Injects unique HMAC-SHA256 canary strings (`SEC-CNR-...`) into system prompts.
- **Sliding-Window Limiter**: Enforces tenant-level RPM and TPM quotas, returning 429 Too Many Requests when exhausted.

### Layer 3: Outbound SSE Guardrails & Canary Tripwires
- **Sliding Lookahead Window ($W=128\text{B}, L=64\text{B}$)**: Guarantees that patterns spanning chunk boundaries are caught before bytes are released downstream.
- **Canary Tripwire Abort**: Terminates connections upon detecting canary tokens, emits RFC-compliant SSE error frames (`TRIPWIRE_VIOLATION`), cancels upstream GPU compute, and violently severs the TCP socket.
- **Outbound Secret Exfiltration Filter**: Catches credentials in generated responses and blocks synchronous leaks with HTTP 502 Bad Gateway.
- **Schema Validator**: Enforces strict JSON syntax and structure compliance on model tool calls.

### Layer 4: Resilience, Cryptographic Audit & Telemetry
- **Cryptographic Audit Ledger**: Sequential HMAC-SHA256 hash recurrence chaining ($H_i = \text{HMAC}(H_{i-1} \parallel \dots)$). Guarantees forward tamper-evidence.
- **Lock-Free Ring Buffer**: MPSC atomic circular buffer with 65,536 slot capacity, isolating the request path from disk I/O ($< 100\text{ns}$ latency overhead).
- **Circuit Breaker**: Implements `CLOSED`, `OPEN`, and `HALF-OPEN` states with automated fast-fail and probe recovery.
- **Prometheus Telemetry**: Real-time `/metrics` endpoint exposing request counters, sub-millisecond stage duration histograms, tripwire counters, and circuit breaker gauges.
- **CLI Verifier**: Built-in `guardrail-proxy audit verify` tool to detect tampering.

---

## Quickstart

### Build the Binary
```bash
go build -o guardrail-proxy ./cmd/proxy
```

### Run the Proxy
```bash
./guardrail-proxy -config config.example.yaml
```

### Inspect Health
```bash
curl -i http://localhost:8080/healthz/liveness
curl -i http://localhost:8080/healthz/readiness
```

### Query Metrics
```bash
curl -s http://localhost:8080/metrics
```

### Verify Audit Ledger Integrity
```bash
./guardrail-proxy audit verify -file /var/log/guardrail/audit.log
```

---

## Test Verification

Run the full automated unit and end-to-end integration test suite:

```bash
go test -v -count=1 ./...
```

All packages pass with 100% success rate:
- `internal/auth`
- `internal/config`
- `internal/dispatcher`
- `internal/inbound`
- `internal/metrics`
- `internal/outbound`
- `internal/pipeline`
- `internal/resilience`
- `internal/server`
- `test` (21 end-to-end integration tests)
