package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"ai-security-guardrail-proxy/internal/audit"
	"ai-security-guardrail-proxy/internal/auth"
	"ai-security-guardrail-proxy/internal/config"
	"ai-security-guardrail-proxy/internal/dispatcher"
	"ai-security-guardrail-proxy/internal/inbound"
	"ai-security-guardrail-proxy/internal/metrics"
	"ai-security-guardrail-proxy/internal/pipeline"
)

// Server encapsulates the HTTP ingress server, routing, and guardrail pipeline.
type Server struct {
	config          *config.Config
	authenticator   *auth.Authenticator
	pipeline        *pipeline.PipelineRunner
	dispatcher      *dispatcher.Dispatcher
	auditLedger     *audit.ChainedLedger
	metricsRegistry *metrics.Registry
	httpServer      *http.Server
	mux             *http.ServeMux
}

// NewServer constructs and wires the ingress HTTP server with audit ledger and metrics registry.
func NewServer(
	cfg *config.Config,
	authenticator *auth.Authenticator,
	runner *pipeline.PipelineRunner,
	disp *dispatcher.Dispatcher,
) *Server {
	if runner == nil || len(runner.Stages()) == 0 {
		runner = inbound.NewDefaultPipeline(cfg)
	}

	var auditLedger *audit.ChainedLedger
	if cfg.Audit.JournalPath != "" {
		al, err := audit.NewChainedLedger(cfg.Audit.JournalPath, []byte(cfg.Audit.HMACKey), cfg.Audit.NodeID)
		if err != nil {
			// Fallback to temp file if configured path cannot be created (e.g. unprivileged test env)
			tmpPath := filepath.Join(os.TempDir(), fmt.Sprintf("guardrail-audit-%d.log", time.Now().UnixNano()))
			al, _ = audit.NewChainedLedger(tmpPath, []byte(cfg.Audit.HMACKey), cfg.Audit.NodeID)
		}
		auditLedger = al
	}

	if disp != nil && auditLedger != nil {
		disp.SetAuditLedger(auditLedger)
	}

	s := &Server{
		config:          cfg,
		authenticator:   authenticator,
		pipeline:        runner,
		dispatcher:      disp,
		auditLedger:     auditLedger,
		metricsRegistry: metrics.DefaultRegistry,
		mux:             http.NewServeMux(),
	}

	s.registerRoutes()

	s.httpServer = &http.Server{
		Addr:              cfg.GetListenAddr(),
		Handler:           s.mux,
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       cfg.Timeouts.IdleTimeout(),
		MaxHeaderBytes:    1 << 16, // 64KB
	}

	return s
}

// Handler returns the server's root HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// AuditLedger returns the attached audit ledger.
func (s *Server) AuditLedger() *audit.ChainedLedger {
	return s.auditLedger
}

// SetAuditLedger overrides or updates the audit ledger.
func (s *Server) SetAuditLedger(al *audit.ChainedLedger) {
	s.auditLedger = al
	if s.dispatcher != nil {
		s.dispatcher.SetAuditLedger(al)
	}
}

// MetricsRegistry returns the metrics registry.
func (s *Server) MetricsRegistry() *metrics.Registry {
	return s.metricsRegistry
}

// SetMetricsRegistry overrides or updates the metrics registry.
func (s *Server) SetMetricsRegistry(mr *metrics.Registry) {
	s.metricsRegistry = mr
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server, flushing all audit ledger entries.
func (s *Server) Shutdown(ctx context.Context) error {
	var errs []error
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if s.auditLedger != nil {
		if err := s.auditLedger.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (s *Server) registerRoutes() {
	// Health & Liveness probes
	s.mux.HandleFunc("/healthz/liveness", s.handleLiveness)
	s.mux.HandleFunc("/healthz/readiness", s.handleReadiness)

	// Prometheus Metrics endpoint
	s.mux.Handle("/metrics", s.metricsRegistry.Handler())

	// API Gateway routes: /v1/*
	s.mux.HandleFunc("/v1/", s.handleProxy)
}

func (s *Server) handleLiveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready"}`))
}

func (s *Server) handleProxy(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate incoming request
	tc, err := s.authenticator.Authenticate(r)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, auth.ErrDisabledTenant) {
			status = http.StatusForbidden
		}
		auth.WriteAuthError(w, status, err)

		errJSON, _ := json.Marshal(map[string]any{"error": err.Error()})
		if s.auditLedger != nil {
			_ = s.auditLedger.Record("unauthenticated", "", "AUTH_FAILURE", nil, errJSON)
		}
		s.metricsRegistry.IncRequests("unauthenticated", "AUTH_FAILURE", fmt.Sprint(status))
		s.metricsRegistry.IncAuditRecords()
		return
	}

	// 2. Enforce MaxPayloadBytes limit
	r.Body = http.MaxBytesReader(w, r.Body, s.config.MaxPayloadBytes)
	rawPayload, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			errJSON, _ := json.Marshal(map[string]any{
				"error": map[string]any{
					"code":    "payload_too_large",
					"message": fmt.Sprintf("request payload exceeds maximum limit of %d bytes", s.config.MaxPayloadBytes),
				},
			})
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				fmt.Sprintf("request payload exceeds maximum limit of %d bytes", s.config.MaxPayloadBytes))

			if s.auditLedger != nil {
				_ = s.auditLedger.Record(tc.TenantID, "", "PAYLOAD_TOO_LARGE", nil, errJSON)
			}
			s.metricsRegistry.IncRequests(tc.TenantID, "PAYLOAD_TOO_LARGE", "413")
			s.metricsRegistry.IncAuditRecords()
			return
		}
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("failed to read request body: %v", err))
		return
	}

	// 3. Acquire recycled PipelineContext
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.Header.Get("X-Request-ID")
	}
	pc := pipeline.AcquireContext(r.Context(), tc.TenantID, sessionID)
	defer pipeline.ReleaseContext(pc)

	pc.RequestID = r.Header.Get("X-Request-ID")
	pc.RawPayload = append(pc.RawPayload, rawPayload...)
	pc.CleanPayload = append(pc.CleanPayload, rawPayload...)

	// Detect streaming intent
	if strings.Contains(string(rawPayload), `"stream":true`) || r.URL.Query().Get("stream") == "true" {
		pc.IsStreaming = true
	}

	// 4. Execute deterministic inspection pipeline
	stageResult, stageErr := s.pipeline.Execute(pc)
	if stageResult == pipeline.StageTripwire {
		ruleID := pc.MatchedRuleID
		if ruleID == "" {
			ruleID = "POLICY_VIOLATION"
		}
		msg := "request blocked by security guardrail policy"
		if stageErr != nil {
			msg = stageErr.Error()
		}

		if pc.ViolationType == "RATE_LIMIT" || ruleID == "RATE_LIMIT_EXCEEDED" {
			errResp := map[string]any{
				"error": map[string]any{
					"code":    "RATE_LIMIT_EXCEEDED",
					"rule_id": ruleID,
					"message": msg,
				},
			}
			errJSON, _ := json.Marshal(errResp)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write(errJSON)

			if s.auditLedger != nil {
				_ = s.auditLedger.Record(pc.TenantID, pc.SessionID, "RATE_LIMIT", rawPayload, errJSON)
			}
			s.metricsRegistry.IncRequests(pc.TenantID, "RATE_LIMIT", "429")
			s.metricsRegistry.IncTripwireViolations("RATE_LIMIT_EXCEEDED", "rate_limiter")
			s.metricsRegistry.IncAuditRecords()
			return
		}

		errResp := map[string]any{
			"error": map[string]any{
				"code":    "POLICY_VIOLATION",
				"rule_id": ruleID,
				"message": msg,
			},
		}
		errJSON, _ := json.Marshal(errResp)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write(errJSON)

		if s.auditLedger != nil {
			_ = s.auditLedger.Record(pc.TenantID, pc.SessionID, "BLOCK_INBOUND", rawPayload, errJSON)
		}
		s.metricsRegistry.IncRequests(pc.TenantID, "BLOCK_INBOUND", "400")
		s.metricsRegistry.IncTripwireViolations(ruleID, "inbound_inspection")
		s.metricsRegistry.IncAuditRecords()
		for stageName, durUs := range pc.StageDurations {
			s.metricsRegistry.ObserveStageDuration(stageName, float64(durUs)/1e6)
		}
		return
	}

	// 5. Forward validated request to upstream inference endpoint
	_ = s.dispatcher.Forward(w, r, pc)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
