package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"ai-security-guardrail-proxy/internal/audit"
	"ai-security-guardrail-proxy/internal/auth"
	"ai-security-guardrail-proxy/internal/config"
	"ai-security-guardrail-proxy/internal/dispatcher"
	"ai-security-guardrail-proxy/internal/inbound"
	"ai-security-guardrail-proxy/internal/resilience"
	"ai-security-guardrail-proxy/internal/server"
)

func main() {
	// Support CLI command: guardrail-proxy audit verify -file <path> [-key <key>]
	if len(os.Args) >= 3 && os.Args[1] == "audit" && os.Args[2] == "verify" {
		auditCmd := flag.NewFlagSet("audit verify", flag.ExitOnError)
		filePath := auditCmd.String("file", "", "Path to cryptographic audit ledger file")
		keyFlag := auditCmd.String("key", "", "HMAC secret key for chain verification (optional)")
		_ = auditCmd.Parse(os.Args[3:])

		if *filePath == "" {
			fmt.Fprintln(os.Stderr, "[ERROR] Missing required flag: -file <path>")
			os.Exit(1)
		}

		var key []byte
		if *keyFlag != "" {
			key = []byte(*keyFlag)
		} else if envKey := os.Getenv("AUDIT_HMAC_KEY"); envKey != "" {
			key = []byte(envKey)
		}

		valid, count, err := audit.VerifyChain(*filePath, key)
		if !valid || err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Audit chain verification FAILED: %v (records verified: %d)\n", err, count)
			os.Exit(1)
		}

		fmt.Printf("[OK] Audit chain verification SUCCESS: %d records verified cleanly.\n", count)
		os.Exit(0)
	}

	configPath := flag.String("config", "", "Path to YAML or JSON configuration file")
	portFlag := flag.Int("port", 0, "Server listening port (overrides config)")
	upstreamFlag := flag.String("upstream", "", "Upstream model endpoint URL (overrides config)")
	upstreamKeyFlag := flag.String("upstream-key", "", "Upstream API authorization bearer key (overrides config)")
	flag.Parse()

	var cfg *config.Config
	var err error

	if *configPath != "" {
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("[FATAL] Failed to load configuration from %q: %v", *configPath, err)
		}
	} else {
		cfg = config.NewDefaultConfig()
	}

	if *portFlag > 0 {
		cfg.Port = *portFlag
		cfg.ListenAddr = fmt.Sprintf(":%d", *portFlag)
	}
	if *upstreamFlag != "" {
		cfg.UpstreamURL = *upstreamFlag
	}
	if *upstreamKeyFlag != "" {
		cfg.UpstreamAuthToken = *upstreamKeyFlag
	}

	// Initialize Tenant Authenticator
	var tenantList []auth.TenantContext
	for _, tc := range cfg.Tenants {
		tenantList = append(tenantList, auth.TenantContext{
			TenantID: tc.TenantID,
			Name:     tc.Name,
			APIKey:   tc.APIKey,
			Enabled:  tc.Enabled,
		})
	}
	authenticator := auth.NewAuthenticator(tenantList)

	// Initialize Pipeline Runner (Layer 2 Inbound Deterministic Engine)
	runner := inbound.NewDefaultPipeline(cfg)

	// Initialize Upstream Dispatcher
	disp, err := dispatcher.NewDispatcher(cfg.GetUpstreamURL(), cfg.Timeouts.IdleTimeout())
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize upstream dispatcher: %v", err)
	}
	if cfg.UpstreamAuthToken != "" {
		disp.SetUpstreamAuthToken(cfg.UpstreamAuthToken)
	}

	// Configure Upstream Circuit Breaker from config
	disp.SetCircuitBreaker(resilience.NewCircuitBreaker(resilience.Config{
		FailureThreshold: cfg.CircuitBreaker.FailureThreshold,
		CooldownDuration: time.Duration(cfg.CircuitBreaker.CooldownSeconds) * time.Second,
		HalfOpenProbes:   cfg.CircuitBreaker.HalfOpenProbes,
	}))

	// Initialize Ingress Server
	srv := server.NewServer(cfg, authenticator, runner, disp)

	// Graceful shutdown signaling
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		log.Printf("[INFO] AI Security Guardrail Proxy starting on %s (upstream: %s)",
			cfg.GetListenAddr(), cfg.GetUpstreamURL())
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[FATAL] Ingress server failed: %v", err)
		}
	}()

	sig := <-stopChan
	log.Printf("[INFO] Received signal %s, draining connections and flushing audit journal...", sig)

	drainCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("[ERROR] Server graceful drain encountered error: %v", err)
	} else {
		log.Printf("[INFO] Ingress server stopped cleanly.")
	}
}
