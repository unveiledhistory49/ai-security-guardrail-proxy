package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Default constants for proxy configuration.
const (
	DefaultHost            = "0.0.0.0"
	DefaultPort            = 8080
	DefaultListenAddr      = ":8080"
	DefaultUpstreamURL     = "http://localhost:11434"
	DefaultMaxPayloadBytes = 4 * 1024 * 1024 // 4MB
	DefaultReadTimeoutMs   = 10000          // 10s
	DefaultWriteTimeoutMs  = 60000          // 60s
	DefaultIdleTimeoutMs   = 120000         // 120s
	DefaultUpstreamTimeout = 60000          // 60s
)

// TenantConfig represents an individual tenant's security identity and state.
type TenantConfig struct {
	APIKey   string `json:"api_key" yaml:"api_key"`
	TenantID string `json:"tenant_id" yaml:"tenant_id"`
	Name     string `json:"name" yaml:"name"`
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	RPM      int    `json:"rpm" yaml:"rpm"`
	TPM      int    `json:"tpm" yaml:"tpm"`
}

// TimeoutConfig defines timeouts across the ingress proxy and upstream dispatcher.
type TimeoutConfig struct {
	ReadTimeoutMs     int64 `json:"read_timeout_ms" yaml:"read_timeout_ms"`
	WriteTimeoutMs    int64 `json:"write_timeout_ms" yaml:"write_timeout_ms"`
	IdleTimeoutMs     int64 `json:"idle_timeout_ms" yaml:"idle_timeout_ms"`
	UpstreamTimeoutMs int64 `json:"upstream_timeout_ms" yaml:"upstream_timeout_ms"`
}

// ReadTimeout returns the read timeout duration.
func (t TimeoutConfig) ReadTimeout() time.Duration {
	if t.ReadTimeoutMs <= 0 {
		return time.Duration(DefaultReadTimeoutMs) * time.Millisecond
	}
	return time.Duration(t.ReadTimeoutMs) * time.Millisecond
}

// WriteTimeout returns the write timeout duration.
func (t TimeoutConfig) WriteTimeout() time.Duration {
	if t.WriteTimeoutMs <= 0 {
		return time.Duration(DefaultWriteTimeoutMs) * time.Millisecond
	}
	return time.Duration(t.WriteTimeoutMs) * time.Millisecond
}

// IdleTimeout returns the idle connection timeout duration.
func (t TimeoutConfig) IdleTimeout() time.Duration {
	if t.IdleTimeoutMs <= 0 {
		return time.Duration(DefaultIdleTimeoutMs) * time.Millisecond
	}
	return time.Duration(t.IdleTimeoutMs) * time.Millisecond
}

// UpstreamTimeout returns the upstream dispatch timeout duration.
func (t TimeoutConfig) UpstreamTimeout() time.Duration {
	if t.UpstreamTimeoutMs <= 0 {
		return time.Duration(DefaultUpstreamTimeout) * time.Millisecond
	}
	return time.Duration(t.UpstreamTimeoutMs) * time.Millisecond
}

// TenantMap supports deserializing tenants from either a JSON/YAML map or list.
type TenantMap map[string]TenantConfig

// UnmarshalJSON implements custom JSON unmarshaling for TenantMap.
func (tm *TenantMap) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if len(trimmed) == 0 || trimmed == "null" {
		*tm = make(map[string]TenantConfig)
		return nil
	}

	// Case 1: Array of TenantConfig
	if trimmed[0] == '[' {
		var list []TenantConfig
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		res := make(map[string]TenantConfig, len(list))
		for _, t := range list {
			key := t.APIKey
			if key == "" {
				key = t.TenantID
			}
			if key != "" {
				res[key] = t
			}
		}
		*tm = res
		return nil
	}

	// Case 2: Map of TenantConfig
	var m map[string]TenantConfig
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	for k, v := range m {
		if v.APIKey == "" {
			v.APIKey = k
			m[k] = v
		}
	}
	*tm = m
	return nil
}

// AuditConfig defines parameters for the cryptographic audit journal.
type AuditConfig struct {
	JournalPath     string `json:"journal_path" yaml:"journal_path"`
	RingBufferSize  int    `json:"ring_buffer_size" yaml:"ring_buffer_size"`
	FlushIntervalMs int64  `json:"flush_interval_ms" yaml:"flush_interval_ms"`
	HMACKey         string `json:"hmac_key" yaml:"hmac_key"`
	NodeID          string `json:"node_id" yaml:"node_id"`
}

// CircuitBreakerConfig defines failure thresholds and cooldown for upstream dispatch.
type CircuitBreakerConfig struct {
	FailureThreshold uint32 `json:"failure_threshold" yaml:"failure_threshold"`
	CooldownSeconds  int64  `json:"cooldown_seconds" yaml:"cooldown_seconds"`
	HalfOpenProbes   uint32 `json:"half_open_probes" yaml:"half_open_probes"`
}

// Config is the top-level structured configuration for the AI Security Guardrail Proxy.
type Config struct {
	Host            string               `json:"host" yaml:"host"`
	Port            int                  `json:"port" yaml:"port"`
	ListenAddr      string               `json:"listen_addr" yaml:"listen_addr"`
	UpstreamURL       string               `json:"upstream_url" yaml:"upstream_url"`
	UpstreamAuthToken string               `json:"upstream_auth_token" yaml:"upstream_auth_token"`
	MaxPayloadBytes   int64                `json:"max_payload_bytes" yaml:"max_payload_bytes"`
	Timeouts          TimeoutConfig        `json:"timeouts" yaml:"timeouts"`
	Tenants           TenantMap            `json:"tenants" yaml:"tenants"`
	Audit             AuditConfig          `json:"audit" yaml:"audit"`
	CircuitBreaker    CircuitBreakerConfig `json:"circuit_breaker" yaml:"circuit_breaker"`
}

// NewDefaultConfig constructs a standard configuration with hardened production defaults.
func NewDefaultConfig() *Config {
	return &Config{
		Host:            DefaultHost,
		Port:            DefaultPort,
		ListenAddr:      DefaultListenAddr,
		UpstreamURL:     DefaultUpstreamURL,
		MaxPayloadBytes: DefaultMaxPayloadBytes,
		Timeouts: TimeoutConfig{
			ReadTimeoutMs:     DefaultReadTimeoutMs,
			WriteTimeoutMs:    DefaultWriteTimeoutMs,
			IdleTimeoutMs:     DefaultIdleTimeoutMs,
			UpstreamTimeoutMs: DefaultUpstreamTimeout,
		},
		Tenants: make(TenantMap),
		Audit: AuditConfig{
			JournalPath:    "/var/log/guardrail/audit.log",
			RingBufferSize: 65536,
			NodeID:         "guardrail-proxy-node-1",
		},
		CircuitBreaker: CircuitBreakerConfig{
			FailureThreshold: 5,
			CooldownSeconds:  30,
			HalfOpenProbes:   2,
		},
	}
}

// GetListenAddr returns the effective listening network address.
func (c *Config) GetListenAddr() string {
	if c.ListenAddr != "" {
		return c.ListenAddr
	}
	if c.Port > 0 {
		if c.Host != "" && c.Host != "0.0.0.0" {
			return fmt.Sprintf("%s:%d", c.Host, c.Port)
		}
		return fmt.Sprintf(":%d", c.Port)
	}
	return DefaultListenAddr
}

// GetUpstreamURL returns the configured upstream model URL.
func (c *Config) GetUpstreamURL() string {
	if c.UpstreamURL != "" {
		return c.UpstreamURL
	}
	return DefaultUpstreamURL
}

// AddTenant registers a tenant programmatically.
func (c *Config) AddTenant(t TenantConfig) {
	if c.Tenants == nil {
		c.Tenants = make(TenantMap)
	}
	key := t.APIKey
	if key == "" {
		key = t.TenantID
	}
	c.Tenants[key] = t
}

// LoadConfig reads configuration from a JSON or YAML file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	format := "json"
	if ext == ".yaml" || ext == ".yml" {
		format = "yaml"
	}

	return ParseConfigData(data, format)
}

// ParseConfigData parses configuration data in "json" or "yaml" format.
func ParseConfigData(data []byte, format string) (*Config, error) {
	cfg := NewDefaultConfig()

	var jsonBytes []byte
	switch strings.ToLower(format) {
	case "yaml", "yml":
		jb, err := YAMLToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML configuration: %w", err)
		}
		jsonBytes = jb
	case "json":
		jsonBytes = data
	default:
		// Attempt JSON first, fallback to YAML
		if err := json.Unmarshal(data, cfg); err == nil {
			applyDefaultsAndNormalize(cfg)
			return cfg, nil
		}
		jb, err := YAMLToJSON(data)
		if err != nil {
			return nil, fmt.Errorf("unsupported or malformed configuration format: %w", err)
		}
		jsonBytes = jb
	}

	if err := json.Unmarshal(jsonBytes, cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration: %w", err)
	}

	applyDefaultsAndNormalize(cfg)
	return cfg, nil
}

func applyDefaultsAndNormalize(cfg *Config) {
	if cfg.Port <= 0 && cfg.ListenAddr == "" {
		cfg.Port = DefaultPort
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = cfg.GetListenAddr()
	}
	if cfg.UpstreamURL == "" {
		cfg.UpstreamURL = DefaultUpstreamURL
	}
	if cfg.MaxPayloadBytes <= 0 {
		cfg.MaxPayloadBytes = DefaultMaxPayloadBytes
	}
	if cfg.Timeouts.ReadTimeoutMs <= 0 {
		cfg.Timeouts.ReadTimeoutMs = DefaultReadTimeoutMs
	}
	if cfg.Timeouts.WriteTimeoutMs <= 0 {
		cfg.Timeouts.WriteTimeoutMs = DefaultWriteTimeoutMs
	}
	if cfg.Timeouts.IdleTimeoutMs <= 0 {
		cfg.Timeouts.IdleTimeoutMs = DefaultIdleTimeoutMs
	}
	if cfg.Timeouts.UpstreamTimeoutMs <= 0 {
		cfg.Timeouts.UpstreamTimeoutMs = DefaultUpstreamTimeout
	}
	if cfg.Tenants == nil {
		cfg.Tenants = make(TenantMap)
	}
	if cfg.Audit.JournalPath == "" {
		cfg.Audit.JournalPath = "/var/log/guardrail/audit.log"
	}
	if cfg.Audit.RingBufferSize <= 0 {
		cfg.Audit.RingBufferSize = 65536
	}
	if cfg.Audit.NodeID == "" {
		cfg.Audit.NodeID = "guardrail-proxy-node-1"
	}
	if cfg.CircuitBreaker.FailureThreshold == 0 {
		cfg.CircuitBreaker.FailureThreshold = 5
	}
	if cfg.CircuitBreaker.CooldownSeconds <= 0 {
		cfg.CircuitBreaker.CooldownSeconds = 30
	}
	if cfg.CircuitBreaker.HalfOpenProbes == 0 {
		cfg.CircuitBreaker.HalfOpenProbes = 2
	}
}
