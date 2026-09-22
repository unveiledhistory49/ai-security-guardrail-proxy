package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewDefaultConfig(t *testing.T) {
	cfg := NewDefaultConfig()
	if cfg.Port != 8080 {
		t.Fatalf("expected default port 8080, got %d", cfg.Port)
	}
	if cfg.ListenAddr != ":8080" {
		t.Fatalf("expected default listen addr :8080, got %s", cfg.ListenAddr)
	}
	if cfg.UpstreamURL != "http://localhost:11434" {
		t.Fatalf("expected default upstream url http://localhost:11434, got %s", cfg.UpstreamURL)
	}
	if cfg.MaxPayloadBytes != 4*1024*1024 {
		t.Fatalf("expected default max payload 4MB, got %d", cfg.MaxPayloadBytes)
	}
	if cfg.Timeouts.ReadTimeout() != 10*time.Second {
		t.Fatalf("expected 10s read timeout, got %v", cfg.Timeouts.ReadTimeout())
	}
	if cfg.Timeouts.WriteTimeout() != 60*time.Second {
		t.Fatalf("expected 60s write timeout, got %v", cfg.Timeouts.WriteTimeout())
	}
	if cfg.Timeouts.IdleTimeout() != 120*time.Second {
		t.Fatalf("expected 120s idle timeout, got %v", cfg.Timeouts.IdleTimeout())
	}
	if cfg.Timeouts.UpstreamTimeout() != 60*time.Second {
		t.Fatalf("expected 60s upstream timeout, got %v", cfg.Timeouts.UpstreamTimeout())
	}
}

func TestParseConfigJSON(t *testing.T) {
	jsonContent := `{
		"host": "127.0.0.1",
		"port": 9090,
		"upstream_url": "http://10.0.0.1:8000",
		"max_payload_bytes": 2097152,
		"timeouts": {
			"read_timeout_ms": 5000,
			"write_timeout_ms": 30000,
			"idle_timeout_ms": 60000,
			"upstream_timeout_ms": 25000
		},
		"tenants": [
			{
				"api_key": "sk-test-123",
				"tenant_id": "tenant-alpha",
				"name": "Alpha Team",
				"enabled": true
			},
			{
				"api_key": "sk-test-456",
				"tenant_id": "tenant-disabled",
				"name": "Disabled Team",
				"enabled": false
			}
		]
	}`

	cfg, err := ParseConfigData([]byte(jsonContent), "json")
	if err != nil {
		t.Fatalf("failed to parse JSON config: %v", err)
	}

	if cfg.Port != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.Port)
	}
	if cfg.UpstreamURL != "http://10.0.0.1:8000" {
		t.Fatalf("expected upstream URL http://10.0.0.1:8000, got %s", cfg.UpstreamURL)
	}
	if cfg.MaxPayloadBytes != 2097152 {
		t.Fatalf("expected 2MB max payload, got %d", cfg.MaxPayloadBytes)
	}
	if cfg.Timeouts.ReadTimeout() != 5*time.Second {
		t.Fatalf("expected 5s read timeout, got %v", cfg.Timeouts.ReadTimeout())
	}
	if cfg.Timeouts.UpstreamTimeout() != 25*time.Second {
		t.Fatalf("expected 25s upstream timeout, got %v", cfg.Timeouts.UpstreamTimeout())
	}
	if len(cfg.Tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(cfg.Tenants))
	}

	t1, ok := cfg.Tenants["sk-test-123"]
	if !ok || !t1.Enabled || t1.TenantID != "tenant-alpha" {
		t.Fatalf("tenant-alpha mismatch: %+v", t1)
	}

	t2, ok := cfg.Tenants["sk-test-456"]
	if !ok || t2.Enabled || t2.TenantID != "tenant-disabled" {
		t.Fatalf("tenant-disabled mismatch: %+v", t2)
	}
}

func TestParseConfigYAML(t *testing.T) {
	yamlContent := `
host: "127.0.0.1"
port: 9000
listen_addr: "127.0.0.1:9000"
upstream_url: "http://localhost:8080"
max_payload_bytes: 8388608
timeouts:
  read_timeout_ms: 3000
  write_timeout_ms: 15000
  idle_timeout_ms: 45000
  upstream_timeout_ms: 12000
tenants:
  - api_key: "sk-yaml-1"
    tenant_id: "tenant-yaml"
    name: "YAML Tenant"
    enabled: true
  - api_key: "sk-yaml-2"
    tenant_id: "tenant-yaml-2"
    name: "Disabled YAML"
    enabled: false
`

	cfg, err := ParseConfigData([]byte(yamlContent), "yaml")
	if err != nil {
		t.Fatalf("failed to parse YAML config: %v", err)
	}

	if cfg.Port != 9000 {
		t.Fatalf("expected port 9000, got %d", cfg.Port)
	}
	if cfg.GetListenAddr() != "127.0.0.1:9000" {
		t.Fatalf("expected listen addr 127.0.0.1:9000, got %s", cfg.GetListenAddr())
	}
	if cfg.Timeouts.ReadTimeout() != 3*time.Second {
		t.Fatalf("expected 3s read timeout, got %v", cfg.Timeouts.ReadTimeout())
	}
	if cfg.Timeouts.UpstreamTimeout() != 12*time.Second {
		t.Fatalf("expected 12s upstream timeout, got %v", cfg.Timeouts.UpstreamTimeout())
	}
	if len(cfg.Tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(cfg.Tenants))
	}
	if !cfg.Tenants["sk-yaml-1"].Enabled {
		t.Fatalf("expected sk-yaml-1 to be enabled")
	}
	if cfg.Tenants["sk-yaml-2"].Enabled {
		t.Fatalf("expected sk-yaml-2 to be disabled")
	}
}

func TestLoadConfigFile(t *testing.T) {
	tempDir := t.TempDir()

	// 1. JSON file
	jsonPath := filepath.Join(tempDir, "config.json")
	if err := os.WriteFile(jsonPath, []byte(`{"port": 7777, "upstream_url": "http://mock-upstream:8080"}`), 0644); err != nil {
		t.Fatalf("failed to write temp json config: %v", err)
	}
	cfgJSON, err := LoadConfig(jsonPath)
	if err != nil {
		t.Fatalf("failed to load JSON config file: %v", err)
	}
	if cfgJSON.Port != 7777 {
		t.Fatalf("expected port 7777, got %d", cfgJSON.Port)
	}

	// 2. YAML file
	yamlPath := filepath.Join(tempDir, "config.yaml")
	if err := os.WriteFile(yamlPath, []byte("port: 8888\nupstream_url: \"http://mock-upstream:9000\"\n"), 0644); err != nil {
		t.Fatalf("failed to write temp yaml config: %v", err)
	}
	cfgYAML, err := LoadConfig(yamlPath)
	if err != nil {
		t.Fatalf("failed to load YAML config file: %v", err)
	}
	if cfgYAML.Port != 8888 {
		t.Fatalf("expected port 8888, got %d", cfgYAML.Port)
	}
	if cfgYAML.UpstreamURL != "http://mock-upstream:9000" {
		t.Fatalf("expected upstream URL http://mock-upstream:9000, got %s", cfgYAML.UpstreamURL)
	}
}

func TestAddTenant(t *testing.T) {
	cfg := NewDefaultConfig()
	cfg.AddTenant(TenantConfig{
		APIKey:   "sk-prog-key",
		TenantID: "tenant-prog",
		Name:     "Programmatic Tenant",
		Enabled:  true,
	})

	if len(cfg.Tenants) != 1 {
		t.Fatalf("expected 1 tenant, got %d", len(cfg.Tenants))
	}
	tc, ok := cfg.Tenants["sk-prog-key"]
	if !ok || tc.TenantID != "tenant-prog" {
		t.Fatalf("failed to find added tenant: %+v", tc)
	}
}
