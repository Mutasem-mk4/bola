// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package config provides YAML configuration loading, validation, and defaults
// for the bola BOLA/IDOR detection engine.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration structure for bola.
type Config struct {
	Target     TargetConfig     `yaml:"target"`
	Proxy      ProxyConfig      `yaml:"proxy"`
	Identities []IdentityConfig `yaml:"identities"`
	Testing    TestingConfig    `yaml:"testing"`
	Analysis   AnalysisConfig   `yaml:"analysis"`
	Output     OutputConfig     `yaml:"output"`
}

// TargetConfig defines the target application.
type TargetConfig struct {
	BaseURL string      `yaml:"base_url"`
	Scope   ScopeConfig `yaml:"scope"`
}

// ScopeConfig defines URL scope filtering.
type ScopeConfig struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// ProxyConfig defines the MITM proxy settings.
type ProxyConfig struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
}

// TLSConfig defines TLS certificate paths for HTTPS interception.
type TLSConfig struct {
	CACert string `yaml:"ca_cert"`
	CAKey  string `yaml:"ca_key"`
}

// IdentityConfig defines a single user identity/session.
type IdentityConfig struct {
	Name         string            `yaml:"name"`
	Role         string            `yaml:"role"`
	Headers      map[string]string `yaml:"headers"`
	Cookies      []CookieConfig    `yaml:"cookies"`
	RefreshToken string            `yaml:"refresh_token"`
	RefreshURL   string            `yaml:"refresh_url"`
}

// CookieConfig defines a single HTTP cookie.
type CookieConfig struct {
	Name   string `yaml:"name"`
	Value  string `yaml:"value"`
	Domain string `yaml:"domain"`
	Path   string `yaml:"path"`
}

// TestingConfig defines scan parameters.
type TestingConfig struct {
	Workers   int           `yaml:"workers"`
	RateLimit int           `yaml:"rate_limit"`
	Timeout   time.Duration `yaml:"timeout"`
	Retry     int           `yaml:"retry"`
	Jitter    bool          `yaml:"jitter"`
}

// AnalysisConfig defines response analysis parameters.
type AnalysisConfig struct {
	SimilarityThreshold  float64  `yaml:"similarity_threshold"`
	MinConfidence        string   `yaml:"min_confidence"`
	DetectErrorPatterns  []string `yaml:"detect_error_patterns"`
}

// OutputConfig defines report output settings.
type OutputConfig struct {
	Terminal bool   `yaml:"terminal"`
	JSON     string `yaml:"json"`
	Markdown string `yaml:"markdown"`
	Database string `yaml:"database"`
}

// Load reads and parses a YAML configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %q: %w", path, err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: parsing %q: %w", path, err)
	}

	applyDefaults(cfg)

	if err := validate(cfg); err != nil {
		return nil, fmt.Errorf("config: validation: %w", err)
	}

	// Expand ~ in paths
	cfg.Proxy.TLS.CACert = expandPath(cfg.Proxy.TLS.CACert)
	cfg.Proxy.TLS.CAKey = expandPath(cfg.Proxy.TLS.CAKey)
	cfg.Output.Database = expandPath(cfg.Output.Database)

	return cfg, nil
}

// applyDefaults fills in zero-value fields with sensible defaults.
func applyDefaults(cfg *Config) {
	if cfg.Proxy.Listen == "" {
		cfg.Proxy.Listen = "127.0.0.1:8080"
	}
	if cfg.Proxy.TLS.CACert == "" {
		cfg.Proxy.TLS.CACert = "~/.bola/ca.pem"
	}
	if cfg.Proxy.TLS.CAKey == "" {
		cfg.Proxy.TLS.CAKey = "~/.bola/ca-key.pem"
	}
	if cfg.Testing.Workers == 0 {
		cfg.Testing.Workers = 5
	}
	if cfg.Testing.RateLimit == 0 {
		cfg.Testing.RateLimit = 10
	}
	if cfg.Testing.Timeout == 0 {
		cfg.Testing.Timeout = 30 * time.Second
	}
	if cfg.Testing.Retry == 0 {
		cfg.Testing.Retry = 2
	}
	if cfg.Analysis.SimilarityThreshold == 0 {
		cfg.Analysis.SimilarityThreshold = 0.85
	}
	if cfg.Analysis.MinConfidence == "" {
		cfg.Analysis.MinConfidence = "LOW"
	}
	if len(cfg.Analysis.DetectErrorPatterns) == 0 {
		cfg.Analysis.DetectErrorPatterns = []string{
			"error", "unauthorized", "forbidden", "not found",
			"access denied", "permission denied", "invalid token",
		}
	}
	if cfg.Output.Database == "" {
		cfg.Output.Database = "bola.db"
	}
	if !cfg.Output.Terminal && cfg.Output.JSON == "" && cfg.Output.Markdown == "" {
		cfg.Output.Terminal = true
	}
}

// validate checks that required fields are present and valid.
func validate(cfg *Config) error {
	if cfg.Target.BaseURL == "" {
		return fmt.Errorf("target.base_url is required")
	}
	if !strings.HasPrefix(cfg.Target.BaseURL, "http://") && !strings.HasPrefix(cfg.Target.BaseURL, "https://") {
		return fmt.Errorf("target.base_url must start with http:// or https://")
	}
	if len(cfg.Identities) < 2 {
		return fmt.Errorf("at least 2 identities are required for cross-identity testing")
	}
	for i, id := range cfg.Identities {
		if id.Name == "" {
			return fmt.Errorf("identities[%d].name is required", i)
		}
		if id.Role == "" {
			return fmt.Errorf("identities[%d].role is required (admin/user/guest/custom)", i)
		}
		if len(id.Headers) == 0 && len(id.Cookies) == 0 {
			return fmt.Errorf("identities[%d] (%s): must have headers or cookies", i, id.Name)
		}
	}
	switch strings.ToUpper(cfg.Analysis.MinConfidence) {
	case "HIGH", "MEDIUM", "LOW":
		cfg.Analysis.MinConfidence = strings.ToUpper(cfg.Analysis.MinConfidence)
	default:
		return fmt.Errorf("analysis.min_confidence must be HIGH, MEDIUM, or LOW")
	}
	if cfg.Testing.Workers < 1 || cfg.Testing.Workers > 50 {
		return fmt.Errorf("testing.workers must be between 1 and 50")
	}
	if cfg.Testing.RateLimit < 1 || cfg.Testing.RateLimit > 100 {
		return fmt.Errorf("testing.rate_limit must be between 1 and 100")
	}
	return nil
}

// expandPath expands ~ to the user's home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

// ExampleConfig returns a fully-commented example YAML configuration.
func ExampleConfig() string {
	return `# bola — BOLA/IDOR Detection Engine Configuration
# Documentation: https://github.com/Mutasem-mk4/bola

target:
  base_url: "https://api.target.com"
  scope:
    include:
      - "/api/v1/*"
      - "/api/v2/*"
    exclude:
      - "/api/v1/health"
      - "/api/v1/docs"

proxy:
  listen: "127.0.0.1:8080"
  tls:
    ca_cert: "~/.bola/ca.pem"    # auto-generated on first run
    ca_key: "~/.bola/ca-key.pem"

identities:
  - name: "admin"
    role: "admin"
    headers:
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."
    refresh_token: "def502..."   # optional — for auto-refresh
    refresh_url: "https://api.target.com/auth/refresh"

  - name: "user1"
    role: "user"
    headers:
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."

  - name: "guest"
    role: "guest"
    cookies:
      - name: "session"
        value: "abc123def456"
        domain: "api.target.com"

testing:
  workers: 5          # concurrent test workers
  rate_limit: 10      # max requests per second
  timeout: "30s"      # per-request timeout
  retry: 2            # retry count on failure
  jitter: true        # add random 0-100ms delay

analysis:
  similarity_threshold: 0.85    # JSON key overlap threshold
  min_confidence: "LOW"         # report findings at this level and above
  detect_error_patterns:        # strings indicating error (not real data)
    - "error"
    - "unauthorized"
    - "forbidden"
    - "not found"
    - "access denied"

output:
  terminal: true                # colored terminal output
  json: "bola-report.json"     # JSON export (empty to skip)
  markdown: "bola-report.md"   # Markdown export (empty to skip)
  database: "bola.db"          # SQLite database path
`
}
