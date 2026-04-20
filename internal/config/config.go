// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package config provides YAML configuration loading and validation for bola.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration for bola.
type Config struct {
	Target     TargetConfig     `yaml:"target"`
	Proxy      ProxyConfig      `yaml:"proxy"`
	Identities []IdentityConfig `yaml:"identities"`
	Testing    TestingConfig    `yaml:"testing"`
	Analysis   AnalysisConfig   `yaml:"analysis"`
	Output     OutputConfig     `yaml:"output"`
}

// TargetConfig defines the target application scope.
type TargetConfig struct {
	BaseURL string      `yaml:"base_url"`
	Scope   ScopeConfig `yaml:"scope"`
}

// ScopeConfig defines include/exclude path patterns.
type ScopeConfig struct {
	Include []string `yaml:"include"`
	Exclude []string `yaml:"exclude"`
}

// ProxyConfig defines the MITM proxy settings.
type ProxyConfig struct {
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
}

// TLSConfig holds paths to the CA certificate and key for HTTPS interception.
type TLSConfig struct {
	CACert string `yaml:"ca_cert"`
	CAKey  string `yaml:"ca_key"`
}

// IdentityConfig defines a single user session/identity.
type IdentityConfig struct {
	Name         string            `yaml:"name"`
	Role         string            `yaml:"role"`
	Headers      map[string]string `yaml:"headers"`
	Cookies      []CookieConfig    `yaml:"cookies"`
	RefreshToken string            `yaml:"refresh_token"`
	RefreshURL   string            `yaml:"refresh_url"`
}

// CookieConfig represents a single browser cookie.
type CookieConfig struct {
	Name   string `yaml:"name"`
	Value  string `yaml:"value"`
	Domain string `yaml:"domain"`
	Path   string `yaml:"path"`
}

// TestingConfig controls the cross-identity testing engine.
type TestingConfig struct {
	Workers   int           `yaml:"workers"`
	RateLimit int           `yaml:"rate_limit"`
	Timeout   time.Duration `yaml:"timeout"`
	Retry     int           `yaml:"retry"`
	Jitter    bool          `yaml:"jitter"`
}

// AnalysisConfig controls the response comparison engine.
type AnalysisConfig struct {
	SimilarityThreshold float64  `yaml:"similarity_threshold"`
	MinConfidence       string   `yaml:"min_confidence"`
	DetectErrorPatterns []string `yaml:"detect_error_patterns"`
}

// OutputConfig controls report generation.
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
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return cfg, nil
}

// applyDefaults sets sane defaults for unset fields.
func (c *Config) applyDefaults() {
	if c.Proxy.Listen == "" {
		c.Proxy.Listen = "127.0.0.1:8080"
	}
	if c.Testing.Workers == 0 {
		c.Testing.Workers = 5
	}
	if c.Testing.RateLimit == 0 {
		c.Testing.RateLimit = 10
	}
	if c.Testing.Timeout == 0 {
		c.Testing.Timeout = 30 * time.Second
	}
	if c.Testing.Retry == 0 {
		c.Testing.Retry = 2
	}
	if c.Analysis.SimilarityThreshold == 0 {
		c.Analysis.SimilarityThreshold = 0.85
	}
	if c.Analysis.MinConfidence == "" {
		c.Analysis.MinConfidence = "LOW"
	}
	if len(c.Analysis.DetectErrorPatterns) == 0 {
		c.Analysis.DetectErrorPatterns = []string{
			"error", "message", "unauthorized", "forbidden",
			"not found", "access denied", "invalid",
		}
	}
	if c.Output.Database == "" {
		c.Output.Database = "bola.db"
	}
	c.Output.Terminal = true
}

// Validate checks that the configuration is semantically valid.
func (c *Config) Validate() error {
	if len(c.Identities) < 2 {
		return fmt.Errorf("at least 2 identities are required for cross-identity testing, got %d", len(c.Identities))
	}

	names := make(map[string]bool)
	for _, id := range c.Identities {
		if id.Name == "" {
			return fmt.Errorf("identity name cannot be empty")
		}
		if names[id.Name] {
			return fmt.Errorf("duplicate identity name: %q", id.Name)
		}
		names[id.Name] = true

		if id.Role == "" {
			return fmt.Errorf("identity %q: role cannot be empty", id.Name)
		}

		hasAuth := len(id.Headers) > 0 || len(id.Cookies) > 0
		if !hasAuth && id.Role != "guest" {
			return fmt.Errorf("identity %q: non-guest identity must have headers or cookies", id.Name)
		}
	}

	switch c.Analysis.MinConfidence {
	case "HIGH", "MEDIUM", "LOW":
		// valid
	default:
		return fmt.Errorf("invalid min_confidence: %q (must be HIGH, MEDIUM, or LOW)", c.Analysis.MinConfidence)
	}

	if c.Analysis.SimilarityThreshold < 0 || c.Analysis.SimilarityThreshold > 1 {
		return fmt.Errorf("similarity_threshold must be between 0 and 1, got %f", c.Analysis.SimilarityThreshold)
	}

	return nil
}

// ExampleConfig returns a commented example YAML configuration string.
func ExampleConfig() string {
	return `# bola.yaml — Configuration for Bola BOLA/IDOR Scanner
# Docs: https://github.com/Mutasem-mk4/bola

target:
  base_url: "https://api.target.com"
  scope:
    include:
      - "/api/v1/*"
      - "/api/v2/*"
    exclude:
      - "/api/v1/health"
      - "/api/v1/public/*"

proxy:
  listen: "127.0.0.1:8080"
  tls:
    ca_cert: "~/.bola/ca.pem"
    ca_key: "~/.bola/ca-key.pem"

identities:
  - name: "admin"
    role: "admin"
    headers:
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."

  - name: "user1"
    role: "user"
    headers:
      Authorization: "Bearer eyJhbGciOiJIUzI1NiIs..."

  - name: "user2"
    role: "user"
    cookies:
      - name: "session"
        value: "abc123def456"
        domain: "api.target.com"

  - name: "guest"
    role: "guest"
    # No auth — tests unauthenticated access

testing:
  workers: 5          # concurrent test workers
  rate_limit: 10      # max requests per second
  timeout: 30s        # per-request timeout
  retry: 2            # retry failed requests
  jitter: true        # add random delay between requests

analysis:
  similarity_threshold: 0.85   # JSON structure similarity threshold
  min_confidence: "LOW"        # report findings at LOW, MEDIUM, HIGH
  detect_error_patterns:
    - "error"
    - "message"
    - "unauthorized"
    - "forbidden"
    - "not found"
    - "access denied"

output:
  terminal: true
  json: "bola-report.json"
  markdown: "bola-report.md"
  database: "bola.db"
`
}
