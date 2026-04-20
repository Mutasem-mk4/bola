// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bola.yaml")

	content := `
target:
  base_url: "https://api.example.com"
  scope:
    include: ["/api/*"]
identities:
  - name: "admin"
    role: "admin"
    headers:
      Authorization: "Bearer token-admin"
  - name: "user"
    role: "user"
    headers:
      Authorization: "Bearer token-user"
testing:
  workers: 3
  rate_limit: 5
  timeout: "10s"
analysis:
  similarity_threshold: 0.80
  min_confidence: "MEDIUM"
output:
  terminal: true
  database: "test.db"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	if cfg.Target.BaseURL != "https://api.example.com" {
		t.Errorf("base_url: got %q", cfg.Target.BaseURL)
	}
	if cfg.Testing.Workers != 3 {
		t.Errorf("workers: got %d", cfg.Testing.Workers)
	}
	if cfg.Analysis.MinConfidence != "MEDIUM" {
		t.Errorf("min_confidence: got %q", cfg.Analysis.MinConfidence)
	}
	if len(cfg.Identities) != 2 {
		t.Errorf("identities: got %d", len(cfg.Identities))
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/bola.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestDefaultsApplied(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bola.yaml")

	content := `
target:
  base_url: "https://api.example.com"
identities:
  - name: "a"
    role: "admin"
    headers:
      Authorization: "Bearer x"
  - name: "b"
    role: "user"
    headers:
      Authorization: "Bearer y"
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	if cfg.Proxy.Listen != "127.0.0.1:8080" {
		t.Errorf("default proxy listen: got %q", cfg.Proxy.Listen)
	}
	if cfg.Testing.Workers != 5 {
		t.Errorf("default workers: got %d", cfg.Testing.Workers)
	}
	if cfg.Testing.RateLimit != 10 {
		t.Errorf("default rate_limit: got %d", cfg.Testing.RateLimit)
	}
	if cfg.Analysis.SimilarityThreshold != 0.85 {
		t.Errorf("default similarity_threshold: got %f", cfg.Analysis.SimilarityThreshold)
	}
	if len(cfg.Analysis.DetectErrorPatterns) == 0 {
		t.Error("expected default error patterns")
	}
}

func TestValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			name:    "missing base_url",
			content: `identities: [{name: a, role: admin, headers: {Authorization: "Bearer x"}}, {name: b, role: user, headers: {Authorization: "Bearer y"}}]`,
		},
		{
			name:    "one identity",
			content: `target: {base_url: "https://x.com"}\nidentities: [{name: a, role: admin, headers: {Authorization: "Bearer x"}}]`,
		},
		{
			name:    "invalid base_url",
			content: `target: {base_url: "ftp://x.com"}\nidentities: [{name: a, role: admin, headers: {Authorization: "Bearer x"}}, {name: b, role: user, headers: {Authorization: "Bearer y"}}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "bola.yaml")
			if err := os.WriteFile(path, []byte(tt.content), 0644); err != nil {
				t.Fatalf("writing config: %v", err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestInvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bola.yaml")
	if err := os.WriteFile(path, []byte(":::invalid:::"), 0644); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestExampleConfig(t *testing.T) {
	example := ExampleConfig()
	if len(example) < 100 {
		t.Error("example config too short")
	}
}
