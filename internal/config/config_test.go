// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	cfg := ExampleConfig()
	tmp := filepath.Join(t.TempDir(), "bola.yaml")
	if err := os.WriteFile(tmp, []byte(cfg), 0644); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}

	c, err := Load(tmp)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}

	if c.Target.BaseURL != "https://api.target.com" {
		t.Errorf("expected base_url https://api.target.com, got %s", c.Target.BaseURL)
	}

	if len(c.Identities) != 4 {
		t.Errorf("expected 4 identities, got %d", len(c.Identities))
	}

	if c.Testing.Workers != 5 {
		t.Errorf("expected 5 workers, got %d", c.Testing.Workers)
	}

	if c.Analysis.SimilarityThreshold != 0.85 {
		t.Errorf("expected similarity 0.85, got %f", c.Analysis.SimilarityThreshold)
	}
}

func TestValidateMinIdentities(t *testing.T) {
	c := &Config{
		Identities: []IdentityConfig{
			{Name: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer x"}},
		},
		Analysis: AnalysisConfig{MinConfidence: "HIGH", SimilarityThreshold: 0.85},
	}

	if err := c.Validate(); err == nil {
		t.Error("expected validation error for single identity")
	}
}

func TestValidateDuplicateNames(t *testing.T) {
	c := &Config{
		Identities: []IdentityConfig{
			{Name: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer x"}},
			{Name: "admin", Role: "user", Headers: map[string]string{"Authorization": "Bearer y"}},
		},
		Analysis: AnalysisConfig{MinConfidence: "HIGH", SimilarityThreshold: 0.85},
	}

	if err := c.Validate(); err == nil {
		t.Error("expected validation error for duplicate identity names")
	}
}

func TestValidateGuestNoAuth(t *testing.T) {
	c := &Config{
		Identities: []IdentityConfig{
			{Name: "admin", Role: "admin", Headers: map[string]string{"Authorization": "Bearer x"}},
			{Name: "guest", Role: "guest"},
		},
		Analysis: AnalysisConfig{MinConfidence: "LOW", SimilarityThreshold: 0.85},
	}

	if err := c.Validate(); err != nil {
		t.Errorf("guest without auth should be valid: %v", err)
	}
}

func TestApplyDefaults(t *testing.T) {
	c := &Config{}
	c.applyDefaults()

	if c.Proxy.Listen != "127.0.0.1:8080" {
		t.Errorf("expected default listen 127.0.0.1:8080, got %s", c.Proxy.Listen)
	}
	if c.Testing.Workers != 5 {
		t.Errorf("expected default workers 5, got %d", c.Testing.Workers)
	}
	if c.Output.Database != "bola.db" {
		t.Errorf("expected default database bola.db, got %s", c.Output.Database)
	}
}
