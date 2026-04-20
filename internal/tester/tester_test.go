// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package tester

import (
	"strings"
	"testing"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

func TestBuildCurlCommand(t *testing.T) {
	orig := &graph.CapturedRequest{
		Method: "GET",
		URL:    "https://api.example.com/api/v1/users/123",
	}

	identities := []config.IdentityConfig{
		{Name: "attacker", Role: "user", Headers: map[string]string{"Authorization": "Bearer evil-token"}},
	}
	v, _ := vault.New(identities)

	curl := BuildCurlCommand(orig, "attacker", v)
	if curl == "" {
		t.Fatal("expected non-empty curl command")
	}
	if !strings.Contains(curl, "evil-token") {
		t.Error("curl should contain tester's token")
	}
	if !strings.Contains(curl, "users/123") {
		t.Error("curl should contain the original URL")
	}
}

func TestBuildCurlCommandWithBody(t *testing.T) {
	orig := &graph.CapturedRequest{
		Method: "POST",
		URL:    "https://api.example.com/api/v1/orders",
		Body:   []byte(`{"product_id": 42}`),
	}

	identities := []config.IdentityConfig{
		{Name: "attacker", Role: "user", Headers: map[string]string{"Authorization": "Bearer evil"}},
	}
	v, _ := vault.New(identities)

	curl := BuildCurlCommand(orig, "attacker", v)
	if !strings.Contains(curl, "-d") {
		t.Error("POST curl should contain -d flag")
	}
	if !strings.Contains(curl, "product_id") {
		t.Error("curl should contain the request body")
	}
}

func TestMeetsMinConfidence(t *testing.T) {
	tests := []struct {
		finding  string
		minimum  string
		expected bool
	}{
		{"HIGH", "LOW", true},
		{"HIGH", "MEDIUM", true},
		{"HIGH", "HIGH", true},
		{"MEDIUM", "HIGH", false},
		{"LOW", "HIGH", false},
		{"LOW", "LOW", true},
		{"MEDIUM", "LOW", true},
	}

	for _, tt := range tests {
		got := meetsMinConfidence(tt.finding, tt.minimum)
		if got != tt.expected {
			t.Errorf("meetsMinConfidence(%q, %q) = %v, want %v",
				tt.finding, tt.minimum, got, tt.expected)
		}
	}
}
