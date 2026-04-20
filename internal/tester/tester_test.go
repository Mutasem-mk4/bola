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
		Body:   nil,
	}

	identities := []config.IdentityConfig{
		{
			Name:    "attacker",
			Role:    "user",
			Headers: map[string]string{"Authorization": "Bearer evil-token"},
		},
	}
	v, _ := vault.New(identities)

	curl := buildCurlCommand(orig, "attacker", v)

	if curl == "" {
		t.Error("expected non-empty curl command")
	}

	if !strings.Contains(curl, "evil-token") {
		t.Error("curl command should contain the tester's token")
	}

	if !strings.Contains(curl, "users/123") {
		t.Error("curl command should contain the original URL")
	}
}
