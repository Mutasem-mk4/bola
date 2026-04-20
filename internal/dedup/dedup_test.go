// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package dedup

import (
	"testing"

	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/proxy"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"/api/users/123/orders/456", "/api/users/{id}/orders/{id}"},
		{"/api/users/550e8400-e29b-41d4-a716-446655440000/profile", "/api/users/{uuid}/profile"},
		{"/v2/items/507f1f77bcf86cd799439011", "/v2/items/{mongoid}"},
		{"/api/v1/health", "/api/v1/health"},
		{"/", "/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := proxy.NormalizePath(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestNormalizeRole(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"admin", "admin"},
		{"admin_super", "admin"},
		{"superadmin", "admin"},
		{"guest", "guest"},
		{"anonymous", "guest"},
		{"user1", "user"},
		{"bob", "user"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizeRole(tt.input); got != tt.expected {
				t.Errorf("normalizeRole(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestConfidenceRank(t *testing.T) {
	if confidenceRank(graph.ConfidenceHigh) <= confidenceRank(graph.ConfidenceMedium) {
		t.Error("HIGH should outrank MEDIUM")
	}
	if confidenceRank(graph.ConfidenceMedium) <= confidenceRank(graph.ConfidenceLow) {
		t.Error("MEDIUM should outrank LOW")
	}
}
