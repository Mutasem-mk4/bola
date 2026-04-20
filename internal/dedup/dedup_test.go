// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package dedup

import (
	"testing"
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
		{"/api/v1/users/{id}", "/api/v1/users/{id}"},
		{"/", "/"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizePath(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestIsLikelyHash(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"abcdef1234567890abcdef", true},
		{"short", false},
		{"has-special-chars-!", false},
		{"abcdefghijklmnop", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isLikelyHash(tt.input)
			if got != tt.expected {
				t.Errorf("isLikelyHash(%q) = %v, want %v", tt.input, got, tt.expected)
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
		{"user1", "user"},
		{"admin_super", "admin"},
		{"guest", "guest"},
		{"random", "random"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeRole(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeRole(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestConfidenceRank(t *testing.T) {
	if confidenceRank("HIGH") <= confidenceRank("MEDIUM") {
		t.Error("HIGH should rank above MEDIUM")
	}
	if confidenceRank("MEDIUM") <= confidenceRank("LOW") {
		t.Error("MEDIUM should rank above LOW")
	}
}
