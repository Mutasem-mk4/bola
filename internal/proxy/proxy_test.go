// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

func TestClassifyID(t *testing.T) {
	tests := []struct {
		input    string
		expected IDType
	}{
		{"550e8400-e29b-41d4-a716-446655440000", IDTypeUUID},
		{"507f1f77bcf86cd799439011", IDTypeMongoID},
		{"123", IDTypeInteger},
		{"42", IDTypeInteger},
		{"99999999", IDTypeInteger},
		{"abcdef1234567890abcdef1234567890", IDTypeHash},
		{"api", ""},
		{"users", ""},
		{"v1", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ClassifyID(tt.input)
			if got != tt.expected {
				t.Errorf("ClassifyID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

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
			got := NormalizePath(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestExtractFromPath(t *testing.T) {
	u, _ := url.Parse("https://api.test.com/api/users/123/orders/456")
	ids := ExtractFromURL(u)

	if len(ids) < 2 {
		t.Fatalf("expected at least 2 IDs, got %d", len(ids))
	}

	found123, found456 := false, false
	for _, id := range ids {
		if id.Value == "123" {
			found123 = true
			if id.Type != IDTypeInteger {
				t.Errorf("123 type: got %q", id.Type)
			}
			if id.Location != "path" {
				t.Errorf("123 location: got %q", id.Location)
			}
		}
		if id.Value == "456" {
			found456 = true
		}
	}
	if !found123 {
		t.Error("missing ID 123")
	}
	if !found456 {
		t.Error("missing ID 456")
	}
}

func TestExtractFromQuery(t *testing.T) {
	u, _ := url.Parse("https://api.test.com/api/search?user_id=789&q=test")
	ids := ExtractFromURL(u)

	found := false
	for _, id := range ids {
		if id.Value == "789" && id.Key == "user_id" {
			found = true
			break
		}
	}
	if !found {
		t.Error("missing query param user_id=789")
	}
}

func TestExtractFromJSONBody(t *testing.T) {
	body := []byte(`{"id": 42, "user_id": "550e8400-e29b-41d4-a716-446655440000", "name": "test"}`)
	ids := ExtractFromBody(body, "application/json")

	if len(ids) < 2 {
		t.Fatalf("expected at least 2 IDs, got %d", len(ids))
	}
}

func TestExtractFromHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Location", "/api/v1/users/550e8400-e29b-41d4-a716-446655440000")
	headers.Set("X-Request-Id", "7c9e6679-7425-40de-944b-e07fc1f90ae7")

	ids := ExtractFromHeaders(headers)
	if len(ids) < 2 {
		t.Fatalf("expected at least 2 header IDs, got %d", len(ids))
	}
}

func TestExtractAll(t *testing.T) {
	u, _ := url.Parse("https://api.test.com/api/users/123")
	body := []byte(`{"id": 123, "order_id": 456}`)
	headers := http.Header{}
	headers.Set("Content-Type", "application/json")

	ids := ExtractAll(u, body, headers)
	if len(ids) < 2 {
		t.Fatalf("expected at least 2 total IDs, got %d", len(ids))
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern  string
		path     string
		expected bool
	}{
		{"/api/v1/*", "/api/v1/users", true},
		{"/api/v1/*", "/api/v1/users/123", true},
		{"/api/v1/*", "/api/v2/users", false},
		{"/api/v1/health", "/api/v1/health", true},
		{"/api/v1/health", "/api/v1/users", false},
	}

	for _, tt := range tests {
		name := tt.pattern + "_" + tt.path
		t.Run(name, func(t *testing.T) {
			if got := MatchGlob(tt.pattern, tt.path); got != tt.expected {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.expected)
			}
		})
	}
}

func TestInScope(t *testing.T) {
	include := []string{"/api/*"}
	exclude := []string{"/api/health"}

	if !InScope("/api/users/1", include, exclude) {
		t.Error("should be in scope")
	}
	if InScope("/api/health", include, exclude) {
		t.Error("should be excluded")
	}
	if InScope("/other/path", include, exclude) {
		t.Error("should not be in scope")
	}
}
