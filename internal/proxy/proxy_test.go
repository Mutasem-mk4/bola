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
		expected string
	}{
		{"550e8400-e29b-41d4-a716-446655440000", "uuid"},
		{"507f1f77bcf86cd799439011", "mongoid"},
		{"123", "integer"},
		{"42", "integer"},
		{"99999999", "integer"},
		{"abcdef1234567890abcdef", "hash"},
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
	results := ExtractFromPath("/api/users/123/orders/456")

	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	if results[0].Value != "123" || results[0].Type != "integer" || results[0].Key != "users" {
		t.Errorf("first result: got value=%q type=%q key=%q", results[0].Value, results[0].Type, results[0].Key)
	}

	if results[1].Value != "456" || results[1].Type != "integer" || results[1].Key != "orders" {
		t.Errorf("second result: got value=%q type=%q key=%q", results[1].Value, results[1].Type, results[1].Key)
	}
}

func TestExtractFromQuery(t *testing.T) {
	params := url.Values{
		"user_id": []string{"42"},
		"token":   []string{"abc"},
		"page":    []string{"1"},
	}

	results := ExtractFromQuery(params)

	found := false
	for _, r := range results {
		if r.Key == "user_id" && r.Value == "42" && r.Type == "integer" {
			found = true
		}
	}
	if !found {
		t.Error("expected to find user_id=42 as integer")
	}
}

func TestExtractFromJSONBody(t *testing.T) {
	body := []byte(`{
		"id": 42,
		"user_id": "550e8400-e29b-41d4-a716-446655440000",
		"name": "test",
		"nested": {
			"project_id": 99
		},
		"items": [
			{"id": 1, "title": "first"},
			{"id": 2, "title": "second"}
		]
	}`)

	results := ExtractFromJSONBody(body)

	if len(results) == 0 {
		t.Fatal("expected results from JSON body extraction")
	}

	// Check that id=42 was extracted
	found42 := false
	foundUUID := false
	foundNested := false
	for _, r := range results {
		if r.Key == "id" && r.Value == "42" {
			found42 = true
		}
		if r.Key == "user_id" && r.Type == "uuid" {
			foundUUID = true
		}
		if r.Key == "nested.project_id" && r.Value == "99" {
			foundNested = true
		}
	}

	if !found42 {
		t.Error("expected to find id=42")
	}
	if !foundUUID {
		t.Error("expected to find UUID user_id")
	}
	if !foundNested {
		t.Error("expected to find nested.project_id=99")
	}
}

func TestExtractFromHeaders(t *testing.T) {
	headers := http.Header{
		"Location":     []string{"/api/resources/550e8400-e29b-41d4-a716-446655440000"},
		"X-Request-Id": []string{"550e8400-e29b-41d4-a716-446655440001"},
	}

	results := ExtractFromHeaders(headers)

	if len(results) < 1 {
		t.Fatalf("expected at least 1 result, got %d", len(results))
	}
}

func TestExtractAll(t *testing.T) {
	u, _ := url.Parse("https://api.example.com/api/users/123?include=orders")
	body := []byte(`{"id": 42, "email": "test@test.com"}`)
	headers := http.Header{}

	results := ExtractAll(u, body, headers)
	if len(results) < 2 { // at least path ID and body ID
		t.Errorf("expected at least 2 results, got %d", len(results))
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern string
		path    string
		want    bool
	}{
		{"/api/v1/*", "/api/v1/users", true},
		{"/api/v1/*", "/api/v1/users/123", true},
		{"/api/v1/*", "/api/v2/users", false},
		{"/api/v1/health", "/api/v1/health", true},
		{"/api/v1/health", "/api/v1/users", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.path, func(t *testing.T) {
			got := matchGlob(tt.pattern, tt.path)
			if got != tt.want {
				t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.path, got, tt.want)
			}
		})
	}
}
