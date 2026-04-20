// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package analyzer

import (
	"testing"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
)

func testConfig() *config.Config {
	return &config.Config{
		Analysis: config.AnalysisConfig{
			SimilarityThreshold: 0.85,
			DetectErrorPatterns: []string{"error", "unauthorized", "forbidden", "access denied"},
		},
	}
}

func TestAnalyze_BlockedAccess(t *testing.T) {
	cfg := testConfig()

	result := Analyze(
		&graph.CapturedRequest{StatusCode: 200, ResponseBody: []byte(`{"id": 1}`)},
		&graph.CapturedRequest{StatusCode: 403, ResponseBody: []byte(`{"error": "forbidden"}`)},
		cfg,
	)

	if result != nil {
		t.Error("expected nil (blocked access)")
	}
}

func TestAnalyze_HighConfidence(t *testing.T) {
	cfg := testConfig()
	body := []byte(`{"id": 1, "name": "Alice", "email": "alice@test.com", "role": "user"}`)

	result := Analyze(
		&graph.CapturedRequest{StatusCode: 200, ResponseBody: body},
		&graph.CapturedRequest{StatusCode: 200, ResponseBody: body},
		cfg,
	)

	if result == nil {
		t.Fatal("expected finding for identical responses")
	}
	if result.Confidence != "HIGH" {
		t.Errorf("expected HIGH confidence, got %s (score: %.1f)", result.Confidence, result.Score)
	}
	if result.Score < 80 {
		t.Errorf("score should be >= 80, got %.1f", result.Score)
	}
}

func TestAnalyze_ErrorBody200(t *testing.T) {
	cfg := testConfig()

	result := Analyze(
		&graph.CapturedRequest{StatusCode: 200, ResponseBody: []byte(`{"id": 1, "name": "test"}`)},
		&graph.CapturedRequest{
			StatusCode:   200,
			ResponseBody: []byte(`{"error": "access denied", "message": "You cannot access this resource"}`),
		},
		cfg,
	)

	// Should either be nil (not a finding) or low confidence due to error penalty
	if result != nil && result.Confidence == "HIGH" {
		t.Error("200 with error body should NOT be HIGH confidence")
	}
}

func TestAnalyze_DifferentStructure(t *testing.T) {
	cfg := testConfig()

	result := Analyze(
		&graph.CapturedRequest{StatusCode: 200, ResponseBody: []byte(`{"id": 1, "name": "Alice", "email": "alice@test.com"}`)},
		&graph.CapturedRequest{StatusCode: 200, ResponseBody: []byte(`{"status": "ok", "timestamp": "2025-01-01"}`)},
		cfg,
	)

	// Different JSON structures → should be LOW or nil
	if result != nil && result.Confidence == "HIGH" {
		t.Error("different structures should not be HIGH confidence")
	}
}

func TestComputeKeySimilarity(t *testing.T) {
	body1 := []byte(`{"id": 1, "name": "Alice", "email": "alice@test.com"}`)
	body2 := []byte(`{"id": 2, "name": "Bob", "email": "bob@test.com"}`)

	sim := ComputeKeySimilarity(body1, body2)
	if sim < 0.9 {
		t.Errorf("identical structures should have similarity > 0.9, got %f", sim)
	}
}

func TestComputeKeySimilarity_Different(t *testing.T) {
	body1 := []byte(`{"id": 1, "name": "Alice"}`)
	body2 := []byte(`{"error": "not found", "message": "Resource does not exist"}`)

	sim := ComputeKeySimilarity(body1, body2)
	if sim > 0.5 {
		t.Errorf("different structures should have low similarity, got %f", sim)
	}
}

func TestComputeValueSimilarity(t *testing.T) {
	body1 := []byte(`{"id": 1, "name": "Alice", "role": "user"}`)
	body2 := []byte(`{"id": 1, "name": "Alice", "role": "user"}`)

	sim := ComputeValueSimilarity(body1, body2)
	if sim != 1.0 {
		t.Errorf("identical bodies should have value similarity 1.0, got %f", sim)
	}
}

func TestFlattenJSON(t *testing.T) {
	body := []byte(`{"user": {"name": "Alice", "id": 42}, "status": "active"}`)
	flat := FlattenJSON(body)

	if flat["user.name"] != "Alice" {
		t.Errorf("user.name: got %q", flat["user.name"])
	}
	if flat["user.id"] != "42" {
		t.Errorf("user.id: got %q", flat["user.id"])
	}
	if flat["status"] != "active" {
		t.Errorf("status: got %q", flat["status"])
	}
}

func TestDetectErrorIndicators(t *testing.T) {
	patterns := []string{"error", "unauthorized", "forbidden"}

	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"json error field", `{"error": "something failed"}`, true},
		{"success false", `{"success": false, "message": "no access"}`, true},
		{"status error", `{"status": "error"}`, true},
		{"clean response", `{"id": 1, "name": "Alice"}`, false},
		{"empty body", ``, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectErrorIndicators([]byte(tt.body), patterns)
			if got != tt.expected {
				t.Errorf("DetectErrorIndicators(%q) = %v, want %v", tt.body, got, tt.expected)
			}
		})
	}
}

func TestComputeSizeDelta(t *testing.T) {
	tests := []struct {
		a, b     int
		expected float64
	}{
		{100, 100, 0.0},
		{100, 90, 0.1},
		{0, 0, 0.0},
		{100, 0, 1.0},
	}

	for _, tt := range tests {
		got := computeSizeDelta(tt.a, tt.b)
		delta := got - tt.expected
		if delta < 0 {
			delta = -delta
		}
		if delta > 0.01 {
			t.Errorf("computeSizeDelta(%d, %d) = %f, want %f", tt.a, tt.b, got, tt.expected)
		}
	}
}
