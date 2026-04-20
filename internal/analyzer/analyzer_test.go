// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package analyzer

import (
	"testing"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

func TestAnalyze_BlockedAccess(t *testing.T) {
	a := New(0.85, []string{"error", "unauthorized"})

	pair := &graph.TestPair{
		OriginalRequest: &graph.CapturedRequest{
			StatusCode:   200,
			ResponseBody: []byte(`{"id": 1, "name": "test"}`),
		},
		TestRequest: &graph.CapturedRequest{
			StatusCode:   403,
			ResponseBody: []byte(`{"error": "forbidden"}`),
		},
	}

	result := a.Analyze(pair)
	if result.BOLA {
		t.Error("expected no BOLA for 403 response")
	}
}

func TestAnalyze_HighConfidence(t *testing.T) {
	a := New(0.85, []string{"error", "unauthorized"})

	body := []byte(`{"id": 1, "name": "test", "email": "user@test.com", "role": "user"}`)

	pair := &graph.TestPair{
		OriginalRequest: &graph.CapturedRequest{
			StatusCode:   200,
			ResponseBody: body,
		},
		TestRequest: &graph.CapturedRequest{
			StatusCode:   200,
			ResponseBody: body, // identical = definitely BOLA
		},
	}

	result := a.Analyze(pair)
	if !result.BOLA {
		t.Error("expected BOLA for identical responses")
	}
	if result.Confidence != graph.ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s (score: %.1f)", result.Confidence, result.Score)
	}
}

func TestAnalyze_ErrorBody200(t *testing.T) {
	a := New(0.85, []string{"error", "unauthorized", "access denied"})

	pair := &graph.TestPair{
		OriginalRequest: &graph.CapturedRequest{
			StatusCode:   200,
			ResponseBody: []byte(`{"id": 1, "name": "test"}`),
		},
		TestRequest: &graph.CapturedRequest{
			StatusCode:   200,
			ResponseBody: []byte(`{"error": "access denied", "message": "You cannot access this resource"}`),
		},
	}

	result := a.Analyze(pair)
	if result.BOLA && result.Confidence == graph.ConfidenceHigh {
		t.Error("200 with error body should not be HIGH confidence BOLA")
	}
}

func TestComputeJSONSimilarity(t *testing.T) {
	body1 := []byte(`{"id": 1, "name": "Alice", "email": "alice@test.com"}`)
	body2 := []byte(`{"id": 2, "name": "Bob", "email": "bob@test.com"}`)

	sim := ComputeJSONSimilarity(body1, body2)
	if sim < 0.9 {
		t.Errorf("expected similarity > 0.9 for identical structures, got %f", sim)
	}
}

func TestComputeJSONSimilarity_Different(t *testing.T) {
	body1 := []byte(`{"id": 1, "name": "Alice"}`)
	body2 := []byte(`{"error": "not found", "message": "Resource does not exist"}`)

	sim := ComputeJSONSimilarity(body1, body2)
	if sim > 0.5 {
		t.Errorf("expected low similarity for different structures, got %f", sim)
	}
}

func TestComputeValueSimilarity(t *testing.T) {
	body1 := []byte(`{"id": 1, "name": "Alice", "role": "user"}`)
	body2 := []byte(`{"id": 1, "name": "Alice", "role": "user"}`)

	sim := ComputeValueSimilarity(body1, body2)
	if sim != 1.0 {
		t.Errorf("expected value similarity 1.0 for identical bodies, got %f", sim)
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
