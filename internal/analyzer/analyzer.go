// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package analyzer provides response comparison and confidence scoring
// for BOLA/IDOR detection.
package analyzer

import (
	"encoding/json"
	"math"
	"strings"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

// Analyzer compares HTTP responses to determine if a BOLA vulnerability exists.
type Analyzer struct {
	similarityThreshold float64
	errorPatterns       []string
}

// New creates a new response analyzer.
func New(similarityThreshold float64, errorPatterns []string) *Analyzer {
	return &Analyzer{
		similarityThreshold: similarityThreshold,
		errorPatterns:       errorPatterns,
	}
}

// Result contains the analysis output for a single test pair.
type Result struct {
	BOLA       bool
	Confidence graph.Confidence
	Score      float64
	SizeDelta  float64
	Similarity float64
	Notes      string
}

// Analyze compares an original response with a test response to detect BOLA.
func (a *Analyzer) Analyze(pair *graph.TestPair) *Result {
	original := pair.OriginalRequest
	test := pair.TestRequest

	result := &Result{}

	// Quick reject: if the test got 401/403/404, authorization is working
	if test.StatusCode == 401 || test.StatusCode == 403 || test.StatusCode == 404 {
		result.Notes = "Authorization properly enforced"
		return result
	}

	// Quick reject: if original failed too, nothing to compare
	if original.StatusCode >= 400 {
		result.Notes = "Original request also failed"
		return result
	}

	var score float64
	var notes []string

	// 1. Status code comparison (30 points)
	if test.StatusCode == original.StatusCode {
		score += 30
		notes = append(notes, "Same status code")
	} else if test.StatusCode >= 200 && test.StatusCode < 300 {
		score += 15
		notes = append(notes, "Different but successful status")
	}

	// 2. Response size comparison (20 points)
	sizeDelta := computeSizeDelta(len(original.ResponseBody), len(test.ResponseBody))
	result.SizeDelta = sizeDelta
	if sizeDelta < 0.10 {
		score += 20
		notes = append(notes, "Similar response size")
	} else if sizeDelta < 0.30 {
		score += 10
		notes = append(notes, "Moderately different response size")
	}

	// 3. JSON structure similarity (25 points)
	similarity := ComputeJSONSimilarity(original.ResponseBody, test.ResponseBody)
	result.Similarity = similarity
	if similarity > a.similarityThreshold {
		score += 25
		notes = append(notes, "High structural similarity")
	} else if similarity > 0.60 {
		score += 12
		notes = append(notes, "Moderate structural similarity")
	}

	// 4. Value similarity for matching keys (15 points)
	if similarity > 0.50 {
		valueSim := ComputeValueSimilarity(original.ResponseBody, test.ResponseBody)
		if valueSim > 0.50 {
			score += 15
			notes = append(notes, "Data values present in test response")
		} else if valueSim > 0.20 {
			score += 7
		}
	}

	// 5. Error pattern detection (-30 points / rejection)
	if a.containsErrorPatterns(test.ResponseBody) {
		score -= 30
		notes = append(notes, "Response contains error indicators (200 with error body)")
	} else {
		score += 10
		notes = append(notes, "No error indicators in response")
	}

	// Score to confidence mapping
	result.Score = score
	result.Notes = strings.Join(notes, "; ")

	if score >= 80 {
		result.BOLA = true
		result.Confidence = graph.ConfidenceHigh
	} else if score >= 50 {
		result.BOLA = true
		result.Confidence = graph.ConfidenceMedium
	} else if score >= 30 {
		result.BOLA = true
		result.Confidence = graph.ConfidenceLow
	}
	// score < 30 → not a finding (BOLA stays false)

	return result
}

// containsErrorPatterns checks if a response body contains error-like patterns.
func (a *Analyzer) containsErrorPatterns(body []byte) bool {
	if len(body) == 0 {
		return false
	}

	// Try to parse as JSON and check for error fields
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err == nil {
		return a.checkJSONForErrors(obj)
	}

	// Fall back to string matching
	lower := strings.ToLower(string(body))
	for _, pattern := range a.errorPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}

	return false
}

// checkJSONForErrors checks a JSON object for common error response patterns.
func (a *Analyzer) checkJSONForErrors(obj map[string]interface{}) bool {
	// Common error response patterns:
	// {"error": "..."}, {"message": "...", "status": 401}, {"success": false}
	errorKeys := []string{"error", "err", "errors"}
	for _, key := range errorKeys {
		if v, ok := obj[key]; ok {
			if v != nil && v != "" && v != false {
				return true
			}
		}
	}

	// Check for {"success": false}
	if success, ok := obj["success"]; ok {
		if b, ok := success.(bool); ok && !b {
			return true
		}
	}

	// Check for {"status": "error"} or {"status": "fail"}
	if status, ok := obj["status"]; ok {
		if s, ok := status.(string); ok {
			lower := strings.ToLower(s)
			if lower == "error" || lower == "fail" || lower == "failure" {
				return true
			}
		}
	}

	// Check message field contains error-like content
	if msg, ok := obj["message"]; ok {
		if s, ok := msg.(string); ok {
			lower := strings.ToLower(s)
			for _, pattern := range a.errorPatterns {
				if strings.Contains(lower, pattern) {
					return true
				}
			}
		}
	}

	return false
}

// computeSizeDelta calculates the relative size difference between two responses.
// Returns a value between 0.0 (identical) and 1.0+ (very different).
func computeSizeDelta(origSize, testSize int) float64 {
	if origSize == 0 && testSize == 0 {
		return 0
	}
	if origSize == 0 || testSize == 0 {
		return 1.0
	}
	return math.Abs(float64(origSize)-float64(testSize)) / math.Max(float64(origSize), float64(testSize))
}
