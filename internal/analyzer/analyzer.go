// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package analyzer provides response comparison and confidence scoring
// for BOLA/IDOR detection.
package analyzer

import (
	"encoding/json"
	"log/slog"
	"math"
	"strings"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
)

// ScoredFinding contains the analysis result for a single test pair.
type ScoredFinding struct {
	Score         float64
	Confidence    string
	KeySimilarity float64
	ValSimilarity float64
	SizeDelta     float64
	ErrorFound    bool
	Notes         string
}

// Analyze compares an original (owner) response with a test (tester) response
// to determine if a BOLA vulnerability exists.
// Returns nil if the score is below 30 (not a finding).
func Analyze(original, test *graph.CapturedRequest, cfg *config.Config) *ScoredFinding {
	// Quick reject: test got a clear authorization denial
	if test.StatusCode == 401 || test.StatusCode == 403 || test.StatusCode == 404 {
		slog.Debug("analyzer: authorization enforced",
			"endpoint", original.URL,
			"test_status", test.StatusCode,
		)
		return nil
	}

	// Quick reject: original also failed
	if original.StatusCode >= 400 {
		return nil
	}

	var score float64
	var notes []string

	// ─── Factor 1: Status Code Match (30 points) ───
	if test.StatusCode == original.StatusCode {
		score += 30
		notes = append(notes, "Same status code")
	} else if test.StatusCode >= 200 && test.StatusCode < 300 {
		score += 15
		notes = append(notes, "Different but successful status")
	}

	// ─── Factor 2: Response Size Delta (20 points) ───
	sizeDelta := computeSizeDelta(len(original.ResponseBody), len(test.ResponseBody))
	if sizeDelta < 0.10 {
		score += 20
		notes = append(notes, "Similar response size")
	} else if sizeDelta < 0.30 {
		score += 10
		notes = append(notes, "Moderately different size")
	}

	// ─── Factor 3: JSON Key Similarity (25 points) ───
	keySimilarity := ComputeKeySimilarity(original.ResponseBody, test.ResponseBody)
	if keySimilarity > cfg.Analysis.SimilarityThreshold {
		score += 25
		notes = append(notes, "High structural similarity")
	} else if keySimilarity > 0.60 {
		score += 12
		notes = append(notes, "Moderate structural similarity")
	}

	// ─── Factor 4: Value Similarity (15 points) ───
	valSimilarity := ComputeValueSimilarity(original.ResponseBody, test.ResponseBody)
	if valSimilarity > 0.50 {
		score += 15
		notes = append(notes, "Data values present in test response")
	} else if valSimilarity > 0.20 {
		score += 7
	}

	// ─── Factor 5: Error Indicator Detection (10 points / -30 penalty) ───
	errorFound := DetectErrorIndicators(test.ResponseBody, cfg.Analysis.DetectErrorPatterns)
	if errorFound {
		score -= 30
		notes = append(notes, "Response contains error indicators (false positive)")
	} else {
		score += 10
		notes = append(notes, "No error indicators")
	}

	// ─── Score below threshold → not a finding ───
	if score < 30 {
		slog.Debug("analyzer: score below threshold",
			"endpoint", original.URL,
			"score", score,
		)
		return nil
	}

	// ─── Map score to confidence ───
	confidence := "LOW"
	if score >= 80 {
		confidence = "HIGH"
	} else if score >= 50 {
		confidence = "MEDIUM"
	}

	return &ScoredFinding{
		Score:         score,
		Confidence:    confidence,
		KeySimilarity: keySimilarity,
		ValSimilarity: valSimilarity,
		SizeDelta:     sizeDelta,
		ErrorFound:    errorFound,
		Notes:         strings.Join(notes, "; "),
	}
}

// DetectErrorIndicators checks if a response body contains error-like patterns.
// Uses both JSON structural checks and string matching.
func DetectErrorIndicators(body []byte, patterns []string) bool {
	if len(body) == 0 {
		return false
	}

	// Try JSON structural check first
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err == nil {
		// {"error": "..."} or {"error": {...}}
		for _, key := range []string{"error", "err", "errors"} {
			if v, ok := obj[key]; ok && v != nil && v != "" && v != false {
				return true
			}
		}
		// {"success": false}
		if success, ok := obj["success"]; ok {
			if b, ok := success.(bool); ok && !b {
				return true
			}
		}
		// {"status": "error"}
		if status, ok := obj["status"]; ok {
			if s, ok := status.(string); ok {
				lower := strings.ToLower(s)
				if lower == "error" || lower == "fail" || lower == "failure" {
					return true
				}
			}
		}
		// Check message field for error patterns
		if msg, ok := obj["message"]; ok {
			if s, ok := msg.(string); ok {
				lower := strings.ToLower(s)
				for _, p := range patterns {
					if strings.Contains(lower, p) {
						return true
					}
				}
			}
		}
	}

	// Fallback: string matching on the entire body
	lower := strings.ToLower(string(body))
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}

	return false
}

// computeSizeDelta calculates the relative size difference between two responses.
func computeSizeDelta(origSize, testSize int) float64 {
	if origSize == 0 && testSize == 0 {
		return 0
	}
	if origSize == 0 || testSize == 0 {
		return 1.0
	}
	return math.Abs(float64(origSize)-float64(testSize)) / math.Max(float64(origSize), float64(testSize))
}
