// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

// JSONFinding is the serializable format for JSON reports.
type JSONFinding struct {
	ID             int64   `json:"id"`
	Confidence     string  `json:"confidence"`
	Method         string  `json:"method"`
	Path           string  `json:"path"`
	RawPath        string  `json:"raw_path,omitempty"`
	OwnerIdentity  string  `json:"owner_identity"`
	TesterIdentity string  `json:"tester_identity"`
	OwnerStatus    int     `json:"owner_status"`
	TesterStatus   int     `json:"tester_status"`
	SizeDelta      float64 `json:"size_delta"`
	Similarity     float64 `json:"similarity"`
	CurlCommand    string  `json:"curl_command"`
	Notes          string  `json:"notes,omitempty"`
	Timestamp      string  `json:"timestamp"`
}

// JSONReport is the top-level JSON report structure.
type JSONReport struct {
	Tool      string        `json:"tool"`
	Version   string        `json:"version"`
	Timestamp string        `json:"timestamp"`
	Summary   JSONSummary   `json:"summary"`
	Findings  []JSONFinding `json:"findings"`
}

// JSONSummary contains aggregate statistics.
type JSONSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
}

// ExportJSON generates a JSON report file from findings.
func ExportJSON(findings []*graph.Finding, path string, version string) error {
	high, medium, low := countByConfidence(findings)

	report := JSONReport{
		Tool:      "bola",
		Version:   version,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Summary: JSONSummary{
			Total:  high + medium + low,
			High:   high,
			Medium: medium,
			Low:    low,
		},
	}

	for _, f := range findings {
		method, fpath, rawPath := "", "", ""
		if f.Endpoint != nil {
			method = f.Endpoint.Method
			fpath = f.Endpoint.Path
			rawPath = f.Endpoint.RawPath
		}

		report.Findings = append(report.Findings, JSONFinding{
			ID:             f.ID,
			Confidence:     string(f.ConfidenceLevel),
			Method:         method,
			Path:           fpath,
			RawPath:        rawPath,
			OwnerIdentity:  f.OwnerIdentity,
			TesterIdentity: f.TesterIdentity,
			OwnerStatus:    f.OwnerStatus,
			TesterStatus:   f.TesterStatus,
			SizeDelta:      f.SizeDelta,
			Similarity:     f.Similarity,
			CurlCommand:    f.CurlCommand,
			Notes:          f.Notes,
			Timestamp:      f.CreatedAt.Format(time.RFC3339),
		})
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("reporter: marshaling JSON: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}
