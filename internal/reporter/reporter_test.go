// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

func sampleFindings() []*graph.Finding {
	return []*graph.Finding{
		{
			ID:              1,
			EndpointID:      1,
			OwnerIdentity:   "user1",
			TesterIdentity:  "user2",
			OwnerStatus:     200,
			TesterStatus:    200,
			SizeDelta:       0.05,
			Similarity:      0.95,
			ConfidenceLevel: graph.ConfidenceHigh,
			CurlCommand:     "curl -X GET 'https://api.test.com/api/v1/users/123' -H 'Authorization: Bearer evil'",
			Notes:           "Full data returned",
			CreatedAt:       time.Now(),
			Endpoint:        &graph.Endpoint{ID: 1, Method: "GET", Path: "/api/v1/users/{id}"},
		},
		{
			ID:              2,
			EndpointID:      2,
			OwnerIdentity:   "admin",
			TesterIdentity:  "guest",
			OwnerStatus:     200,
			TesterStatus:    200,
			SizeDelta:       0.12,
			Similarity:      0.78,
			ConfidenceLevel: graph.ConfidenceMedium,
			CurlCommand:     "curl -X GET 'https://api.test.com/api/v1/orders/456'",
			Notes:           "Partial data match",
			CreatedAt:       time.Now(),
			Endpoint:        &graph.Endpoint{ID: 2, Method: "GET", Path: "/api/v1/orders/{id}"},
		},
	}
}

func TestPrintTerminal(t *testing.T) {
	// Should not panic
	PrintBanner("test")
	PrintSummary(graph.Stats{Endpoints: 5, Resources: 10, Requests: 20, Findings: 2})
	PrintFindings(sampleFindings())
	PrintFindings(nil) // empty findings
}

func TestExportJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	err := ExportJSON(sampleFindings(), path, "v0.1.0-test")
	if err != nil {
		t.Fatalf("export JSON: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading JSON: %v", err)
	}

	var report JSONReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("parsing JSON: %v", err)
	}

	if report.Tool != "bola" {
		t.Errorf("tool: got %q", report.Tool)
	}
	if report.Summary.Total != 2 {
		t.Errorf("total: got %d", report.Summary.Total)
	}
	if report.Summary.High != 1 {
		t.Errorf("high: got %d", report.Summary.High)
	}
	if len(report.Findings) != 2 {
		t.Errorf("findings: got %d", len(report.Findings))
	}
}

func TestExportMarkdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")

	err := ExportMarkdown(sampleFindings(), path, "https://api.test.com")
	if err != nil {
		t.Fatalf("export markdown: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading markdown: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "BOLA/IDOR Vulnerability Report") {
		t.Error("missing title")
	}
	if !strings.Contains(content, "Steps to Reproduce") {
		t.Error("missing steps section")
	}
	if !strings.Contains(content, "curl") {
		t.Error("missing curl command")
	}
	if !strings.Contains(content, "Impact") {
		t.Error("missing impact section")
	}
}
