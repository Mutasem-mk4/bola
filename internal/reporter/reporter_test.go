// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package reporter

import (
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
			Endpoint: &graph.Endpoint{
				ID:      1,
				Method:  "GET",
				Path:    "/api/v1/users/{id}",
				RawPath: "/api/v1/users/123",
			},
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
			Endpoint: &graph.Endpoint{
				ID:      2,
				Method:  "GET",
				Path:    "/api/v1/orders/{id}",
				RawPath: "/api/v1/orders/456",
			},
		},
	}
}

func TestPrintTerminal(t *testing.T) {
	// Just ensure it doesn't panic
	PrintTerminal(sampleFindings())
	PrintTerminal(nil)
	PrintTerminal([]*graph.Finding{})
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")

	if err := WriteJSON(sampleFindings(), path); err != nil {
		t.Fatalf("writing JSON report: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading JSON report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, `"tool": "bola"`) {
		t.Error("JSON report should contain tool name")
	}
	if !strings.Contains(content, `"confidence": "HIGH"`) {
		t.Error("JSON report should contain HIGH confidence finding")
	}
	if !strings.Contains(content, `"high": 1`) {
		t.Error("JSON report should have 1 high finding in summary")
	}
}

func TestWriteMarkdown(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.md")

	if err := WriteMarkdown(sampleFindings(), path, "https://api.test.com"); err != nil {
		t.Fatalf("writing Markdown report: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading Markdown report: %v", err)
	}

	content := string(data)
	if !strings.Contains(content, "BOLA/IDOR Vulnerability Report") {
		t.Error("should contain report title")
	}
	if !strings.Contains(content, "Steps to Reproduce") {
		t.Error("should contain steps to reproduce")
	}
	if !strings.Contains(content, "Impact") {
		t.Error("should contain impact section")
	}
	if !strings.Contains(content, "curl") {
		t.Error("should contain curl reproduction command")
	}
}
