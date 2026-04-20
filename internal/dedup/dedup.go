// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package dedup provides path normalization and finding deduplication.
package dedup

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/proxy"
)

// Deduplicator groups and deduplicates findings.
type Deduplicator struct {
	db *graph.DB
}

// New creates a new deduplicator.
func New(db *graph.DB) *Deduplicator {
	return &Deduplicator{db: db}
}

// Run deduplicates all findings in the database.
// Groups by (method + normalized_path + id_location), keeps highest confidence per group.
func (d *Deduplicator) Run() error {
	findings, err := d.db.AllFindings()
	if err != nil {
		return fmt.Errorf("dedup: loading findings: %w", err)
	}

	if len(findings) == 0 {
		return nil
	}

	// Group findings by their dedup key
	type groupKey struct {
		method         string
		normalizedPath string
		direction      string // "owner→tester" role direction
	}

	groups := make(map[groupKey][]*graph.Finding)

	for _, f := range findings {
		method, path := "", ""
		if f.Endpoint != nil {
			method = f.Endpoint.Method
			path = f.Endpoint.Path
		}

		key := groupKey{
			method:         method,
			normalizedPath: proxy.NormalizePath(path),
			direction:      normalizeRole(f.OwnerIdentity) + "→" + normalizeRole(f.TesterIdentity),
		}

		groups[key] = append(groups[key], f)
	}

	// For each group with > 1 finding, mark all except the highest confidence as deduplicated
	dedupCount := 0
	for _, group := range groups {
		if len(group) <= 1 {
			continue
		}

		// Sort by confidence (HIGH > MEDIUM > LOW), then by similarity
		bestIdx := 0
		for i := 1; i < len(group); i++ {
			if confidenceRank(group[i].ConfidenceLevel) > confidenceRank(group[bestIdx].ConfidenceLevel) {
				bestIdx = i
			} else if confidenceRank(group[i].ConfidenceLevel) == confidenceRank(group[bestIdx].ConfidenceLevel) &&
				group[i].Similarity > group[bestIdx].Similarity {
				bestIdx = i
			}
		}

		for i, f := range group {
			if i != bestIdx {
				if err := d.db.MarkDeduplicated(f.ID); err != nil {
					slog.Error("dedup: marking finding",
						"finding_id", f.ID,
						"error", err,
					)
				}
				dedupCount++
			}
		}
	}

	slog.Info("dedup: completed",
		"total_findings", len(findings),
		"deduplicated", dedupCount,
		"unique_groups", len(groups),
	)

	return nil
}

// confidenceRank returns a numeric rank for confidence ordering.
func confidenceRank(c graph.Confidence) int {
	switch c {
	case graph.ConfidenceHigh:
		return 3
	case graph.ConfidenceMedium:
		return 2
	case graph.ConfidenceLow:
		return 1
	default:
		return 0
	}
}

// normalizeRole normalizes identity/role names for grouping.
func normalizeRole(identity string) string {
	lower := strings.ToLower(identity)
	if strings.Contains(lower, "admin") || strings.Contains(lower, "super") {
		return "admin"
	}
	if strings.Contains(lower, "guest") || strings.Contains(lower, "anon") || strings.Contains(lower, "unauth") {
		return "guest"
	}
	return "user"
}
