// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package dedup provides path normalization and finding deduplication.
package dedup

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

var (
	uuidPattern    = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
	mongoIDPattern = regexp.MustCompile(`[0-9a-fA-F]{24}`)
	integerPattern = regexp.MustCompile(`^\d+$`)
)

// Deduplicator removes duplicate findings by normalizing paths
// and keeping only the highest-confidence finding per unique pattern.
type Deduplicator struct {
	db *graph.DB
}

// New creates a new Deduplicator.
func New(db *graph.DB) *Deduplicator {
	return &Deduplicator{db: db}
}

// Run performs deduplication on all findings in the database.
// It groups findings by normalized endpoint pattern and keeps
// only the highest-confidence finding per group.
func (d *Deduplicator) Run() error {
	findings, err := d.db.ListFindings(graph.ConfidenceLow)
	if err != nil {
		return fmt.Errorf("listing findings: %w", err)
	}

	if len(findings) == 0 {
		return nil
	}

	// Group findings by normalized pattern
	groups := make(map[string][]*graph.Finding)
	for _, f := range findings {
		key := d.normalizeKey(f)
		groups[key] = append(groups[key], f)
	}

	// For each group with multiple findings, keep only the best
	for _, group := range groups {
		if len(group) <= 1 {
			continue
		}

		// Find the best finding (highest confidence, then highest similarity)
		best := group[0]
		for _, f := range group[1:] {
			if confidenceRank(f.ConfidenceLevel) > confidenceRank(best.ConfidenceLevel) {
				best = f
			} else if f.ConfidenceLevel == best.ConfidenceLevel && f.Similarity > best.Similarity {
				best = f
			}
		}

		// Mark duplicates with a note (we don't delete, just annotate)
		for _, f := range group {
			if f.ID != best.ID {
				f.Notes = "[DEDUPLICATED] " + f.Notes
			}
		}
	}

	return nil
}

// normalizeKey creates a deduplication key from a finding.
// Findings with the same key are considered duplicates.
func (d *Deduplicator) normalizeKey(f *graph.Finding) string {
	method := ""
	path := ""
	if f.Endpoint != nil {
		method = f.Endpoint.Method
		path = f.Endpoint.Path
	}

	// The path should already be normalized from the proxy,
	// but normalize again for safety
	normPath := NormalizePath(path)

	// Key: method + normalized path + identity pair direction
	return fmt.Sprintf("%s:%s:%s->%s",
		method,
		normPath,
		normalizeRole(f.OwnerIdentity),
		normalizeRole(f.TesterIdentity),
	)
}

// NormalizePath replaces ID-like segments with type placeholders.
func NormalizePath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}

		if uuidPattern.MatchString(seg) {
			segments[i] = "{uuid}"
		} else if len(seg) == 24 && mongoIDPattern.MatchString(seg) {
			segments[i] = "{mongoid}"
		} else if integerPattern.MatchString(seg) {
			segments[i] = "{id}"
		} else if isLikelyHash(seg) {
			segments[i] = "{hash}"
		}
	}
	return strings.Join(segments, "/")
}

// isLikelyHash checks if a string looks like a hash or token.
func isLikelyHash(s string) bool {
	if len(s) < 16 {
		return false
	}
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// normalizeRole extracts just the role concept (e.g., "user", "admin")
// to prevent duplicate findings for user1→user2 and user3→user4
// when they have the same role.
func normalizeRole(identity string) string {
	// If the identity name contains a role-like suffix, normalize it
	lower := strings.ToLower(identity)
	for _, role := range []string{"admin", "user", "editor", "guest", "viewer"} {
		if strings.Contains(lower, role) {
			return role
		}
	}
	return identity
}

// confidenceRank returns a numeric rank for confidence level comparison.
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
