// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package graph provides SQLite-backed storage for the BOLA resource graph.
package graph

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps a SQLite database for the resource graph.
type DB struct {
	db *sql.DB
}

// Open opens or creates a SQLite database and initializes the schema.
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("graph: opening database %q: %w", path, err)
	}

	sqlDB.SetMaxOpenConns(1) // SQLite doesn't support concurrent writes

	if _, err := sqlDB.Exec(Schema); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("graph: initializing schema: %w", err)
	}

	return &DB{db: sqlDB}, nil
}

// Close closes the database connection.
func (g *DB) Close() error {
	if g.db != nil {
		return g.db.Close()
	}
	return nil
}

// ─── Endpoints ──────────────────────────────────────────────────────

// InsertEndpoint inserts a new endpoint or returns the existing ID if a
// duplicate (method, path) already exists.
func (g *DB) InsertEndpoint(method, path, rawPath string) (int64, error) {
	// Try insert
	result, err := g.db.Exec(
		`INSERT OR IGNORE INTO endpoints (method, path, raw_path) VALUES (?, ?, ?)`,
		method, path, rawPath,
	)
	if err != nil {
		return 0, fmt.Errorf("graph: inserting endpoint: %w", err)
	}

	id, err := result.LastInsertId()
	if err == nil && id > 0 {
		return id, nil
	}

	// Already exists — get its ID
	var existingID int64
	err = g.db.QueryRow(
		`SELECT id FROM endpoints WHERE method = ? AND path = ?`, method, path,
	).Scan(&existingID)
	if err != nil {
		return 0, fmt.Errorf("graph: querying existing endpoint: %w", err)
	}
	return existingID, nil
}

// ListEndpoints returns all endpoints in the resource graph.
func (g *DB) ListEndpoints() ([]*Endpoint, error) {
	rows, err := g.db.Query(`SELECT id, method, path, raw_path FROM endpoints ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("graph: listing endpoints: %w", err)
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		ep := &Endpoint{}
		if err := rows.Scan(&ep.ID, &ep.Method, &ep.Path, &ep.RawPath); err != nil {
			return nil, fmt.Errorf("graph: scanning endpoint: %w", err)
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, rows.Err()
}

// ─── Resources ──────────────────────────────────────────────────────

// InsertResource inserts a new resource or ignores duplicates.
func (g *DB) InsertResource(endpointID int64, identity, objectID, idType, location, key string) (int64, error) {
	result, err := g.db.Exec(
		`INSERT OR IGNORE INTO resources (endpoint_id, identity, object_id, id_type, location, key)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		endpointID, identity, objectID, idType, location, key,
	)
	if err != nil {
		return 0, fmt.Errorf("graph: inserting resource: %w", err)
	}

	id, err := result.LastInsertId()
	if err == nil && id > 0 {
		return id, nil
	}

	var existingID int64
	err = g.db.QueryRow(
		`SELECT id FROM resources WHERE endpoint_id = ? AND identity = ? AND object_id = ?`,
		endpointID, identity, objectID,
	).Scan(&existingID)
	if err != nil {
		return 0, fmt.Errorf("graph: querying existing resource: %w", err)
	}
	return existingID, nil
}

// GetResourcesByEndpoint returns all resources associated with an endpoint.
func (g *DB) GetResourcesByEndpoint(endpointID int64) ([]*Resource, error) {
	rows, err := g.db.Query(
		`SELECT id, endpoint_id, identity, object_id, id_type, location, key
		 FROM resources WHERE endpoint_id = ?`, endpointID,
	)
	if err != nil {
		return nil, fmt.Errorf("graph: listing resources: %w", err)
	}
	defer rows.Close()

	var resources []*Resource
	for rows.Next() {
		r := &Resource{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.ObjectID, &r.IDType, &r.Location, &r.Key); err != nil {
			return nil, fmt.Errorf("graph: scanning resource: %w", err)
		}
		resources = append(resources, r)
	}
	return resources, rows.Err()
}

// GetResourcesByIdentity returns all resources owned by an identity.
func (g *DB) GetResourcesByIdentity(identity string) ([]*Resource, error) {
	rows, err := g.db.Query(
		`SELECT id, endpoint_id, identity, object_id, id_type, location, key
		 FROM resources WHERE identity = ?`, identity,
	)
	if err != nil {
		return nil, fmt.Errorf("graph: listing resources by identity: %w", err)
	}
	defer rows.Close()

	var resources []*Resource
	for rows.Next() {
		r := &Resource{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.ObjectID, &r.IDType, &r.Location, &r.Key); err != nil {
			return nil, fmt.Errorf("graph: scanning resource: %w", err)
		}
		resources = append(resources, r)
	}
	return resources, rows.Err()
}

// ─── Relationships ──────────────────────────────────────────────────

// InsertRelationship creates a parent-child link between resources.
func (g *DB) InsertRelationship(parentID, childID int64) error {
	_, err := g.db.Exec(
		`INSERT OR IGNORE INTO relationships (parent_id, child_id) VALUES (?, ?)`,
		parentID, childID,
	)
	if err != nil {
		return fmt.Errorf("graph: inserting relationship: %w", err)
	}
	return nil
}

// GetParentChain traverses up the parent chain from a resource.
func (g *DB) GetParentChain(resourceID int64) ([]*Resource, error) {
	var chain []*Resource
	visited := make(map[int64]bool)
	currentID := resourceID

	for i := 0; i < 10; i++ { // Max depth 10 to prevent cycles
		if visited[currentID] {
			break
		}
		visited[currentID] = true

		var parentID int64
		err := g.db.QueryRow(
			`SELECT parent_id FROM relationships WHERE child_id = ?`, currentID,
		).Scan(&parentID)
		if err == sql.ErrNoRows {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("graph: traversing parent chain: %w", err)
		}

		parent := &Resource{}
		err = g.db.QueryRow(
			`SELECT id, endpoint_id, identity, object_id, id_type, location, key
			 FROM resources WHERE id = ?`, parentID,
		).Scan(&parent.ID, &parent.EndpointID, &parent.Identity, &parent.ObjectID, &parent.IDType, &parent.Location, &parent.Key)
		if err != nil {
			return nil, fmt.Errorf("graph: loading parent resource: %w", err)
		}

		chain = append(chain, parent)
		currentID = parentID
	}

	return chain, nil
}

// ─── Requests ───────────────────────────────────────────────────────

// InsertRequest stores a captured HTTP request/response pair.
func (g *DB) InsertRequest(r *CapturedRequest) (int64, error) {
	result, err := g.db.Exec(
		`INSERT INTO requests (endpoint_id, identity, method, url, headers, body,
		 status_code, response_headers, response_body, response_size)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.EndpointID, r.Identity, r.Method, r.URL, r.Headers, r.Body,
		r.StatusCode, r.ResponseHeaders, r.ResponseBody, r.ResponseSize,
	)
	if err != nil {
		return 0, fmt.Errorf("graph: inserting request: %w", err)
	}
	return result.LastInsertId()
}

// GetRequestsByEndpointAndIdentity returns requests for an endpoint-identity pair.
func (g *DB) GetRequestsByEndpointAndIdentity(endpointID int64, identity string) ([]*CapturedRequest, error) {
	rows, err := g.db.Query(
		`SELECT id, endpoint_id, identity, method, url, headers, body,
		 status_code, response_headers, response_body, response_size, created_at
		 FROM requests WHERE endpoint_id = ? AND identity = ? ORDER BY id DESC`,
		endpointID, identity,
	)
	if err != nil {
		return nil, fmt.Errorf("graph: querying requests: %w", err)
	}
	defer rows.Close()

	var requests []*CapturedRequest
	for rows.Next() {
		r := &CapturedRequest{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.Method, &r.URL,
			&r.Headers, &r.Body, &r.StatusCode, &r.ResponseHeaders, &r.ResponseBody,
			&r.ResponseSize, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("graph: scanning request: %w", err)
		}
		requests = append(requests, r)
	}
	return requests, rows.Err()
}

// ─── Findings ───────────────────────────────────────────────────────

// InsertFinding stores a detected BOLA vulnerability.
func (g *DB) InsertFinding(f *Finding) (int64, error) {
	result, err := g.db.Exec(
		`INSERT INTO findings (endpoint_id, owner_identity, tester_identity,
		 owner_status, tester_status, size_delta, similarity,
		 confidence_level, curl_command, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.EndpointID, f.OwnerIdentity, f.TesterIdentity,
		f.OwnerStatus, f.TesterStatus, f.SizeDelta, f.Similarity,
		f.ConfidenceLevel, f.CurlCommand, f.Notes,
	)
	if err != nil {
		return 0, fmt.Errorf("graph: inserting finding: %w", err)
	}
	return result.LastInsertId()
}

// ListFindings returns findings at or above the minimum confidence level.
func (g *DB) ListFindings(minConfidence Confidence) ([]*Finding, error) {
	confidences := confidencesAbove(minConfidence)
	if len(confidences) == 0 {
		return nil, nil
	}

	query := `SELECT f.id, f.endpoint_id, f.owner_identity, f.tester_identity,
		f.owner_status, f.tester_status, f.size_delta, f.similarity,
		f.confidence_level, f.curl_command, f.notes, f.deduplicated, f.created_at,
		e.id, e.method, e.path, e.raw_path
		FROM findings f
		JOIN endpoints e ON f.endpoint_id = e.id
		WHERE f.confidence_level IN (` + placeholders(len(confidences)) + `)
		AND f.deduplicated = 0
		ORDER BY CASE f.confidence_level
			WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 END,
		f.id`

	args := make([]interface{}, len(confidences))
	for i, c := range confidences {
		args[i] = c
	}

	rows, err := g.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("graph: listing findings: %w", err)
	}
	defer rows.Close()

	var findings []*Finding
	for rows.Next() {
		f := &Finding{Endpoint: &Endpoint{}}
		if err := rows.Scan(&f.ID, &f.EndpointID, &f.OwnerIdentity, &f.TesterIdentity,
			&f.OwnerStatus, &f.TesterStatus, &f.SizeDelta, &f.Similarity,
			&f.ConfidenceLevel, &f.CurlCommand, &f.Notes, &f.Deduplicated, &f.CreatedAt,
			&f.Endpoint.ID, &f.Endpoint.Method, &f.Endpoint.Path, &f.Endpoint.RawPath,
		); err != nil {
			return nil, fmt.Errorf("graph: scanning finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// MarkDeduplicated flags a finding as deduplicated.
func (g *DB) MarkDeduplicated(findingID int64) error {
	_, err := g.db.Exec(`UPDATE findings SET deduplicated = 1 WHERE id = ?`, findingID)
	if err != nil {
		return fmt.Errorf("graph: marking deduplicated: %w", err)
	}
	return nil
}

// AllFindings returns every finding regardless of dedup status.
func (g *DB) AllFindings() ([]*Finding, error) {
	rows, err := g.db.Query(
		`SELECT f.id, f.endpoint_id, f.owner_identity, f.tester_identity,
		 f.owner_status, f.tester_status, f.size_delta, f.similarity,
		 f.confidence_level, f.curl_command, f.notes, f.deduplicated, f.created_at,
		 e.id, e.method, e.path, e.raw_path
		 FROM findings f
		 JOIN endpoints e ON f.endpoint_id = e.id
		 ORDER BY f.id`,
	)
	if err != nil {
		return nil, fmt.Errorf("graph: listing all findings: %w", err)
	}
	defer rows.Close()

	var findings []*Finding
	for rows.Next() {
		f := &Finding{Endpoint: &Endpoint{}}
		if err := rows.Scan(&f.ID, &f.EndpointID, &f.OwnerIdentity, &f.TesterIdentity,
			&f.OwnerStatus, &f.TesterStatus, &f.SizeDelta, &f.Similarity,
			&f.ConfidenceLevel, &f.CurlCommand, &f.Notes, &f.Deduplicated, &f.CreatedAt,
			&f.Endpoint.ID, &f.Endpoint.Method, &f.Endpoint.Path, &f.Endpoint.RawPath,
		); err != nil {
			return nil, fmt.Errorf("graph: scanning finding: %w", err)
		}
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// ─── Stats ──────────────────────────────────────────────────────────

// Stats returns aggregate counts for the resource graph.
func (g *DB) Stats() Stats {
	var s Stats
	_ = g.db.QueryRow(`SELECT COUNT(*) FROM endpoints`).Scan(&s.Endpoints)
	_ = g.db.QueryRow(`SELECT COUNT(*) FROM resources`).Scan(&s.Resources)
	_ = g.db.QueryRow(`SELECT COUNT(*) FROM requests`).Scan(&s.Requests)
	_ = g.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE deduplicated = 0`).Scan(&s.Findings)
	return s
}

// ─── Helpers ────────────────────────────────────────────────────────

// confidencesAbove returns confidence levels at or above the minimum.
func confidencesAbove(min Confidence) []string {
	switch min {
	case ConfidenceHigh:
		return []string{"HIGH"}
	case ConfidenceMedium:
		return []string{"HIGH", "MEDIUM"}
	default:
		return []string{"HIGH", "MEDIUM", "LOW"}
	}
}

// placeholders generates SQL placeholders: ?,?,?
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	s := "?"
	for i := 1; i < n; i++ {
		s += ",?"
	}
	return s
}

// ensure DB satisfies close interface
var _ interface{ Close() error } = (*DB)(nil)

// Dummy usage to prevent unused import warnings during development
var _ = time.Now
