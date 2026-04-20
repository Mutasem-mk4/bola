// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package graph

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // Pure-Go SQLite driver
)

// schema contains the DDL statements to initialize the bola database.
const schema = `
CREATE TABLE IF NOT EXISTS endpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    raw_path    TEXT NOT NULL,
    content_type TEXT DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(method, path)
);

CREATE TABLE IF NOT EXISTS resources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER REFERENCES endpoints(id),
    identity    TEXT NOT NULL,
    object_id   TEXT NOT NULL,
    id_type     TEXT NOT NULL,
    id_location TEXT NOT NULL,
    id_key      TEXT DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS relationships (
    parent_id   INTEGER REFERENCES resources(id),
    child_id    INTEGER REFERENCES resources(id),
    depth       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (parent_id, child_id)
);

CREATE TABLE IF NOT EXISTS requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id      INTEGER REFERENCES endpoints(id),
    identity         TEXT NOT NULL,
    method           TEXT NOT NULL,
    url              TEXT NOT NULL,
    headers          TEXT NOT NULL DEFAULT '{}',
    body             BLOB,
    status_code      INTEGER DEFAULT 0,
    response_headers TEXT DEFAULT '{}',
    response_body    BLOB,
    response_size    INTEGER DEFAULT 0,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id     INTEGER REFERENCES endpoints(id),
    owner_identity  TEXT NOT NULL,
    tester_identity TEXT NOT NULL,
    owner_status    INTEGER DEFAULT 0,
    tester_status   INTEGER DEFAULT 0,
    size_delta      REAL DEFAULT 0.0,
    similarity      REAL DEFAULT 0.0,
    confidence      TEXT NOT NULL,
    curl_command    TEXT NOT NULL DEFAULT '',
    notes           TEXT DEFAULT '',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_resources_identity ON resources(identity);
CREATE INDEX IF NOT EXISTS idx_resources_endpoint ON resources(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_requests_endpoint ON requests(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_requests_identity ON requests(identity);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint_id);
`

// DB wraps an SQLite database connection for the bola resource graph.
type DB struct {
	conn *sql.DB
}

// Open creates or opens an SQLite database at the given path
// and initializes the schema.
func Open(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// SQLite performance tuning for our workload
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=-64000", // 64MB cache
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := conn.Exec(p); err != nil {
			conn.Close()
			return nil, fmt.Errorf("setting pragma %q: %w", p, err)
		}
	}

	if _, err := conn.Exec(schema); err != nil {
		conn.Close()
		return nil, fmt.Errorf("initializing schema: %w", err)
	}

	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

// --- Endpoint operations ---

// UpsertEndpoint inserts or retrieves an endpoint by (method, path).
func (db *DB) UpsertEndpoint(method, path, rawPath, contentType string) (*Endpoint, error) {
	res, err := db.conn.Exec(
		`INSERT INTO endpoints (method, path, raw_path, content_type)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(method, path) DO UPDATE SET raw_path = excluded.raw_path`,
		method, path, rawPath, contentType,
	)
	if err != nil {
		return nil, fmt.Errorf("upserting endpoint: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		// Conflict — look it up
		row := db.conn.QueryRow(
			"SELECT id, method, path, raw_path, content_type, created_at FROM endpoints WHERE method = ? AND path = ?",
			method, path,
		)
		ep := &Endpoint{}
		if err := row.Scan(&ep.ID, &ep.Method, &ep.Path, &ep.RawPath, &ep.ContentType, &ep.CreatedAt); err != nil {
			return nil, fmt.Errorf("fetching existing endpoint: %w", err)
		}
		return ep, nil
	}

	return &Endpoint{
		ID:          id,
		Method:      method,
		Path:        path,
		RawPath:     rawPath,
		ContentType: contentType,
		CreatedAt:   time.Now(),
	}, nil
}

// GetEndpoint retrieves an endpoint by ID.
func (db *DB) GetEndpoint(id int64) (*Endpoint, error) {
	row := db.conn.QueryRow(
		"SELECT id, method, path, raw_path, content_type, created_at FROM endpoints WHERE id = ?", id,
	)
	ep := &Endpoint{}
	if err := row.Scan(&ep.ID, &ep.Method, &ep.Path, &ep.RawPath, &ep.ContentType, &ep.CreatedAt); err != nil {
		return nil, fmt.Errorf("getting endpoint %d: %w", id, err)
	}
	return ep, nil
}

// ListEndpoints returns all endpoints.
func (db *DB) ListEndpoints() ([]*Endpoint, error) {
	rows, err := db.conn.Query(
		"SELECT id, method, path, raw_path, content_type, created_at FROM endpoints ORDER BY id",
	)
	if err != nil {
		return nil, fmt.Errorf("listing endpoints: %w", err)
	}
	defer rows.Close()

	var endpoints []*Endpoint
	for rows.Next() {
		ep := &Endpoint{}
		if err := rows.Scan(&ep.ID, &ep.Method, &ep.Path, &ep.RawPath, &ep.ContentType, &ep.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning endpoint: %w", err)
		}
		endpoints = append(endpoints, ep)
	}
	return endpoints, rows.Err()
}

// --- Resource operations ---

// InsertResource adds a new resource (object ID) to the graph.
func (db *DB) InsertResource(r *Resource) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO resources (endpoint_id, identity, object_id, id_type, id_location, id_key)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		r.EndpointID, r.Identity, r.ObjectID, r.IDType, r.IDLocation, r.IDKey,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting resource: %w", err)
	}
	return res.LastInsertId()
}

// GetResourcesByEndpoint returns all resources for a given endpoint.
func (db *DB) GetResourcesByEndpoint(endpointID int64) ([]*Resource, error) {
	rows, err := db.conn.Query(
		`SELECT id, endpoint_id, identity, object_id, id_type, id_location, id_key, created_at
		 FROM resources WHERE endpoint_id = ?`,
		endpointID,
	)
	if err != nil {
		return nil, fmt.Errorf("getting resources for endpoint %d: %w", endpointID, err)
	}
	defer rows.Close()

	var resources []*Resource
	for rows.Next() {
		r := &Resource{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.ObjectID, &r.IDType, &r.IDLocation, &r.IDKey, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning resource: %w", err)
		}
		resources = append(resources, r)
	}
	return resources, rows.Err()
}

// GetResourcesByIdentity returns all resources owned by a given identity.
func (db *DB) GetResourcesByIdentity(identity string) ([]*Resource, error) {
	rows, err := db.conn.Query(
		`SELECT id, endpoint_id, identity, object_id, id_type, id_location, id_key, created_at
		 FROM resources WHERE identity = ?`,
		identity,
	)
	if err != nil {
		return nil, fmt.Errorf("getting resources for identity %q: %w", identity, err)
	}
	defer rows.Close()

	var resources []*Resource
	for rows.Next() {
		r := &Resource{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.ObjectID, &r.IDType, &r.IDLocation, &r.IDKey, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning resource: %w", err)
		}
		resources = append(resources, r)
	}
	return resources, rows.Err()
}

// --- Relationship operations ---

// InsertRelationship records a parent-child relationship between resources.
func (db *DB) InsertRelationship(parentID, childID int64, depth int) error {
	_, err := db.conn.Exec(
		`INSERT OR IGNORE INTO relationships (parent_id, child_id, depth)
		 VALUES (?, ?, ?)`,
		parentID, childID, depth,
	)
	if err != nil {
		return fmt.Errorf("inserting relationship: %w", err)
	}
	return nil
}

// GetParentChain returns the parent resources of a given resource, ordered by depth.
func (db *DB) GetParentChain(resourceID int64) ([]*Resource, error) {
	rows, err := db.conn.Query(
		`SELECT r.id, r.endpoint_id, r.identity, r.object_id, r.id_type, r.id_location, r.id_key, r.created_at
		 FROM resources r
		 JOIN relationships rel ON r.id = rel.parent_id
		 WHERE rel.child_id = ?
		 ORDER BY rel.depth DESC`,
		resourceID,
	)
	if err != nil {
		return nil, fmt.Errorf("getting parent chain for resource %d: %w", resourceID, err)
	}
	defer rows.Close()

	var parents []*Resource
	for rows.Next() {
		r := &Resource{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.ObjectID, &r.IDType, &r.IDLocation, &r.IDKey, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning parent resource: %w", err)
		}
		parents = append(parents, r)
	}
	return parents, rows.Err()
}

// --- Request operations ---

// InsertRequest stores a captured HTTP request/response.
func (db *DB) InsertRequest(r *CapturedRequest) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO requests (endpoint_id, identity, method, url, headers, body, status_code, response_headers, response_body, response_size)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		r.EndpointID, r.Identity, r.Method, r.URL, r.Headers, r.Body,
		r.StatusCode, r.ResponseHeaders, r.ResponseBody, r.ResponseSize,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting request: %w", err)
	}
	return res.LastInsertId()
}

// GetRequestsByEndpointAndIdentity returns captured requests for a given endpoint+identity.
func (db *DB) GetRequestsByEndpointAndIdentity(endpointID int64, identity string) ([]*CapturedRequest, error) {
	rows, err := db.conn.Query(
		`SELECT id, endpoint_id, identity, method, url, headers, body, status_code, response_headers, response_body, response_size, created_at
		 FROM requests WHERE endpoint_id = ? AND identity = ?
		 ORDER BY created_at DESC LIMIT 1`,
		endpointID, identity,
	)
	if err != nil {
		return nil, fmt.Errorf("getting requests: %w", err)
	}
	defer rows.Close()

	var requests []*CapturedRequest
	for rows.Next() {
		r := &CapturedRequest{}
		if err := rows.Scan(&r.ID, &r.EndpointID, &r.Identity, &r.Method, &r.URL, &r.Headers, &r.Body,
			&r.StatusCode, &r.ResponseHeaders, &r.ResponseBody, &r.ResponseSize, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning request: %w", err)
		}
		requests = append(requests, r)
	}
	return requests, rows.Err()
}

// --- Finding operations ---

// InsertFinding stores a BOLA/IDOR finding.
func (db *DB) InsertFinding(f *Finding) (int64, error) {
	res, err := db.conn.Exec(
		`INSERT INTO findings (endpoint_id, owner_identity, tester_identity, owner_status, tester_status, size_delta, similarity, confidence, curl_command, notes)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.EndpointID, f.OwnerIdentity, f.TesterIdentity, f.OwnerStatus, f.TesterStatus,
		f.SizeDelta, f.Similarity, f.ConfidenceLevel, f.CurlCommand, f.Notes,
	)
	if err != nil {
		return 0, fmt.Errorf("inserting finding: %w", err)
	}
	return res.LastInsertId()
}

// ListFindings returns all findings, optionally filtered by minimum confidence.
func (db *DB) ListFindings(minConfidence Confidence) ([]*Finding, error) {
	confidences := []string{"HIGH", "MEDIUM", "LOW"}
	switch minConfidence {
	case ConfidenceHigh:
		confidences = []string{"HIGH"}
	case ConfidenceMedium:
		confidences = []string{"HIGH", "MEDIUM"}
	case ConfidenceLow:
		confidences = []string{"HIGH", "MEDIUM", "LOW"}
	}

	query := `SELECT f.id, f.endpoint_id, f.owner_identity, f.tester_identity,
	          f.owner_status, f.tester_status, f.size_delta, f.similarity,
	          f.confidence, f.curl_command, f.notes, f.created_at,
	          e.method, e.path, e.raw_path, e.content_type
	          FROM findings f
	          JOIN endpoints e ON f.endpoint_id = e.id
	          WHERE f.confidence IN (?, ?, ?)
	          ORDER BY CASE f.confidence WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END`

	// Pad confidences to always have 3 args
	for len(confidences) < 3 {
		confidences = append(confidences, confidences[len(confidences)-1])
	}

	rows, err := db.conn.Query(query, confidences[0], confidences[1], confidences[2])
	if err != nil {
		return nil, fmt.Errorf("listing findings: %w", err)
	}
	defer rows.Close()

	var findings []*Finding
	for rows.Next() {
		f := &Finding{Endpoint: &Endpoint{}}
		if err := rows.Scan(
			&f.ID, &f.EndpointID, &f.OwnerIdentity, &f.TesterIdentity,
			&f.OwnerStatus, &f.TesterStatus, &f.SizeDelta, &f.Similarity,
			&f.ConfidenceLevel, &f.CurlCommand, &f.Notes, &f.CreatedAt,
			&f.Endpoint.Method, &f.Endpoint.Path, &f.Endpoint.RawPath, &f.Endpoint.ContentType,
		); err != nil {
			return nil, fmt.Errorf("scanning finding: %w", err)
		}
		f.Endpoint.ID = f.EndpointID
		findings = append(findings, f)
	}
	return findings, rows.Err()
}

// CountEndpoints returns the total number of endpoints.
func (db *DB) CountEndpoints() (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM endpoints").Scan(&count)
	return count, err
}

// CountResources returns the total number of resources.
func (db *DB) CountResources() (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM resources").Scan(&count)
	return count, err
}

// CountFindings returns the total number of findings.
func (db *DB) CountFindings() (int, error) {
	var count int
	err := db.conn.QueryRow("SELECT COUNT(*) FROM findings").Scan(&count)
	return count, err
}
