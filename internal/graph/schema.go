// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package graph

// Schema contains the SQLite DDL for the resource graph.
const Schema = `
-- Enable WAL mode for better concurrent read/write performance
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

-- Endpoints: normalized API path patterns
CREATE TABLE IF NOT EXISTS endpoints (
	id       INTEGER PRIMARY KEY AUTOINCREMENT,
	method   TEXT    NOT NULL,
	path     TEXT    NOT NULL,
	raw_path TEXT    NOT NULL DEFAULT '',
	UNIQUE(method, path)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_method_path ON endpoints(method, path);

-- Resources: extracted object identifiers with ownership
CREATE TABLE IF NOT EXISTS resources (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	endpoint_id INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
	identity    TEXT    NOT NULL,
	object_id   TEXT    NOT NULL,
	id_type     TEXT    NOT NULL DEFAULT 'integer',
	location    TEXT    NOT NULL DEFAULT 'path',
	key         TEXT    NOT NULL DEFAULT '',
	UNIQUE(endpoint_id, identity, object_id)
);

CREATE INDEX IF NOT EXISTS idx_resources_endpoint_id ON resources(endpoint_id);
CREATE INDEX IF NOT EXISTS idx_resources_identity ON resources(identity);
CREATE INDEX IF NOT EXISTS idx_resources_object_id ON resources(object_id);

-- Relationships: parent-child links between resources
CREATE TABLE IF NOT EXISTS relationships (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	parent_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
	child_id  INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
	UNIQUE(parent_id, child_id)
);

-- Captured requests: full HTTP request/response pairs
CREATE TABLE IF NOT EXISTS requests (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	endpoint_id      INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
	identity         TEXT    NOT NULL,
	method           TEXT    NOT NULL,
	url              TEXT    NOT NULL,
	headers          TEXT    NOT NULL DEFAULT '{}',
	body             BLOB,
	status_code      INTEGER NOT NULL DEFAULT 0,
	response_headers TEXT    NOT NULL DEFAULT '{}',
	response_body    BLOB,
	response_size    INTEGER NOT NULL DEFAULT 0,
	created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_requests_endpoint_identity ON requests(endpoint_id, identity);

-- Findings: detected BOLA/IDOR vulnerabilities
CREATE TABLE IF NOT EXISTS findings (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	endpoint_id      INTEGER NOT NULL REFERENCES endpoints(id) ON DELETE CASCADE,
	owner_identity   TEXT    NOT NULL,
	tester_identity  TEXT    NOT NULL,
	owner_status     INTEGER NOT NULL DEFAULT 0,
	tester_status    INTEGER NOT NULL DEFAULT 0,
	size_delta       REAL    NOT NULL DEFAULT 0.0,
	similarity       REAL    NOT NULL DEFAULT 0.0,
	confidence_level TEXT    NOT NULL DEFAULT 'LOW',
	curl_command     TEXT    NOT NULL DEFAULT '',
	notes            TEXT    NOT NULL DEFAULT '',
	deduplicated     INTEGER NOT NULL DEFAULT 0,
	created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings(confidence_level);
CREATE INDEX IF NOT EXISTS idx_findings_endpoint ON findings(endpoint_id);
`
