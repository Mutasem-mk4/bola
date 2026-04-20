// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package graph

import "time"

// Confidence represents the confidence level of a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Endpoint represents a normalized API endpoint.
type Endpoint struct {
	ID      int64
	Method  string
	Path    string // Normalized path pattern (e.g., /api/users/{id})
	RawPath string // Original raw path
}

// Resource represents an extracted object identifier owned by an identity.
type Resource struct {
	ID         int64
	EndpointID int64
	Identity   string // identity name from vault
	ObjectID   string // the actual ID value
	IDType     string // uuid, integer, mongoid, hash
	Location   string // path, query, body, header
	Key        string // the parameter or JSON key
}

// Relationship represents a parent-child link between resources.
type Relationship struct {
	ID       int64
	ParentID int64
	ChildID  int64
}

// CapturedRequest represents a full HTTP request/response pair.
type CapturedRequest struct {
	ID              int64
	EndpointID      int64
	Identity        string
	Method          string
	URL             string
	Headers         string // JSON-encoded map[string]string
	Body            []byte
	StatusCode      int
	ResponseHeaders string // JSON-encoded
	ResponseBody    []byte
	ResponseSize    int
	CreatedAt       time.Time
}

// Finding represents a confirmed or suspected BOLA/IDOR vulnerability.
type Finding struct {
	ID              int64
	EndpointID      int64
	OwnerIdentity   string
	TesterIdentity  string
	OwnerStatus     int
	TesterStatus    int
	SizeDelta       float64
	Similarity      float64
	ConfidenceLevel Confidence
	CurlCommand     string
	Notes           string
	Deduplicated    bool
	CreatedAt       time.Time

	// Joined fields (populated by queries)
	Endpoint *Endpoint
}

// Stats holds aggregate counts for the resource graph.
type Stats struct {
	Endpoints int
	Resources int
	Requests  int
	Findings  int
}
