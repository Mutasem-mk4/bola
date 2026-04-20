// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package graph provides the SQLite-backed resource graph for bola.
// It stores endpoints, resources (object IDs), their ownership relationships,
// captured requests/responses, and BOLA findings.
package graph

import "time"

// Endpoint represents a unique API endpoint (method + normalized path).
type Endpoint struct {
	ID          int64     `json:"id"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`       // normalized: /api/users/{id}
	RawPath     string    `json:"raw_path"`   // original: /api/users/123
	ContentType string    `json:"content_type"`
	CreatedAt   time.Time `json:"created_at"`
}

// Resource represents an object ID extracted from an API response.
type Resource struct {
	ID         int64     `json:"id"`
	EndpointID int64     `json:"endpoint_id"`
	Identity   string    `json:"identity"`    // which identity owns this
	ObjectID   string    `json:"object_id"`   // the actual ID value
	IDType     string    `json:"id_type"`     // uuid | integer | mongoid | hash
	IDLocation string    `json:"id_location"` // path | query | body | header
	IDKey      string    `json:"id_key"`      // the JSON key or param name
	CreatedAt  time.Time `json:"created_at"`
}

// Relationship represents a parent-child link between resources.
type Relationship struct {
	ParentID int64 `json:"parent_id"`
	ChildID  int64 `json:"child_id"`
	Depth    int   `json:"depth"`
}

// CapturedRequest stores a full HTTP request/response pair.
type CapturedRequest struct {
	ID              int64     `json:"id"`
	EndpointID      int64     `json:"endpoint_id"`
	Identity        string    `json:"identity"`
	Method          string    `json:"method"`
	URL             string    `json:"url"`
	Headers         string    `json:"headers"`          // JSON serialized
	Body            []byte    `json:"body,omitempty"`
	StatusCode      int       `json:"status_code"`
	ResponseHeaders string    `json:"response_headers"` // JSON serialized
	ResponseBody    []byte    `json:"response_body,omitempty"`
	ResponseSize    int       `json:"response_size"`
	CreatedAt       time.Time `json:"created_at"`
}

// Confidence represents the confidence level of a BOLA finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Finding represents a potential BOLA/IDOR vulnerability.
type Finding struct {
	ID              int64      `json:"id"`
	EndpointID      int64      `json:"endpoint_id"`
	OwnerIdentity   string     `json:"owner_identity"`
	TesterIdentity  string     `json:"tester_identity"`
	OwnerStatus     int        `json:"owner_status"`
	TesterStatus    int        `json:"tester_status"`
	SizeDelta       float64    `json:"size_delta"`
	Similarity      float64    `json:"similarity"`
	ConfidenceLevel Confidence `json:"confidence"`
	CurlCommand     string     `json:"curl_command"`
	Notes           string     `json:"notes"`
	CreatedAt       time.Time  `json:"created_at"`

	// Populated by joins, not stored directly
	Endpoint *Endpoint `json:"endpoint,omitempty"`
}

// TestPair holds the original and test response for comparison.
type TestPair struct {
	OriginalRequest  *CapturedRequest
	TestRequest      *CapturedRequest
	OwnerIdentity    string
	TesterIdentity   string
	EndpointID       int64
}
