// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package graph

import (
	"path/filepath"
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("opening test db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAndSchema(t *testing.T) {
	db := openTestDB(t)
	stats := db.Stats()
	if stats.Endpoints != 0 {
		t.Errorf("expected 0 endpoints, got %d", stats.Endpoints)
	}
}

func TestEndpointCRUD(t *testing.T) {
	db := openTestDB(t)

	id1, err := db.InsertEndpoint("GET", "/api/users/{id}", "/api/users/123")
	if err != nil {
		t.Fatalf("insert endpoint: %v", err)
	}
	if id1 <= 0 {
		t.Fatal("expected positive endpoint ID")
	}

	// Duplicate should return same ID
	id2, err := db.InsertEndpoint("GET", "/api/users/{id}", "/api/users/456")
	if err != nil {
		t.Fatalf("insert duplicate: %v", err)
	}
	if id2 != id1 {
		t.Errorf("duplicate insert returned different ID: %d vs %d", id1, id2)
	}

	// Different method = different endpoint
	id3, err := db.InsertEndpoint("POST", "/api/users/{id}", "/api/users/123")
	if err != nil {
		t.Fatalf("insert POST endpoint: %v", err)
	}
	if id3 == id1 {
		t.Error("different method should create new endpoint")
	}

	endpoints, err := db.ListEndpoints()
	if err != nil {
		t.Fatalf("list endpoints: %v", err)
	}
	if len(endpoints) != 2 {
		t.Errorf("expected 2 endpoints, got %d", len(endpoints))
	}
}

func TestResourceCRUD(t *testing.T) {
	db := openTestDB(t)

	epID, _ := db.InsertEndpoint("GET", "/api/users/{id}", "/api/users/123")
	rID, err := db.InsertResource(epID, "user1", "123", "integer", "path", "users")
	if err != nil {
		t.Fatalf("insert resource: %v", err)
	}
	if rID <= 0 {
		t.Fatal("expected positive resource ID")
	}

	resources, err := db.GetResourcesByEndpoint(epID)
	if err != nil {
		t.Fatalf("get resources: %v", err)
	}
	if len(resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(resources))
	}

	byIdentity, err := db.GetResourcesByIdentity("user1")
	if err != nil {
		t.Fatalf("get by identity: %v", err)
	}
	if len(byIdentity) != 1 {
		t.Errorf("expected 1 resource for user1, got %d", len(byIdentity))
	}
}

func TestRelationships(t *testing.T) {
	db := openTestDB(t)

	epID, _ := db.InsertEndpoint("GET", "/api/users/{id}/orders/{id}", "/api/users/1/orders/1")
	parentID, _ := db.InsertResource(epID, "user1", "1", "integer", "path", "users")
	childID, _ := db.InsertResource(epID, "user1", "42", "integer", "path", "orders")

	if err := db.InsertRelationship(parentID, childID); err != nil {
		t.Fatalf("insert relationship: %v", err)
	}

	chain, err := db.GetParentChain(childID)
	if err != nil {
		t.Fatalf("get parent chain: %v", err)
	}
	if len(chain) != 1 {
		t.Errorf("expected 1 parent, got %d", len(chain))
	}
	if chain[0].ObjectID != "1" {
		t.Errorf("parent objectID: got %q", chain[0].ObjectID)
	}
}

func TestRequestsCRUD(t *testing.T) {
	db := openTestDB(t)

	epID, _ := db.InsertEndpoint("GET", "/api/users/{id}", "/api/users/1")
	_, err := db.InsertRequest(&CapturedRequest{
		EndpointID: epID,
		Identity:   "user1",
		Method:     "GET",
		URL:        "http://localhost/api/users/1",
		Headers:    `{"Authorization":"Bearer x"}`,
		StatusCode: 200,
		ResponseBody: []byte(`{"id": 1}`),
		ResponseSize: 10,
	})
	if err != nil {
		t.Fatalf("insert request: %v", err)
	}

	requests, err := db.GetRequestsByEndpointAndIdentity(epID, "user1")
	if err != nil {
		t.Fatalf("get requests: %v", err)
	}
	if len(requests) != 1 {
		t.Errorf("expected 1 request, got %d", len(requests))
	}
}

func TestFindingsCRUD(t *testing.T) {
	db := openTestDB(t)

	epID, _ := db.InsertEndpoint("GET", "/api/users/{id}", "/api/users/1")
	_, err := db.InsertFinding(&Finding{
		EndpointID:      epID,
		OwnerIdentity:   "user1",
		TesterIdentity:  "user2",
		OwnerStatus:     200,
		TesterStatus:    200,
		SizeDelta:       0.05,
		Similarity:      0.95,
		ConfidenceLevel: ConfidenceHigh,
		CurlCommand:     "curl ...",
		Notes:           "High similarity",
	})
	if err != nil {
		t.Fatalf("insert finding: %v", err)
	}

	findings, err := db.ListFindings(ConfidenceLow)
	if err != nil {
		t.Fatalf("list findings: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence() != ConfidenceHigh {
		t.Errorf("confidence: got %q", findings[0].ConfidenceLevel)
	}
	if findings[0].Endpoint == nil {
		t.Error("expected endpoint to be joined")
	}

	stats := db.Stats()
	if stats.Findings != 1 {
		t.Errorf("stats findings: got %d", stats.Findings)
	}
}

func TestMarkDeduplicated(t *testing.T) {
	db := openTestDB(t)

	epID, _ := db.InsertEndpoint("GET", "/test", "/test")
	fID, _ := db.InsertFinding(&Finding{
		EndpointID:      epID,
		OwnerIdentity:   "a",
		TesterIdentity:  "b",
		ConfidenceLevel: ConfidenceLow,
	})

	if err := db.MarkDeduplicated(fID); err != nil {
		t.Fatalf("mark deduplicated: %v", err)
	}

	// Should not appear in active findings
	findings, _ := db.ListFindings(ConfidenceLow)
	if len(findings) != 0 {
		t.Error("deduplicated finding should not appear in ListFindings")
	}

	// But should appear in AllFindings
	all, _ := db.AllFindings()
	if len(all) != 1 {
		t.Error("AllFindings should return deduplicated findings")
	}
}

// Confidence returns the confidence level.
func (f *Finding) Confidence() Confidence {
	return f.ConfidenceLevel
}
