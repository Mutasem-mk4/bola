// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package graph

import (
	"path/filepath"
	"testing"
)

func TestOpenAndSchema(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()
}

func TestEndpointCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	// Insert
	ep, err := db.UpsertEndpoint("GET", "/api/users/{id}", "/api/users/123", "application/json")
	if err != nil {
		t.Fatalf("upserting endpoint: %v", err)
	}
	if ep.ID == 0 {
		t.Error("expected non-zero endpoint ID")
	}

	// Upsert same path should not error
	ep2, err := db.UpsertEndpoint("GET", "/api/users/{id}", "/api/users/456", "application/json")
	if err != nil {
		t.Fatalf("upserting duplicate endpoint: %v", err)
	}
	if ep2.Method != "GET" {
		t.Errorf("expected GET, got %s", ep2.Method)
	}

	// List
	endpoints, err := db.ListEndpoints()
	if err != nil {
		t.Fatalf("listing endpoints: %v", err)
	}
	if len(endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(endpoints))
	}

	count, err := db.CountEndpoints()
	if err != nil {
		t.Fatalf("counting endpoints: %v", err)
	}
	if count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}
}

func TestResourceCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	ep, _ := db.UpsertEndpoint("GET", "/api/users/{id}", "/api/users/123", "application/json")

	id, err := db.InsertResource(&Resource{
		EndpointID: ep.ID,
		Identity:   "user1",
		ObjectID:   "123",
		IDType:     "integer",
		IDLocation: "path",
		IDKey:      "id",
	})
	if err != nil {
		t.Fatalf("inserting resource: %v", err)
	}
	if id == 0 {
		t.Error("expected non-zero resource ID")
	}

	resources, err := db.GetResourcesByEndpoint(ep.ID)
	if err != nil {
		t.Fatalf("getting resources: %v", err)
	}
	if len(resources) != 1 {
		t.Errorf("expected 1 resource, got %d", len(resources))
	}

	resources, err = db.GetResourcesByIdentity("user1")
	if err != nil {
		t.Fatalf("getting resources by identity: %v", err)
	}
	if len(resources) != 1 {
		t.Errorf("expected 1 resource for user1, got %d", len(resources))
	}
}

func TestRelationships(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	ep, _ := db.UpsertEndpoint("GET", "/api/orgs/{id}/projects/{id}", "/api/orgs/1/projects/5", "application/json")

	parentID, _ := db.InsertResource(&Resource{
		EndpointID: ep.ID, Identity: "admin", ObjectID: "1",
		IDType: "integer", IDLocation: "path", IDKey: "org_id",
	})
	childID, _ := db.InsertResource(&Resource{
		EndpointID: ep.ID, Identity: "admin", ObjectID: "5",
		IDType: "integer", IDLocation: "path", IDKey: "project_id",
	})

	if err := db.InsertRelationship(parentID, childID, 0); err != nil {
		t.Fatalf("inserting relationship: %v", err)
	}

	parents, err := db.GetParentChain(childID)
	if err != nil {
		t.Fatalf("getting parent chain: %v", err)
	}
	if len(parents) != 1 {
		t.Errorf("expected 1 parent, got %d", len(parents))
	}
	if parents[0].ObjectID != "1" {
		t.Errorf("expected parent object ID 1, got %s", parents[0].ObjectID)
	}
}

func TestFindingsCRUD(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("opening database: %v", err)
	}
	defer db.Close()

	ep, _ := db.UpsertEndpoint("GET", "/api/users/{id}", "/api/users/123", "application/json")

	findingID, err := db.InsertFinding(&Finding{
		EndpointID:      ep.ID,
		OwnerIdentity:   "user1",
		TesterIdentity:  "user2",
		OwnerStatus:     200,
		TesterStatus:    200,
		SizeDelta:       0.05,
		Similarity:      0.92,
		ConfidenceLevel: ConfidenceHigh,
		CurlCommand:     "curl -X GET ...",
		Notes:           "Full data returned",
	})
	if err != nil {
		t.Fatalf("inserting finding: %v", err)
	}
	if findingID == 0 {
		t.Error("expected non-zero finding ID")
	}

	findings, err := db.ListFindings(ConfidenceLow)
	if err != nil {
		t.Fatalf("listing findings: %v", err)
	}
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ConfidenceLevel != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", findings[0].ConfidenceLevel)
	}
	if findings[0].Endpoint == nil {
		t.Error("expected endpoint to be populated")
	}
}
