// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package tester implements the cross-identity authorization replay engine.
package tester

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Mutasem-mk4/bola/internal/analyzer"
	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

// Tester orchestrates cross-identity authorization tests.
type Tester struct {
	cfg      *config.Config
	db       *graph.DB
	vault    *vault.Vault
	analyzer *analyzer.Analyzer
	client   *http.Client

	// Rate limiting
	ticker    *time.Ticker
	rateLimit chan struct{}

	// Stats
	mu            sync.Mutex
	testsRun      int
	findingsFound int
}

// New creates a new cross-identity tester.
func New(cfg *config.Config, db *graph.DB, v *vault.Vault, az *analyzer.Analyzer) *Tester {
	return &Tester{
		cfg:      cfg,
		db:       db,
		vault:    v,
		analyzer: az,
		client: &http.Client{
			Timeout: cfg.Testing.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		rateLimit: make(chan struct{}, cfg.Testing.RateLimit),
	}
}

// Run executes the full cross-identity testing suite.
func (t *Tester) Run() error {
	// Get all endpoints
	endpoints, err := t.db.ListEndpoints()
	if err != nil {
		return fmt.Errorf("listing endpoints: %w", err)
	}

	if len(endpoints) == 0 {
		fmt.Println("[!] No endpoints in resource graph. Run 'bola proxy' or 'bola import' first.")
		return nil
	}

	// Start rate limiter
	t.ticker = time.NewTicker(time.Second / time.Duration(t.cfg.Testing.RateLimit))
	defer t.ticker.Stop()

	// Process endpoints with worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, t.cfg.Testing.Workers)

	for _, ep := range endpoints {
		wg.Add(1)
		sem <- struct{}{} // acquire worker slot

		go func(ep *graph.Endpoint) {
			defer wg.Done()
			defer func() { <-sem }() // release worker slot

			if err := t.testEndpoint(ep); err != nil {
				fmt.Printf("[!] Error testing %s %s: %v\n", ep.Method, ep.Path, err)
			}
		}(ep)
	}

	wg.Wait()

	fmt.Printf("[*] Tests completed: %d tests run, %d potential findings\n", t.testsRun, t.findingsFound)
	return nil
}

// testEndpoint tests a single endpoint across all identity pairs.
func (t *Tester) testEndpoint(ep *graph.Endpoint) error {
	// Get all resources for this endpoint
	resources, err := t.db.GetResourcesByEndpoint(ep.ID)
	if err != nil {
		return fmt.Errorf("getting resources: %w", err)
	}

	// Group resources by identity
	identityResources := make(map[string][]*graph.Resource)
	for _, r := range resources {
		identityResources[r.Identity] = append(identityResources[r.Identity], r)
	}

	identities := t.vault.List()

	// For each identity that owns resources, test with every other identity
	for ownerName, ownerResources := range identityResources {
		// Get the original request for this endpoint+identity
		origRequests, err := t.db.GetRequestsByEndpointAndIdentity(ep.ID, ownerName)
		if err != nil || len(origRequests) == 0 {
			continue
		}
		origReq := origRequests[0]

		for _, testerName := range identities {
			if testerName == ownerName {
				continue
			}

			// Don't test admin → admin
			ownerID, _ := t.vault.Get(ownerName)
			testerID, _ := t.vault.Get(testerName)
			if ownerID != nil && testerID != nil && ownerID.Role == testerID.Role && ownerID.Role == "admin" {
				continue
			}

			// Check parent chain accessibility first
			accessible := true
			for _, r := range ownerResources {
				if !t.checkParentAccess(r.ID, testerName) {
					accessible = false
					break
				}
			}
			if !accessible {
				continue
			}

			// Replay the request with tester's identity
			testResult, err := t.replayRequest(origReq, testerName)
			if err != nil {
				continue
			}

			t.mu.Lock()
			t.testsRun++
			t.mu.Unlock()

			// Analyze the response pair
			pair := &graph.TestPair{
				OriginalRequest: origReq,
				TestRequest:     testResult,
				OwnerIdentity:   ownerName,
				TesterIdentity:  testerName,
				EndpointID:      ep.ID,
			}

			result := t.analyzer.Analyze(pair)

			if result.BOLA {
				t.mu.Lock()
				t.findingsFound++
				t.mu.Unlock()

				// Build curl command for reproduction
				curlCmd := buildCurlCommand(origReq, testerName, t.vault)

				// Store finding
				_, err := t.db.InsertFinding(&graph.Finding{
					EndpointID:      ep.ID,
					OwnerIdentity:   ownerName,
					TesterIdentity:  testerName,
					OwnerStatus:     origReq.StatusCode,
					TesterStatus:    testResult.StatusCode,
					SizeDelta:       result.SizeDelta,
					Similarity:      result.Similarity,
					ConfidenceLevel: result.Confidence,
					CurlCommand:     curlCmd,
					Notes:           result.Notes,
				})
				if err != nil {
					fmt.Printf("[!] Error storing finding: %v\n", err)
				}
			}
		}
	}

	return nil
}

// replayRequest replays an original request using a different identity.
func (t *Tester) replayRequest(orig *graph.CapturedRequest, testerName string) (*graph.CapturedRequest, error) {
	// Rate limit
	<-t.ticker.C

	// Build the request
	var body io.Reader
	if len(orig.Body) > 0 {
		body = bytes.NewReader(orig.Body)
	}

	req, err := http.NewRequest(orig.Method, orig.URL, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Restore original headers
	var headers map[string]string
	if err := json.Unmarshal([]byte(orig.Headers), &headers); err == nil {
		for k, v := range headers {
			// Skip auth headers — we'll set the tester's
			lower := strings.ToLower(k)
			if lower == "authorization" || lower == "cookie" {
				continue
			}
			req.Header.Set(k, v)
		}
	}

	// Apply tester's authentication
	if err := t.vault.ApplyAuth(req, testerName); err != nil {
		return nil, fmt.Errorf("applying auth: %w", err)
	}

	// Execute with retry
	var resp *http.Response
	for attempt := 0; attempt <= t.cfg.Testing.Retry; attempt++ {
		resp, err = t.client.Do(req)
		if err == nil {
			break
		}
		if attempt < t.cfg.Testing.Retry {
			time.Sleep(time.Second * time.Duration(attempt+1))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	respHeaders, _ := json.Marshal(headerMap(resp.Header))

	return &graph.CapturedRequest{
		EndpointID:      orig.EndpointID,
		Identity:        testerName,
		Method:          orig.Method,
		URL:             orig.URL,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: string(respHeaders),
		ResponseBody:    respBody,
		ResponseSize:    len(respBody),
	}, nil
}

// checkParentAccess verifies that a tester can access parent resources.
func (t *Tester) checkParentAccess(resourceID int64, testerName string) bool {
	parents, err := t.db.GetParentChain(resourceID)
	if err != nil || len(parents) == 0 {
		return true // No parents = no chain to check
	}

	for _, parent := range parents {
		requests, err := t.db.GetRequestsByEndpointAndIdentity(parent.EndpointID, parent.Identity)
		if err != nil || len(requests) == 0 {
			continue
		}

		testResult, err := t.replayRequest(requests[0], testerName)
		if err != nil {
			return false
		}

		if testResult.StatusCode == 401 || testResult.StatusCode == 403 {
			return false // Tester can't access parent
		}
	}

	return true
}

// buildCurlCommand generates a curl command to reproduce a finding.
func buildCurlCommand(orig *graph.CapturedRequest, testerName string, v *vault.Vault) string {
	parts := []string{"curl", "-X", orig.Method}

	// Add tester's auth headers
	testerID, err := v.Get(testerName)
	if err == nil {
		for k, val := range testerID.Headers {
			parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", k, val))
		}
		for _, c := range testerID.Cookies {
			parts = append(parts, "-b", fmt.Sprintf("'%s=%s'", c.Name, c.Value))
		}
	}

	// Add content type
	parts = append(parts, "-H", "'Content-Type: application/json'")

	// Add body if present
	if len(orig.Body) > 0 {
		parts = append(parts, "-d", fmt.Sprintf("'%s'", string(orig.Body)))
	}

	parts = append(parts, fmt.Sprintf("'%s'", orig.URL))

	return strings.Join(parts, " \\\n  ")
}

// headerMap converts http.Header to map[string]string.
func headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}
