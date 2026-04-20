// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package tester implements the cross-identity authorization replay engine
// with rate limiting, jitter, progress tracking, and parent-chain verification.
package tester

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/time/rate"

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
	client   *http.Client
	limiter  *rate.Limiter

	// Stats
	testsRun      atomic.Int64
	findingsFound atomic.Int64
}

// New creates a new cross-identity tester.
func New(cfg *config.Config, db *graph.DB, v *vault.Vault) *Tester {
	return &Tester{
		cfg:   cfg,
		db:    db,
		vault: v,
		client: &http.Client{
			Timeout: cfg.Testing.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
		limiter: rate.NewLimiter(rate.Limit(cfg.Testing.RateLimit), 1),
	}
}

// Run executes the full cross-identity testing suite.
func (t *Tester) Run(ctx context.Context) error {
	endpoints, err := t.db.ListEndpoints()
	if err != nil {
		return fmt.Errorf("tester: listing endpoints: %w", err)
	}

	if len(endpoints) == 0 {
		slog.Warn("tester: no endpoints in resource graph — run 'bola proxy' or 'bola import' first")
		return nil
	}

	// Calculate total test pairs for progress bar
	identityCount := len(t.vault.List())
	totalPairs := int64(0)
	for _, ep := range endpoints {
		resources, _ := t.db.GetResourcesByEndpoint(ep.ID)
		identityResources := make(map[string]bool)
		for _, r := range resources {
			identityResources[r.Identity] = true
		}
		totalPairs += int64(len(identityResources)) * int64(identityCount-1)
	}

	bar := progressbar.NewOptions64(totalPairs,
		progressbar.OptionSetDescription("Scanning"),
		progressbar.OptionSetTheme(progressbar.Theme{Saucer: "█", SaucerPadding: "░", BarStart: "[", BarEnd: "]"}),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetWidth(40),
	)

	// Process endpoints with worker pool
	var wg sync.WaitGroup
	sem := make(chan struct{}, t.cfg.Testing.Workers)

	for _, ep := range endpoints {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(ep *graph.Endpoint) {
			defer wg.Done()
			defer func() { <-sem }()

			tested, err := t.testEndpoint(ctx, ep)
			if err != nil {
				slog.Error("tester: endpoint test failed",
					"method", ep.Method,
					"path", ep.Path,
					"error", err,
				)
			}
			_ = bar.Add(int(tested))
		}(ep)
	}

	wg.Wait()
	_ = bar.Finish()

	fmt.Printf("\n[*] Tests completed: %d tests run, %d potential findings\n",
		t.testsRun.Load(), t.findingsFound.Load())

	return nil
}

// testEndpoint tests a single endpoint across all identity pairs.
func (t *Tester) testEndpoint(ctx context.Context, ep *graph.Endpoint) (int64, error) {
	resources, err := t.db.GetResourcesByEndpoint(ep.ID)
	if err != nil {
		return 0, fmt.Errorf("tester: getting resources: %w", err)
	}

	// Group resources by identity
	identityResources := make(map[string][]*graph.Resource)
	for _, r := range resources {
		identityResources[r.Identity] = append(identityResources[r.Identity], r)
	}

	identities := t.vault.List()
	var tested int64

	for ownerName := range identityResources {
		origRequests, err := t.db.GetRequestsByEndpointAndIdentity(ep.ID, ownerName)
		if err != nil || len(origRequests) == 0 {
			tested += int64(len(identities) - 1)
			continue
		}
		origReq := origRequests[0]

		for _, testerName := range identities {
			if ctx.Err() != nil {
				return tested, ctx.Err()
			}

			if testerName == ownerName {
				continue
			}
			tested++

			// Skip admin→admin (same role, same privileges)
			ownerID, _ := t.vault.Get(ownerName)
			testerID, _ := t.vault.Get(testerName)
			if ownerID != nil && testerID != nil &&
				ownerID.Role == testerID.Role && ownerID.Role == "admin" {
				continue
			}

			// Check parent chain accessibility
			for _, r := range identityResources[ownerName] {
				if !t.checkParentAccess(ctx, r.ID, testerName) {
					continue
				}
			}

			// Rate limit + jitter
			if err := t.limiter.Wait(ctx); err != nil {
				return tested, err
			}
			if t.cfg.Testing.Jitter {
				jitter := time.Duration(rand.Int63n(100)) * time.Millisecond
				time.Sleep(jitter)
			}

			// Replay the request with tester's identity
			testResult, err := t.replayRequest(ctx, origReq, testerName)
			if err != nil {
				slog.Debug("tester: replay failed",
					"endpoint", origReq.URL,
					"tester", testerName,
					"error", err,
				)
				continue
			}

			t.testsRun.Add(1)

			// Analyze the response pair
			finding := analyzer.Analyze(origReq, testResult, t.cfg)
			if finding == nil {
				continue
			}

			// Check minimum confidence filter
			if !meetsMinConfidence(finding.Confidence, t.cfg.Analysis.MinConfidence) {
				continue
			}

			t.findingsFound.Add(1)

			curlCmd := BuildCurlCommand(origReq, testerName, t.vault)

			_, err = t.db.InsertFinding(&graph.Finding{
				EndpointID:      ep.ID,
				OwnerIdentity:   ownerName,
				TesterIdentity:  testerName,
				OwnerStatus:     origReq.StatusCode,
				TesterStatus:    testResult.StatusCode,
				SizeDelta:       finding.SizeDelta,
				Similarity:      finding.KeySimilarity,
				ConfidenceLevel: graph.Confidence(finding.Confidence),
				CurlCommand:     curlCmd,
				Notes:           finding.Notes,
			})
			if err != nil {
				slog.Error("tester: storing finding failed", "error", err)
			}
		}
	}

	return tested, nil
}

// replayRequest replays an original request using a different identity.
func (t *Tester) replayRequest(ctx context.Context, orig *graph.CapturedRequest, testerName string) (*graph.CapturedRequest, error) {
	var body io.Reader
	if len(orig.Body) > 0 {
		body = bytes.NewReader(orig.Body)
	}

	req, err := http.NewRequestWithContext(ctx, orig.Method, orig.URL, body)
	if err != nil {
		return nil, fmt.Errorf("tester: creating request: %w", err)
	}

	// Restore original headers (except auth)
	var headers map[string]string
	if err := json.Unmarshal([]byte(orig.Headers), &headers); err == nil {
		for k, v := range headers {
			lower := strings.ToLower(k)
			if lower == "authorization" || lower == "cookie" {
				continue
			}
			req.Header.Set(k, v)
		}
	}

	// Apply tester's authentication
	if err := t.vault.InjectAuth(req, testerName); err != nil {
		return nil, fmt.Errorf("tester: injecting auth: %w", err)
	}

	// Execute with retry
	var resp *http.Response
	for attempt := 0; attempt <= t.cfg.Testing.Retry; attempt++ {
		resp, err = t.client.Do(req)
		if err == nil {
			break
		}
		if attempt < t.cfg.Testing.Retry {
			backoff := time.Second * time.Duration(attempt+1)
			slog.Debug("tester: retrying request",
				"attempt", attempt+1,
				"backoff", backoff,
				"error", err,
			)
			time.Sleep(backoff)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("tester: executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("tester: reading response: %w", err)
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
func (t *Tester) checkParentAccess(ctx context.Context, resourceID int64, testerName string) bool {
	parents, err := t.db.GetParentChain(resourceID)
	if err != nil || len(parents) == 0 {
		return true // No parents = no chain to verify
	}

	for _, parent := range parents {
		requests, err := t.db.GetRequestsByEndpointAndIdentity(parent.EndpointID, parent.Identity)
		if err != nil || len(requests) == 0 {
			continue
		}

		testResult, err := t.replayRequest(ctx, requests[0], testerName)
		if err != nil {
			return false
		}

		if testResult.StatusCode == 401 || testResult.StatusCode == 403 {
			slog.Debug("tester: parent access denied, skipping child",
				"parent_endpoint", requests[0].URL,
				"tester", testerName,
			)
			return false
		}
	}

	return true
}

// BuildCurlCommand generates a curl command to reproduce a finding.
func BuildCurlCommand(orig *graph.CapturedRequest, testerName string, v *vault.Vault) string {
	parts := []string{"curl", "-X", orig.Method}

	testerID, err := v.Get(testerName)
	if err == nil {
		for k, val := range testerID.Headers {
			parts = append(parts, "-H", fmt.Sprintf("'%s: %s'", k, val))
		}
		for _, c := range testerID.Cookies {
			parts = append(parts, "-b", fmt.Sprintf("'%s=%s'", c.Name, c.Value))
		}
	}

	parts = append(parts, "-H", "'Content-Type: application/json'")

	if len(orig.Body) > 0 {
		parts = append(parts, "-d", fmt.Sprintf("'%s'", string(orig.Body)))
	}

	parts = append(parts, fmt.Sprintf("'%s'", orig.URL))

	return strings.Join(parts, " \\\n  ")
}

// meetsMinConfidence checks if a finding meets the minimum confidence threshold.
func meetsMinConfidence(finding, minimum string) bool {
	rank := map[string]int{"LOW": 1, "MEDIUM": 2, "HIGH": 3}
	return rank[finding] >= rank[minimum]
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

// Stats returns the current test statistics.
func (t *Tester) Stats() (testsRun, findingsFound int64) {
	return t.testsRun.Load(), t.findingsFound.Load()
}
