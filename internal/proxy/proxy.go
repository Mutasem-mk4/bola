// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package proxy provides the MITM HTTP/HTTPS proxy engine for bola.
// It captures traffic, extracts object IDs, and builds the resource graph.
package proxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/elazarl/goproxy"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

// Proxy wraps the goproxy MITM proxy with resource graph integration.
type Proxy struct {
	cfg    *config.Config
	db     *graph.DB
	vault  *vault.Vault
	server *http.Server
	proxy  *goproxy.ProxyHttpServer
	mu     sync.Mutex
}

// New creates a new MITM proxy instance.
func New(cfg *config.Config, db *graph.DB, v *vault.Vault) (*Proxy, error) {
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false

	// Load or generate CA certificate for HTTPS interception
	if cfg.Proxy.TLS.CACert != "" && cfg.Proxy.TLS.CAKey != "" {
		certPath := expandPath(cfg.Proxy.TLS.CACert)
		keyPath := expandPath(cfg.Proxy.TLS.CAKey)

		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("loading CA certificate: %w", err)
		}

		caCert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("parsing CA certificate: %w", err)
		}

		goproxy.GoproxyCa = cert
		goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(&cert)}
		_ = caCert // Used indirectly via goproxy.GoproxyCa
	}

	// Enable MITM for all HTTPS connections
	gp.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p := &Proxy{
		cfg:   cfg,
		db:    db,
		vault: v,
		proxy: gp,
	}

	// Install request/response handlers
	gp.OnRequest().DoFunc(p.handleRequest)
	gp.OnResponse().DoFunc(p.handleResponse)

	return p, nil
}

// Start begins listening for proxy connections.
func (p *Proxy) Start() error {
	p.server = &http.Server{
		Addr:    p.cfg.Proxy.Listen,
		Handler: p.proxy,
	}
	return p.server.ListenAndServe()
}

// Stop gracefully shuts down the proxy server.
func (p *Proxy) Stop() {
	if p.server != nil {
		p.server.Close()
	}
}

// handleRequest processes incoming HTTP requests through the proxy.
func (p *Proxy) handleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	// Check scope
	if !p.isInScope(req.URL.Path) {
		return req, nil
	}

	// Identify which user is making this request
	identity := p.vault.IdentifyRequest(req)
	if identity != "" {
		ctx.UserData = identity
	}

	return req, nil
}

// handleResponse processes HTTP responses and extracts resources.
func (p *Proxy) handleResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || ctx.Req == nil {
		return resp
	}

	// Check scope
	if !p.isInScope(ctx.Req.URL.Path) {
		return resp
	}

	identity, _ := ctx.UserData.(string)
	if identity == "" {
		identity = "unknown"
	}

	// Read response body (we need to buffer it for extraction)
	var bodyBytes []byte
	if resp.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[!] Error reading response body: %v", err)
			return resp
		}
		// Restore the body so the client still receives it
		resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	// Read request body if present
	var reqBodyBytes []byte
	if ctx.Req.Body != nil {
		reqBodyBytes, _ = io.ReadAll(ctx.Req.Body)
		ctx.Req.Body = io.NopCloser(bytes.NewReader(reqBodyBytes))
	}

	// Process in background to avoid slowing down the proxy
	go func() {
		p.mu.Lock()
		defer p.mu.Unlock()

		if err := p.processResponse(ctx.Req, resp, identity, bodyBytes, reqBodyBytes); err != nil {
			log.Printf("[!] Error processing response: %v", err)
		}
	}()

	return resp
}

// processResponse extracts resources and stores the request/response in the database.
func (p *Proxy) processResponse(req *http.Request, resp *http.Response, identity string, bodyBytes, reqBodyBytes []byte) error {
	rawPath := req.URL.Path
	method := req.Method
	contentType := resp.Header.Get("Content-Type")

	// Normalize the path
	normalizedPath := NormalizePath(rawPath)

	// Upsert endpoint
	ep, err := p.db.UpsertEndpoint(method, normalizedPath, rawPath, contentType)
	if err != nil {
		return fmt.Errorf("upserting endpoint: %w", err)
	}

	// Serialize headers
	reqHeaders, _ := json.Marshal(headerMap(req.Header))
	respHeaders, _ := json.Marshal(headerMap(resp.Header))

	// Store the captured request/response
	_, err = p.db.InsertRequest(&graph.CapturedRequest{
		EndpointID:      ep.ID,
		Identity:        identity,
		Method:          method,
		URL:             req.URL.String(),
		Headers:         string(reqHeaders),
		Body:            reqBodyBytes,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: string(respHeaders),
		ResponseBody:    bodyBytes,
		ResponseSize:    len(bodyBytes),
	})
	if err != nil {
		return fmt.Errorf("inserting request: %w", err)
	}

	// Extract object IDs from the response
	extracted := ExtractAll(req.URL, bodyBytes, resp.Header)

	// Store extracted resources
	var resourceIDs []int64
	for _, ext := range extracted {
		rid, err := p.db.InsertResource(&graph.Resource{
			EndpointID: ep.ID,
			Identity:   identity,
			ObjectID:   ext.Value,
			IDType:     ext.Type,
			IDLocation: ext.Location,
			IDKey:      ext.Key,
		})
		if err != nil {
			log.Printf("[!] Error inserting resource: %v", err)
			continue
		}
		resourceIDs = append(resourceIDs, rid)
	}

	// Build parent-child relationships from path hierarchy
	pathResources := filterByLocation(extracted, "path")
	if len(pathResources) > 1 && len(resourceIDs) >= len(pathResources) {
		for i := 1; i < len(pathResources); i++ {
			parentIdx := i - 1
			if parentIdx < len(resourceIDs) && i < len(resourceIDs) {
				_ = p.db.InsertRelationship(resourceIDs[parentIdx], resourceIDs[i], parentIdx)
			}
		}
	}

	return nil
}

// isInScope checks whether a request path matches the configured scope.
func (p *Proxy) isInScope(path string) bool {
	// If no scope configured, everything is in scope
	if len(p.cfg.Target.Scope.Include) == 0 && len(p.cfg.Target.Scope.Exclude) == 0 {
		return true
	}

	// Check excludes first
	for _, pattern := range p.cfg.Target.Scope.Exclude {
		if matchGlob(pattern, path) {
			return false
		}
	}

	// If no includes specified, default to all
	if len(p.cfg.Target.Scope.Include) == 0 {
		return true
	}

	// Check includes
	for _, pattern := range p.cfg.Target.Scope.Include {
		if matchGlob(pattern, path) {
			return true
		}
	}

	return false
}

// matchGlob performs simple glob matching (supports * as wildcard).
func matchGlob(pattern, path string) bool {
	// Simple glob: /api/v1/* matches /api/v1/anything
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}
	return path == pattern
}

// headerMap converts http.Header to map[string]string (first value only).
func headerMap(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// filterByLocation filters extracted IDs by their source location.
func filterByLocation(extracted []ExtractedID, location string) []ExtractedID {
	var result []ExtractedID
	for _, e := range extracted {
		if e.Location == location {
			result = append(result, e)
		}
	}
	return result
}

// expandPath expands ~ to the user's home directory.
func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
