// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package proxy provides the MITM HTTP/HTTPS proxy engine for bola.
package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

	"github.com/elazarl/goproxy"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

// Proxy is a MITM HTTP/HTTPS proxy for traffic capture and resource graph building.
type Proxy struct {
	cfg    *config.Config
	db     *graph.DB
	vault  *vault.Vault
	server *http.Server
	proxy  *goproxy.ProxyHttpServer

	requestCount atomic.Int64
	idCount      atomic.Int64
}

// New creates a new MITM proxy engine.
func New(cfg *config.Config, db *graph.DB, v *vault.Vault) (*Proxy, error) {
	gp := goproxy.NewProxyHttpServer()
	gp.Verbose = false
	gp.Logger = log.New(io.Discard, "", 0)

	p := &Proxy{
		cfg:   cfg,
		db:    db,
		vault: v,
		proxy: gp,
	}

	// Set up response handler
	gp.OnResponse().DoFunc(p.onResponse)

	return p, nil
}

// Start begins listening for proxy connections.
func (p *Proxy) Start() error {
	p.server = &http.Server{
		Addr:    p.cfg.Proxy.Listen,
		Handler: p.proxy,
	}

	slog.Info("proxy: listening", "addr", p.cfg.Proxy.Listen)
	return p.server.ListenAndServe()
}

// Stop gracefully shuts down the proxy server.
func (p *Proxy) Stop() {
	if p.server != nil {
		_ = p.server.Close()
	}
}

// onResponse processes each HTTP response captured by the proxy.
func (p *Proxy) onResponse(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if resp == nil || ctx.Req == nil {
		return resp
	}

	req := ctx.Req
	parsedURL := req.URL
	if parsedURL.Host == "" {
		parsedURL.Host = req.Host
	}

	// Check scope
	if !InScope(parsedURL.Path, p.cfg.Target.Scope.Include, p.cfg.Target.Scope.Exclude) {
		return resp
	}

	// Identify which user is making this request
	identity := p.vault.IdentifyRequest(req)
	if identity == "" {
		return resp
	}

	// Read response body (but put it back)
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp
	}
	resp.Body = io.NopCloser(strings.NewReader(string(respBody)))

	// Normalize path and register endpoint
	normalizedPath := NormalizePath(parsedURL.Path)
	endpointID, err := p.db.InsertEndpoint(req.Method, normalizedPath, parsedURL.Path)
	if err != nil {
		slog.Error("proxy: inserting endpoint", "error", err)
		return resp
	}

	// Read request body
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
	}

	// Store captured request
	reqHeaders := headerMapFromHTTP(req.Header)
	reqHeadersJSON, _ := json.Marshal(reqHeaders)
	respHeadersJSON, _ := json.Marshal(headerMapFromHTTP(resp.Header))

	_, err = p.db.InsertRequest(&graph.CapturedRequest{
		EndpointID:      endpointID,
		Identity:        identity,
		Method:          req.Method,
		URL:             fullURL(parsedURL),
		Headers:         string(reqHeadersJSON),
		Body:            reqBody,
		StatusCode:      resp.StatusCode,
		ResponseHeaders: string(respHeadersJSON),
		ResponseBody:    respBody,
		ResponseSize:    len(respBody),
	})
	if err != nil {
		slog.Error("proxy: inserting request", "error", err)
	}

	// Extract object IDs
	ids := ExtractAll(parsedURL, respBody, resp.Header)
	prevResourceIDs := make([]int64, 0)

	for _, oid := range ids {
		resourceID, err := p.db.InsertResource(endpointID, identity, oid.Value, string(oid.Type), oid.Location, oid.Key)
		if err != nil {
			continue
		}
		for _, parentID := range prevResourceIDs {
			_ = p.db.InsertRelationship(parentID, resourceID)
		}
		if oid.Location == "path" {
			prevResourceIDs = append(prevResourceIDs, resourceID)
		}
		p.idCount.Add(1)
	}

	p.requestCount.Add(1)

	slog.Info("proxy: captured",
		"method", req.Method,
		"path", parsedURL.Path,
		"identity", identity,
		"status", resp.StatusCode,
		"ids", len(ids),
	)

	return resp
}

// headerMapFromHTTP converts http.Header to map[string]string.
func headerMapFromHTTP(h http.Header) map[string]string {
	m := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// fullURL reconstructs the full URL string.
func fullURL(u *url.URL) string {
	s := u.String()
	if !strings.HasPrefix(s, "http") {
		scheme := "https"
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		s = fmt.Sprintf("%s://%s%s", scheme, u.Host, u.RequestURI())
	}
	return s
}
