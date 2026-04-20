// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

// HARLog represents the top-level HAR 1.2 structure.
type HARLog struct {
	Log struct {
		Version string     `json:"version"`
		Entries []HAREntry `json:"entries"`
	} `json:"log"`
}

// HAREntry represents a single HTTP exchange in a HAR file.
type HAREntry struct {
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
}

// HARRequest represents an HTTP request in HAR format.
type HARRequest struct {
	Method      string           `json:"method"`
	URL         string           `json:"url"`
	Headers     []HARNameValue   `json:"headers"`
	QueryString []HARNameValue   `json:"queryString"`
	PostData    *HARPostData     `json:"postData,omitempty"`
	Cookies     []HARCookie      `json:"cookies"`
}

// HARResponse represents an HTTP response in HAR format.
type HARResponse struct {
	Status      int            `json:"status"`
	Headers     []HARNameValue `json:"headers"`
	Content     HARContent     `json:"content"`
}

// HARNameValue is a generic name-value pair used in HAR.
type HARNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARPostData represents POST request data.
type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HARContent represents response body content.
type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HARCookie represents a cookie in HAR format.
type HARCookie struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Domain string `json:"domain"`
	Path   string `json:"path"`
}

// ImportHAR reads a HAR file and populates the resource graph.
// Returns the number of entries processed.
func ImportHAR(path string, cfg *config.Config, db *graph.DB, v *vault.Vault) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening HAR file: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return 0, fmt.Errorf("reading HAR file: %w", err)
	}

	var har HARLog
	if err := json.Unmarshal(data, &har); err != nil {
		return 0, fmt.Errorf("parsing HAR file: %w", err)
	}

	count := 0
	for _, entry := range har.Log.Entries {
		if err := processHAREntry(entry, cfg, db, v); err != nil {
			// Log but continue processing other entries
			fmt.Printf("[!] Error processing HAR entry %s %s: %v\n",
				entry.Request.Method, entry.Request.URL, err)
			continue
		}
		count++
	}

	return count, nil
}

// processHAREntry processes a single HAR entry into the resource graph.
func processHAREntry(entry HAREntry, cfg *config.Config, db *graph.DB, v *vault.Vault) error {
	reqURL, err := url.Parse(entry.Request.URL)
	if err != nil {
		return fmt.Errorf("parsing URL: %w", err)
	}

	// Check scope
	if !isPathInScope(reqURL.Path, cfg) {
		return nil
	}

	method := entry.Request.Method
	rawPath := reqURL.Path
	normalizedPath := NormalizePath(rawPath)
	contentType := ""
	for _, h := range entry.Response.Headers {
		if strings.EqualFold(h.Name, "Content-Type") {
			contentType = h.Value
			break
		}
	}

	// Identify the user by matching request headers against vault identities
	identity := identifyHARRequest(entry.Request, v)

	// Upsert endpoint
	ep, err := db.UpsertEndpoint(method, normalizedPath, rawPath, contentType)
	if err != nil {
		return fmt.Errorf("upserting endpoint: %w", err)
	}

	// Build header maps
	reqHeaders := make(map[string]string)
	for _, h := range entry.Request.Headers {
		reqHeaders[h.Name] = h.Value
	}
	respHeaders := make(map[string]string)
	for _, h := range entry.Response.Headers {
		respHeaders[h.Name] = h.Value
	}

	reqHeadersJSON, _ := json.Marshal(reqHeaders)
	respHeadersJSON, _ := json.Marshal(respHeaders)

	var reqBody []byte
	if entry.Request.PostData != nil {
		reqBody = []byte(entry.Request.PostData.Text)
	}

	respBody := []byte(entry.Response.Content.Text)

	// Store captured request
	_, err = db.InsertRequest(&graph.CapturedRequest{
		EndpointID:      ep.ID,
		Identity:        identity,
		Method:          method,
		URL:             entry.Request.URL,
		Headers:         string(reqHeadersJSON),
		Body:            reqBody,
		StatusCode:      entry.Response.Status,
		ResponseHeaders: string(respHeadersJSON),
		ResponseBody:    respBody,
		ResponseSize:    len(respBody),
	})
	if err != nil {
		return fmt.Errorf("inserting request: %w", err)
	}

	// Extract object IDs
	respHdr := harHeadersToHTTP(entry.Response.Headers)
	extracted := ExtractAll(reqURL, respBody, respHdr)

	// Store resources
	for _, ext := range extracted {
		_, err := db.InsertResource(&graph.Resource{
			EndpointID: ep.ID,
			Identity:   identity,
			ObjectID:   ext.Value,
			IDType:     ext.Type,
			IDLocation: ext.Location,
			IDKey:      ext.Key,
		})
		if err != nil {
			continue
		}
	}

	return nil
}

// identifyHARRequest matches a HAR request against vault identities.
func identifyHARRequest(req HARRequest, v *vault.Vault) string {
	// Build an http.Request to use vault's IdentifyRequest
	httpReq, err := http.NewRequest(req.Method, req.URL, nil)
	if err != nil {
		return "unknown"
	}

	for _, h := range req.Headers {
		httpReq.Header.Set(h.Name, h.Value)
	}

	for _, c := range req.Cookies {
		httpReq.AddCookie(&http.Cookie{
			Name:  c.Name,
			Value: c.Value,
		})
	}

	if name := v.IdentifyRequest(httpReq); name != "" {
		return name
	}
	return "unknown"
}

// isPathInScope checks if a path is within the configured scope.
func isPathInScope(path string, cfg *config.Config) bool {
	if len(cfg.Target.Scope.Include) == 0 && len(cfg.Target.Scope.Exclude) == 0 {
		return true
	}

	for _, pattern := range cfg.Target.Scope.Exclude {
		if matchGlob(pattern, path) {
			return false
		}
	}

	if len(cfg.Target.Scope.Include) == 0 {
		return true
	}

	for _, pattern := range cfg.Target.Scope.Include {
		if matchGlob(pattern, path) {
			return true
		}
	}

	return false
}

// harHeadersToHTTP converts HAR headers to http.Header.
func harHeadersToHTTP(headers []HARNameValue) http.Header {
	h := make(http.Header)
	for _, nv := range headers {
		h.Set(nv.Name, nv.Value)
	}
	return h
}
