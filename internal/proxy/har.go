// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package proxy

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

// HAR 1.2 structures for parsing Burp/ZAP exports.

// HAR is the top-level HAR 1.2 file structure.
type HAR struct {
	Log HARLog `json:"log"`
}

// HARLog contains the HAR entries.
type HARLog struct {
	Version string     `json:"version"`
	Entries []HAREntry `json:"entries"`
}

// HAREntry represents a single HTTP exchange in a HAR file.
type HAREntry struct {
	Request  HARRequest  `json:"request"`
	Response HARResponse `json:"response"`
}

// HARRequest represents the request portion of a HAR entry.
type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Headers     []HARHeader `json:"headers"`
	QueryString []HARQuery  `json:"queryString"`
	PostData    *HARPost    `json:"postData,omitempty"`
	Cookies     []HARCookie `json:"cookies"`
}

// HARResponse represents the response portion of a HAR entry.
type HARResponse struct {
	Status  int         `json:"status"`
	Headers []HARHeader `json:"headers"`
	Content HARContent  `json:"content"`
}

// HARHeader is a name-value header pair.
type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARQuery is a query string parameter.
type HARQuery struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARPost represents POST/PUT request body data.
type HARPost struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HARContent represents the response body.
type HARContent struct {
	Size     int    `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HARCookie represents a cookie in the HAR entry.
type HARCookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ImportHAR parses a HAR file and populates the resource graph.
func ImportHAR(harPath string, cfg *config.Config, db *graph.DB, v *vault.Vault) (int, error) {
	data, err := os.ReadFile(harPath)
	if err != nil {
		return 0, fmt.Errorf("proxy: reading HAR file: %w", err)
	}

	var har HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return 0, fmt.Errorf("proxy: parsing HAR JSON: %w", err)
	}

	imported := 0
	for _, entry := range har.Log.Entries {
		parsedURL, err := url.Parse(entry.Request.URL)
		if err != nil {
			slog.Debug("proxy: skipping invalid URL in HAR", "url", entry.Request.URL)
			continue
		}

		// Check scope
		if !InScope(parsedURL.Path, cfg.Target.Scope.Include, cfg.Target.Scope.Exclude) {
			continue
		}

		// Build headers map
		headers := make(map[string]string)
		for _, h := range entry.Request.Headers {
			headers[h.Name] = h.Value
		}

		// Identify which identity this request belongs to
		identity := identifyFromHAR(entry, v)
		if identity == "" {
			slog.Debug("proxy: unidentified HAR entry", "url", entry.Request.URL)
			identity = "unknown"
		}

		// Normalize path
		normalizedPath := NormalizePath(parsedURL.Path)

		// Insert endpoint
		endpointID, err := db.InsertEndpoint(entry.Request.Method, normalizedPath, parsedURL.Path)
		if err != nil {
			slog.Error("proxy: inserting endpoint from HAR", "error", err)
			continue
		}

		// Get request body
		var bodyBytes []byte
		if entry.Request.PostData != nil {
			bodyBytes = []byte(entry.Request.PostData.Text)
		}

		// Store headers as JSON
		headersJSON, _ := json.Marshal(headers)

		// Get response headers
		respHeaders := make(http.Header)
		for _, h := range entry.Response.Headers {
			respHeaders.Set(h.Name, h.Value)
		}

		respBody := []byte(entry.Response.Content.Text)

		// Insert captured request
		_, err = db.InsertRequest(&graph.CapturedRequest{
			EndpointID:      endpointID,
			Identity:        identity,
			Method:          entry.Request.Method,
			URL:             entry.Request.URL,
			Headers:         string(headersJSON),
			Body:            bodyBytes,
			StatusCode:      entry.Response.Status,
			ResponseHeaders: marshalHeaders(respHeaders),
			ResponseBody:    respBody,
			ResponseSize:    len(respBody),
		})
		if err != nil {
			slog.Error("proxy: inserting request from HAR", "error", err)
			continue
		}

		// Extract object IDs from URL and response body
		ids := ExtractAll(parsedURL, respBody, respHeaders)
		prevResourceIDs := make([]int64, 0)

		for _, oid := range ids {
			resourceID, err := db.InsertResource(endpointID, identity, oid.Value, string(oid.Type), oid.Location, oid.Key)
			if err != nil {
				continue
			}

			// Create parent-child relationships from path hierarchy
			for _, parentID := range prevResourceIDs {
				_ = db.InsertRelationship(parentID, resourceID)
			}
			if oid.Location == "path" {
				prevResourceIDs = append(prevResourceIDs, resourceID)
			}
		}

		imported++
		slog.Debug("proxy: imported HAR entry",
			"method", entry.Request.Method,
			"url", parsedURL.Path,
			"identity", identity,
			"ids_found", len(ids),
		)
	}

	return imported, nil
}

// identifyFromHAR matches a HAR entry to a vault identity by comparing auth headers/cookies.
func identifyFromHAR(entry HAREntry, v *vault.Vault) string {
	req, err := http.NewRequest(entry.Request.Method, entry.Request.URL, nil)
	if err != nil {
		return ""
	}

	for _, h := range entry.Request.Headers {
		req.Header.Set(h.Name, h.Value)
	}

	for _, c := range entry.Request.Cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}

	return v.IdentifyRequest(req)
}

// marshalHeaders serializes http.Header to a JSON string.
func marshalHeaders(headers http.Header) string {
	m := make(map[string]string, len(headers))
	for k, v := range headers {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	data, _ := json.Marshal(m)
	return string(data)
}

// InScope checks if a path matches the include/exclude filter patterns.
func InScope(path string, include, exclude []string) bool {
	if len(include) == 0 {
		return true
	}

	inScope := false
	for _, pattern := range include {
		if MatchGlob(pattern, path) {
			inScope = true
			break
		}
	}
	if !inScope {
		return false
	}

	for _, pattern := range exclude {
		if MatchGlob(pattern, path) {
			return false
		}
	}

	return true
}

// MatchGlob performs a simple glob-style path match.
// Supports * as a wildcard for one or more path segments.
func MatchGlob(pattern, path string) bool {
	if pattern == path {
		return true
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix)
	}

	return false
}

// Ensure io import is used
var _ = io.ReadAll
