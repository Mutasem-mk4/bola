// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package proxy

import (
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// IDType represents the classification of an extracted object identifier.
type IDType string

const (
	IDTypeUUID    IDType = "uuid"
	IDTypeInteger IDType = "integer"
	IDTypeMongoID IDType = "mongoid"
	IDTypeHash    IDType = "hash"
)

// ObjectID represents an object identifier extracted from an HTTP exchange.
type ObjectID struct {
	Value    string // the actual ID value
	Type     IDType // uuid | integer | mongoid | hash
	Location string // path | query | body | header
	Key      string // the parameter or JSON key name
}

// Package-level compiled regex patterns for performance.
var (

	// Generic UUID: any version
	uuidGenericPattern = regexp.MustCompile(
		`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`,
	)
	// MongoDB ObjectID: exactly 24 hex chars
	mongoIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	// Integer ID: digits only, reasonable range (1 to 2^53)
	integerIDPattern = regexp.MustCompile(`^\d+$`)
	// UUID scanner for finding UUIDs within strings
	uuidScanPattern = regexp.MustCompile(
		`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
	)

	// JSON keys that commonly contain object IDs
	idKeyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)^id$`),
		regexp.MustCompile(`(?i)_id$`),
		regexp.MustCompile(`(?i)Id$`),
		regexp.MustCompile(`(?i)^uuid$`),
		regexp.MustCompile(`(?i)Uuid$`),
		regexp.MustCompile(`(?i)^oid$`),
		regexp.MustCompile(`(?i)^key$`),
		regexp.MustCompile(`(?i)^slug$`),
		regexp.MustCompile(`(?i)^ref$`),
		regexp.MustCompile(`(?i)^resource_id$`),
		regexp.MustCompile(`(?i)^object_id$`),
	}
)

const maxIntegerID = 1 << 53 // JavaScript safe integer limit

// ExtractAll extracts all object IDs from a URL, response body, and headers.
func ExtractAll(reqURL *url.URL, body []byte, respHeaders http.Header) []ObjectID {
	var results []ObjectID
	results = append(results, ExtractFromURL(reqURL)...)
	results = append(results, ExtractFromBody(body, respHeaders.Get("Content-Type"))...)
	results = append(results, ExtractFromHeaders(respHeaders)...)
	return dedupExtracted(results)
}

// ExtractFromURL extracts object IDs from URL path segments and query parameters.
func ExtractFromURL(u *url.URL) []ObjectID {
	var results []ObjectID
	results = append(results, extractFromPath(u.Path)...)
	results = append(results, extractFromQuery(u.Query())...)
	return results
}

// extractFromPath extracts object IDs from URL path segments.
func extractFromPath(path string) []ObjectID {
	var results []ObjectID
	segments := strings.Split(strings.Trim(path, "/"), "/")

	for i, seg := range segments {
		if seg == "" {
			continue
		}

		idType := ClassifyID(seg)
		if idType == "" {
			continue
		}

		// Infer key from previous path segment (resource name)
		key := ""
		if i > 0 {
			key = segments[i-1]
		}

		results = append(results, ObjectID{
			Value:    seg,
			Type:     idType,
			Location: "path",
			Key:      key,
		})
	}

	return results
}

// extractFromQuery extracts object IDs from URL query parameters.
func extractFromQuery(params url.Values) []ObjectID {
	var results []ObjectID

	for key, values := range params {
		for _, val := range values {
			if val == "" {
				continue
			}
			// Prioritize keys that look like ID params
			idType := ClassifyID(val)
			if idType == "" && isIDKey(key) {
				// Even if the value doesn't match standard patterns,
				// if the key strongly suggests an ID, classify as hash
				if len(val) >= 8 {
					idType = IDTypeHash
				}
			}
			if idType == "" {
				continue
			}
			results = append(results, ObjectID{
				Value:    val,
				Type:     idType,
				Location: "query",
				Key:      key,
			})
		}
	}

	return results
}

// ExtractFromBody extracts object IDs from a response body.
func ExtractFromBody(body []byte, contentType string) []ObjectID {
	if len(body) == 0 {
		return nil
	}

	// Only parse JSON bodies
	if !strings.Contains(contentType, "json") && !isJSON(body) {
		return nil
	}

	var results []ObjectID

	// Try parsing as JSON object
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err == nil {
		results = append(results, extractFromMap(obj, "")...)
		return results
	}

	// Try parsing as JSON array
	var arr []interface{}
	if err := json.Unmarshal(body, &arr); err == nil {
		limit := 5 // Only inspect first 5 items to avoid performance issues
		if len(arr) < limit {
			limit = len(arr)
		}
		for i := 0; i < limit; i++ {
			if m, ok := arr[i].(map[string]interface{}); ok {
				results = append(results, extractFromMap(m, "")...)
			}
		}
	}

	return results
}

// extractFromMap recursively traverses a JSON object to find ID-like values.
func extractFromMap(obj map[string]interface{}, prefix string) []ObjectID {
	var results []ObjectID

	for key, val := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			idType := ClassifyID(v)
			if idType != "" || isIDKey(key) {
				if idType == "" && len(v) >= 4 {
					idType = IDTypeHash
				}
				if idType != "" {
					results = append(results, ObjectID{
						Value:    v,
						Type:     idType,
						Location: "body",
						Key:      fullKey,
					})
				}
			}
		case float64:
			if isIDKey(key) && v > 0 && v < maxIntegerID && v == math.Floor(v) {
				results = append(results, ObjectID{
					Value:    formatInt(int64(v)),
					Type:     IDTypeInteger,
					Location: "body",
					Key:      fullKey,
				})
			}
		case map[string]interface{}:
			if strings.Count(fullKey, ".") < 5 {
				results = append(results, extractFromMap(v, fullKey)...)
			}
		case []interface{}:
			limit := 3
			if len(v) < limit {
				limit = len(v)
			}
			for i := 0; i < limit; i++ {
				if m, ok := v[i].(map[string]interface{}); ok {
					results = append(results, extractFromMap(m, fullKey+"[]")...)
				}
			}
		}
	}

	return results
}

// ExtractFromHeaders extracts object IDs from HTTP response headers.
func ExtractFromHeaders(headers http.Header) []ObjectID {
	var results []ObjectID

	interestingHeaders := []string{"Location", "X-Request-Id", "X-Resource-Id", "ETag"}
	for _, h := range interestingHeaders {
		val := headers.Get(h)
		if val == "" {
			continue
		}

		// Scan for UUIDs in header values
		if matches := uuidScanPattern.FindAllString(val, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, ObjectID{
					Value:    m,
					Type:     IDTypeUUID,
					Location: "header",
					Key:      h,
				})
			}
		}
	}

	return results
}

// ClassifyID determines the type of an identifier string.
// Returns empty string if the value doesn't look like an ID.
func ClassifyID(val string) IDType {
	if val == "" {
		return ""
	}

	if uuidGenericPattern.MatchString(val) {
		return IDTypeUUID
	}

	if mongoIDPattern.MatchString(val) {
		return IDTypeMongoID
	}

	if integerIDPattern.MatchString(val) && len(val) <= 16 && len(val) >= 1 {
		return IDTypeInteger
	}

	// Long alphanumeric strings might be hashes/tokens
	if len(val) >= 16 && isAlphanumeric(val) {
		return IDTypeHash
	}

	return ""
}

// NormalizePath replaces ID-like segments with type placeholders.
func NormalizePath(path string) string {
	segments := strings.Split(path, "/")
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		switch ClassifyID(seg) {
		case IDTypeUUID:
			segments[i] = "{uuid}"
		case IDTypeInteger:
			segments[i] = "{id}"
		case IDTypeMongoID:
			segments[i] = "{mongoid}"
		case IDTypeHash:
			segments[i] = "{hash}"
		}
	}
	return strings.Join(segments, "/")
}

// isIDKey checks if a JSON key name looks like an identifier field.
func isIDKey(key string) bool {
	for _, pattern := range idKeyPatterns {
		if pattern.MatchString(key) {
			return true
		}
	}
	return false
}

// isAlphanumeric checks if a string contains only alphanumeric characters.
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// isJSON checks if a byte slice starts with a JSON-like character.
func isJSON(data []byte) bool {
	for _, b := range data {
		if b == ' ' || b == '\t' || b == '\n' || b == '\r' {
			continue
		}
		return b == '{' || b == '['
	}
	return false
}

// formatInt converts an int64 to string without importing strconv.
func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	buf := make([]byte, 0, 20)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return string(buf)
}

// dedupExtracted removes duplicate extracted IDs.
func dedupExtracted(ids []ObjectID) []ObjectID {
	seen := make(map[string]bool)
	var result []ObjectID
	for _, id := range ids {
		key := id.Location + ":" + id.Key + ":" + id.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, id)
		}
	}
	return result
}
