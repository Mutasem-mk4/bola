// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package proxy

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// ExtractedID represents an object identifier extracted from an HTTP exchange.
type ExtractedID struct {
	Value    string // the actual ID value (e.g., "123", "abc-def-ghi-jkl")
	Type     string // uuid | integer | mongoid | hash
	Location string // path | query | body | header
	Key      string // the parameter or JSON key name
}

// Regex patterns for identifying different ID types.
var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	mongoIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	integerPattern = regexp.MustCompile(`^\d+$`)

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
		regexp.MustCompile(`(?i)^token$`),
		regexp.MustCompile(`(?i)^code$`),
	}

	// UUID pattern for scanning within strings
	uuidScanPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)
)

// ExtractAll extracts all object IDs from a URL, response body, and headers.
func ExtractAll(reqURL *url.URL, body []byte, respHeaders http.Header) []ExtractedID {
	var results []ExtractedID

	// 1. Extract from URL path segments
	results = append(results, ExtractFromPath(reqURL.Path)...)

	// 2. Extract from query parameters
	results = append(results, ExtractFromQuery(reqURL.Query())...)

	// 3. Extract from response body (JSON)
	results = append(results, ExtractFromJSONBody(body)...)

	// 4. Extract from response headers
	results = append(results, ExtractFromHeaders(respHeaders)...)

	return dedupExtracted(results)
}

// ExtractFromPath extracts object IDs from URL path segments.
func ExtractFromPath(path string) []ExtractedID {
	var results []ExtractedID
	segments := strings.Split(strings.Trim(path, "/"), "/")

	for i, seg := range segments {
		if seg == "" {
			continue
		}

		idType := ClassifyID(seg)
		if idType == "" {
			continue
		}

		// Try to infer the key from the previous path segment
		key := ""
		if i > 0 {
			key = segments[i-1]
		}

		results = append(results, ExtractedID{
			Value:    seg,
			Type:     idType,
			Location: "path",
			Key:      key,
		})
	}

	return results
}

// ExtractFromQuery extracts object IDs from URL query parameters.
func ExtractFromQuery(params url.Values) []ExtractedID {
	var results []ExtractedID

	for key, values := range params {
		for _, val := range values {
			if val == "" {
				continue
			}
			idType := ClassifyID(val)
			if idType == "" {
				continue
			}
			results = append(results, ExtractedID{
				Value:    val,
				Type:     idType,
				Location: "query",
				Key:      key,
			})
		}
	}

	return results
}

// ExtractFromJSONBody recursively extracts object IDs from a JSON response body.
func ExtractFromJSONBody(body []byte) []ExtractedID {
	if len(body) == 0 {
		return nil
	}

	var results []ExtractedID

	// Try parsing as JSON object
	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err == nil {
		results = append(results, extractFromMap(obj, "")...)
		return results
	}

	// Try parsing as JSON array
	var arr []interface{}
	if err := json.Unmarshal(body, &arr); err == nil {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				results = append(results, extractFromMap(m, "")...)
			}
		}
	}

	return results
}

// extractFromMap recursively traverses a JSON object to find ID-like values.
func extractFromMap(obj map[string]interface{}, prefix string) []ExtractedID {
	var results []ExtractedID

	for key, val := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			if isIDKey(key) || ClassifyID(v) != "" {
				idType := ClassifyID(v)
				if idType == "" {
					idType = "hash" // ID key but unrecognized format
				}
				results = append(results, ExtractedID{
					Value:    v,
					Type:     idType,
					Location: "body",
					Key:      fullKey,
				})
			}
		case float64:
			// JSON numbers that look like IDs (associated with ID-like keys)
			if isIDKey(key) {
				results = append(results, ExtractedID{
					Value:    formatFloat(v),
					Type:     "integer",
					Location: "body",
					Key:      fullKey,
				})
			}
		case map[string]interface{}:
			// Recurse into nested objects (limit depth to avoid infinite loops)
			if strings.Count(fullKey, ".") < 5 {
				results = append(results, extractFromMap(v, fullKey)...)
			}
		case []interface{}:
			// Check first few items in arrays
			limit := 3
			if len(v) < limit {
				limit = len(v)
			}
			for i := 0; i < limit; i++ {
				if m, ok := v[i].(map[string]interface{}); ok {
					results = append(results, extractFromMap(m, fullKey)...)
				}
			}
		}
	}

	return results
}

// ExtractFromHeaders extracts object IDs from response headers.
func ExtractFromHeaders(headers http.Header) []ExtractedID {
	var results []ExtractedID

	interestingHeaders := []string{"Location", "X-Request-Id", "X-Resource-Id", "ETag"}
	for _, h := range interestingHeaders {
		val := headers.Get(h)
		if val == "" {
			continue
		}

		// Check for UUIDs in header values
		if matches := uuidScanPattern.FindAllString(val, -1); len(matches) > 0 {
			for _, m := range matches {
				results = append(results, ExtractedID{
					Value:    m,
					Type:     "uuid",
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
func ClassifyID(val string) string {
	if val == "" {
		return ""
	}

	if uuidPattern.MatchString(val) {
		return "uuid"
	}

	if mongoIDPattern.MatchString(val) {
		return "mongoid"
	}

	if integerPattern.MatchString(val) {
		// Ignore very small numbers (likely not IDs) and very large numbers
		if len(val) >= 1 && len(val) <= 20 {
			return "integer"
		}
	}

	// Long alphanumeric strings might be hashes/tokens
	if len(val) >= 16 && isAlphanumeric(val) {
		return "hash"
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
		case "uuid":
			segments[i] = "{uuid}"
		case "integer":
			segments[i] = "{id}"
		case "mongoid":
			segments[i] = "{mongoid}"
		case "hash":
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

// formatFloat formats a float64 as an integer string if it has no decimal part.
func formatFloat(f float64) string {
	if f == float64(int64(f)) {
		return strings.TrimRight(strings.TrimRight(
			strings.Replace(
				strings.Replace(
					strings.Replace(
						formatFloatBasic(f), ".000000", "", 1),
					".00000", "", 1),
				".0000", "", 1),
			"0"), ".")
	}
	return formatFloatBasic(f)
}

func formatFloatBasic(f float64) string {
	return strings.TrimRight(strings.TrimRight(
		func() string {
			s := make([]byte, 0, 32)
			s = append(s, []byte(func() string {
				if f < 0 {
					return "-"
				}
				return ""
			}())...)

			abs := f
			if abs < 0 {
				abs = -abs
			}

			intPart := int64(abs)
			buf := make([]byte, 0, 20)
			if intPart == 0 {
				buf = append(buf, '0')
			} else {
				for intPart > 0 {
					buf = append([]byte{byte('0' + intPart%10)}, buf...)
					intPart /= 10
				}
			}
			s = append(s, buf...)
			return string(s)
		}(),
		"0"), ".")
}

// dedupExtracted removes duplicate extracted IDs.
func dedupExtracted(ids []ExtractedID) []ExtractedID {
	seen := make(map[string]bool)
	var result []ExtractedID
	for _, id := range ids {
		key := id.Location + ":" + id.Key + ":" + id.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, id)
		}
	}
	return result
}
