// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package analyzer

import (
	"encoding/json"
	"sort"
	"strings"
)

// ComputeJSONSimilarity computes the structural similarity between two JSON responses
// using Jaccard similarity on flattened key sets.
// Returns a value between 0.0 (completely different) and 1.0 (identical structure).
func ComputeJSONSimilarity(body1, body2 []byte) float64 {
	keys1 := flattenJSONKeys(body1)
	keys2 := flattenJSONKeys(body2)

	if len(keys1) == 0 && len(keys2) == 0 {
		// Both empty or non-JSON — compare as plain text
		return plainTextSimilarity(body1, body2)
	}

	return jaccardSimilarity(keys1, keys2)
}

// ComputeValueSimilarity computes the similarity of values for matching keys
// between two JSON responses.
func ComputeValueSimilarity(body1, body2 []byte) float64 {
	vals1 := flattenJSONValues(body1)
	vals2 := flattenJSONValues(body2)

	if len(vals1) == 0 || len(vals2) == 0 {
		return 0
	}

	// Count matching key-value pairs
	matches := 0
	total := 0
	for key, v1 := range vals1 {
		if v2, ok := vals2[key]; ok {
			total++
			if v1 == v2 {
				matches++
			}
		}
	}

	if total == 0 {
		return 0
	}

	return float64(matches) / float64(total)
}

// flattenJSONKeys extracts all keys from a JSON document, including nested keys
// with dot notation (e.g., "user.name", "user.email").
func flattenJSONKeys(data []byte) []string {
	if len(data) == 0 {
		return nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		// Try as array
		var arr []interface{}
		if err := json.Unmarshal(data, &arr); err != nil {
			return nil
		}
		if len(arr) > 0 {
			if m, ok := arr[0].(map[string]interface{}); ok {
				return flattenMap(m, "")
			}
		}
		return nil
	}

	return flattenMap(obj, "")
}

// flattenMap recursively extracts keys from a JSON object.
func flattenMap(obj map[string]interface{}, prefix string) []string {
	var keys []string

	for key, val := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}
		keys = append(keys, fullKey)

		switch v := val.(type) {
		case map[string]interface{}:
			if strings.Count(fullKey, ".") < 5 {
				keys = append(keys, flattenMap(v, fullKey)...)
			}
		case []interface{}:
			if len(v) > 0 {
				if m, ok := v[0].(map[string]interface{}); ok {
					keys = append(keys, flattenMap(m, fullKey+"[]")...)
				}
			}
		}
	}

	sort.Strings(keys)
	return keys
}

// flattenJSONValues extracts all key-value pairs from a JSON document.
func flattenJSONValues(data []byte) map[string]string {
	if len(data) == 0 {
		return nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return nil
	}

	result := make(map[string]string)
	flattenValuesMap(obj, "", result)
	return result
}

// flattenValuesMap recursively extracts key-value pairs.
func flattenValuesMap(obj map[string]interface{}, prefix string, result map[string]string) {
	for key, val := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			result[fullKey] = v
		case float64:
			result[fullKey] = strings.TrimRight(strings.TrimRight(
				func() string {
					if v == float64(int64(v)) {
						return formatInt(int64(v))
					}
					return formatFloat64(v)
				}(),
				"0"), ".")
		case bool:
			if v {
				result[fullKey] = "true"
			} else {
				result[fullKey] = "false"
			}
		case nil:
			result[fullKey] = "null"
		case map[string]interface{}:
			if strings.Count(fullKey, ".") < 5 {
				flattenValuesMap(v, fullKey, result)
			}
		}
	}
}

// jaccardSimilarity computes the Jaccard index between two string sets.
func jaccardSimilarity(a, b []string) float64 {
	setA := make(map[string]bool, len(a))
	for _, s := range a {
		setA[s] = true
	}

	setB := make(map[string]bool, len(b))
	for _, s := range b {
		setB[s] = true
	}

	intersection := 0
	for s := range setA {
		if setB[s] {
			intersection++
		}
	}

	union := len(setA)
	for s := range setB {
		if !setA[s] {
			union++
		}
	}

	if union == 0 {
		return 0
	}

	return float64(intersection) / float64(union)
}

// plainTextSimilarity computes a basic similarity between two byte slices
// based on length comparison.
func plainTextSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}

	longer := float64(len(a))
	shorter := float64(len(b))
	if shorter > longer {
		longer, shorter = shorter, longer
	}

	return shorter / longer
}

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

func formatFloat64(f float64) string {
	// Simple float formatting without importing strconv
	intPart := int64(f)
	fracPart := f - float64(intPart)
	if fracPart < 0 {
		fracPart = -fracPart
	}
	frac := int64(fracPart * 1000000)
	s := formatInt(intPart) + "."
	fracStr := formatInt(frac)
	// Pad to 6 digits
	for len(fracStr) < 6 {
		fracStr = "0" + fracStr
	}
	return s + fracStr
}
