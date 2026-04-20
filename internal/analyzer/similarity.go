// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package analyzer

import (
	"encoding/json"
	"sort"
	"strings"
)

// ComputeKeySimilarity computes the Jaccard similarity between two JSON responses
// based on their flattened key sets.
// Returns a value between 0.0 (completely different) and 1.0 (identical structure).
func ComputeKeySimilarity(body1, body2 []byte) float64 {
	keys1 := FlattenJSON(body1)
	keys2 := FlattenJSON(body2)

	if len(keys1) == 0 && len(keys2) == 0 {
		return plainTextSimilarity(body1, body2)
	}

	set1 := make([]string, 0, len(keys1))
	for k := range keys1 {
		set1 = append(set1, k)
	}
	set2 := make([]string, 0, len(keys2))
	for k := range keys2 {
		set2 = append(set2, k)
	}

	return jaccardSimilarity(set1, set2)
}

// ComputeValueSimilarity computes the similarity of values for matching keys
// between two JSON responses.
func ComputeValueSimilarity(body1, body2 []byte) float64 {
	vals1 := FlattenJSON(body1)
	vals2 := FlattenJSON(body2)

	if len(vals1) == 0 || len(vals2) == 0 {
		return 0
	}

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

// FlattenJSON recursively flattens a JSON document into a map of dotted key paths
// to string values. For example: {"user":{"name":"alice"}} becomes
// {"user.name": "alice"}.
func FlattenJSON(data []byte) map[string]string {
	if len(data) == 0 {
		return nil
	}

	result := make(map[string]string)

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		flattenMap(obj, "", result)
		return result
	}

	var arr []interface{}
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) > 0 {
			if m, ok := arr[0].(map[string]interface{}); ok {
				flattenMap(m, "", result)
			}
		}
	}

	return result
}

// flattenMap recursively extracts key-value pairs.
func flattenMap(obj map[string]interface{}, prefix string, result map[string]string) {
	for key, val := range obj {
		fullKey := key
		if prefix != "" {
			fullKey = prefix + "." + key
		}

		switch v := val.(type) {
		case string:
			result[fullKey] = v
		case float64:
			if v == float64(int64(v)) {
				result[fullKey] = intToString(int64(v))
			} else {
				result[fullKey] = floatToString(v)
			}
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
				flattenMap(v, fullKey, result)
			}
		case []interface{}:
			if len(v) > 0 {
				if m, ok := v[0].(map[string]interface{}); ok {
					flattenMap(m, fullKey+"[]", result)
				}
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

// plainTextSimilarity computes a basic length-based similarity.
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

// KeysOf returns sorted keys from a flattened JSON map.
func KeysOf(flat map[string]string) []string {
	keys := make([]string, 0, len(flat))
	for k := range flat {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func intToString(n int64) string {
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

func floatToString(f float64) string {
	intPart := int64(f)
	frac := f - float64(intPart)
	if frac < 0 {
		frac = -frac
	}
	fracInt := int64(frac * 1000000)
	s := intToString(intPart) + "."
	fracStr := intToString(fracInt)
	for len(fracStr) < 6 {
		fracStr = "0" + fracStr
	}
	return strings.TrimRight(strings.TrimRight(s+fracStr, "0"), ".")
}
