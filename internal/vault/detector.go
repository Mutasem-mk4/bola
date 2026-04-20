// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package vault

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims holds the decoded claims from a JWT token.
type JWTClaims struct {
	Subject   string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Issuer    string
	Raw       map[string]interface{}
}

// DetectTokenType auto-detects the authentication token type from headers and cookies.
func DetectTokenType(headers map[string]string, cookies []*http.Cookie) TokenType {
	if auth, ok := headers["Authorization"]; ok {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			parts := strings.Split(token, ".")
			if len(parts) == 3 {
				// Validate it's actually a JWT by checking base64 decode of header
				if headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
					if strings.Contains(string(headerJSON), "alg") {
						return TokenTypeJWT
					}
				}
			}
			return TokenTypeBearer
		}
		if strings.HasPrefix(auth, "Basic ") {
			return TokenTypeBasic
		}
	}

	// Check for API key headers
	apiKeyHeaders := []string{"X-Api-Key", "X-API-Key", "Api-Key", "Apikey"}
	for _, h := range apiKeyHeaders {
		if _, ok := headers[h]; ok {
			return TokenTypeAPIKey
		}
	}

	if len(cookies) > 0 {
		return TokenTypeCookie
	}

	return TokenTypeUnknown
}

// ParseJWTClaims decodes a JWT token and extracts claims WITHOUT signature validation.
// This is intentional — we don't have the server's secret key and only need
// to read the expiry and subject for token lifecycle management.
func ParseJWTClaims(tokenString string) (*JWTClaims, error) {
	parser := jwt.NewParser(
		jwt.WithoutClaimsValidation(),
	)

	token, _, err := parser.ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("vault: parsing JWT: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("vault: unexpected claims type")
	}

	result := &JWTClaims{
		Raw: map[string]interface{}(claims),
	}

	// Extract standard claims
	if sub, err := claims.GetSubject(); err == nil {
		result.Subject = sub
	}

	if exp, err := claims.GetExpirationTime(); err == nil && exp != nil {
		result.ExpiresAt = exp.Time
	}

	if iat, err := claims.GetIssuedAt(); err == nil && iat != nil {
		result.IssuedAt = iat.Time
	}

	if iss, err := claims.GetIssuer(); err == nil {
		result.Issuer = iss
	}

	return result, nil
}
