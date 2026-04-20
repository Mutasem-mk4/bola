// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package vault provides identity and token management for bola.
// It handles multiple user sessions, auto-detects token formats,
// and manages token lifecycle including refresh.
package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Mutasem-mk4/bola/internal/config"
)

// TokenType represents the detected authentication token format.
type TokenType string

const (
	TokenTypeJWT     TokenType = "JWT"
	TokenTypeBearer  TokenType = "Bearer"
	TokenTypeCookie  TokenType = "Cookie"
	TokenTypeBasic   TokenType = "Basic"
	TokenTypeUnknown TokenType = "Unknown"
)

// Identity represents a managed user session with its authentication state.
type Identity struct {
	Name         string
	Role         string
	TokenType    TokenType
	Headers      map[string]string
	Cookies      []*http.Cookie
	RefreshToken string
	RefreshURL   string
	ExpiresAt    time.Time

	mu sync.RWMutex
}

// Vault manages multiple identities and their authentication state.
type Vault struct {
	identities map[string]*Identity
	mu         sync.RWMutex
}

// New creates a new Vault from configuration.
func New(identities []config.IdentityConfig) (*Vault, error) {
	v := &Vault{
		identities: make(map[string]*Identity),
	}

	for _, ic := range identities {
		id := &Identity{
			Name:         ic.Name,
			Role:         ic.Role,
			Headers:      ic.Headers,
			RefreshToken: ic.RefreshToken,
			RefreshURL:   ic.RefreshURL,
		}

		// Convert config cookies to http.Cookie
		for _, cc := range ic.Cookies {
			id.Cookies = append(id.Cookies, &http.Cookie{
				Name:   cc.Name,
				Value:  cc.Value,
				Domain: cc.Domain,
				Path:   cc.Path,
			})
		}

		// Auto-detect token type
		id.TokenType = DetectTokenType(id.Headers, id.Cookies)

		// If JWT, extract expiry
		if id.TokenType == TokenTypeJWT {
			if auth, ok := id.Headers["Authorization"]; ok {
				token := strings.TrimPrefix(auth, "Bearer ")
				if exp, err := ExtractJWTExpiry(token); err == nil {
					id.ExpiresAt = exp
				}
			}
		}

		v.identities[ic.Name] = id
	}

	return v, nil
}

// Get returns an identity by name.
func (v *Vault) Get(name string) (*Identity, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	id, ok := v.identities[name]
	if !ok {
		return nil, fmt.Errorf("identity %q not found", name)
	}
	return id, nil
}

// List returns all identity names.
func (v *Vault) List() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	names := make([]string, 0, len(v.identities))
	for name := range v.identities {
		names = append(names, name)
	}
	return names
}

// All returns all identities.
func (v *Vault) All() []*Identity {
	v.mu.RLock()
	defer v.mu.RUnlock()

	ids := make([]*Identity, 0, len(v.identities))
	for _, id := range v.identities {
		ids = append(ids, id)
	}
	return ids
}

// IdentifyRequest determines which identity made a request by matching headers/cookies.
func (v *Vault) IdentifyRequest(req *http.Request) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for name, id := range v.identities {
		id.mu.RLock()

		// Check header match
		matched := false
		for key, val := range id.Headers {
			if req.Header.Get(key) == val {
				matched = true
				break
			}
		}

		// Check cookie match
		if !matched {
			for _, c := range id.Cookies {
				if rc, err := req.Cookie(c.Name); err == nil && rc.Value == c.Value {
					matched = true
					break
				}
			}
		}

		id.mu.RUnlock()

		if matched {
			return name
		}
	}

	return ""
}

// ApplyAuth applies an identity's authentication to an HTTP request.
func (v *Vault) ApplyAuth(req *http.Request, identityName string) error {
	id, err := v.Get(identityName)
	if err != nil {
		return err
	}

	id.mu.RLock()
	defer id.mu.RUnlock()

	for key, val := range id.Headers {
		req.Header.Set(key, val)
	}

	for _, c := range id.Cookies {
		req.AddCookie(c)
	}

	return nil
}

// IsExpired checks if an identity's token has expired.
func (id *Identity) IsExpired() bool {
	id.mu.RLock()
	defer id.mu.RUnlock()

	if id.ExpiresAt.IsZero() {
		return false // No expiry known
	}
	return time.Now().After(id.ExpiresAt)
}

// IsExpiringSoon checks if a token will expire within the given duration.
func (id *Identity) IsExpiringSoon(within time.Duration) bool {
	id.mu.RLock()
	defer id.mu.RUnlock()

	if id.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().Add(within).After(id.ExpiresAt)
}

// UpdateToken updates an identity's authentication token.
func (id *Identity) UpdateToken(headerKey, headerValue string, expiresAt time.Time) {
	id.mu.Lock()
	defer id.mu.Unlock()

	if id.Headers == nil {
		id.Headers = make(map[string]string)
	}
	id.Headers[headerKey] = headerValue
	id.ExpiresAt = expiresAt
}

// DetectTokenType auto-detects the authentication token type from headers and cookies.
func DetectTokenType(headers map[string]string, cookies []*http.Cookie) TokenType {
	if auth, ok := headers["Authorization"]; ok {
		if strings.HasPrefix(auth, "Bearer ") {
			token := strings.TrimPrefix(auth, "Bearer ")
			parts := strings.Split(token, ".")
			if len(parts) == 3 {
				// Validate it's actually a JWT by checking base64 decode
				if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
					if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
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

	if len(cookies) > 0 {
		return TokenTypeCookie
	}

	return TokenTypeUnknown
}

// ExtractJWTExpiry decodes a JWT token and extracts the expiration time.
func ExtractJWTExpiry(token string) (time.Time, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("decoding JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return time.Time{}, fmt.Errorf("parsing JWT claims: %w", err)
	}

	exp, ok := claims["exp"]
	if !ok {
		return time.Time{}, fmt.Errorf("JWT has no exp claim")
	}

	expFloat, ok := exp.(float64)
	if !ok {
		return time.Time{}, fmt.Errorf("JWT exp claim is not a number")
	}

	return time.Unix(int64(expFloat), 0), nil
}
