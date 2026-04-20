// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package vault provides multi-identity session management for bola.
// It handles JWT/Cookie/Bearer/Basic authentication with auto-detection,
// expiry monitoring, and token refresh lifecycle.
package vault

import (
	"fmt"
	"log/slog"
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
	TokenTypeAPIKey  TokenType = "APIKey"
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
	Subject      string // JWT sub claim

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
			Headers:      make(map[string]string),
			RefreshToken: ic.RefreshToken,
			RefreshURL:   ic.RefreshURL,
		}

		// Copy headers
		for k, val := range ic.Headers {
			id.Headers[k] = val
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

		// Auto-detect token type and parse JWT claims
		id.TokenType = DetectTokenType(id.Headers, id.Cookies)

		if id.TokenType == TokenTypeJWT {
			if auth, ok := id.Headers["Authorization"]; ok {
				token := strings.TrimPrefix(auth, "Bearer ")
				claims, err := ParseJWTClaims(token)
				if err == nil {
					id.ExpiresAt = claims.ExpiresAt
					id.Subject = claims.Subject
					slog.Debug("vault: parsed JWT",
						"identity", id.Name,
						"sub", claims.Subject,
						"exp", claims.ExpiresAt.Format(time.RFC3339),
					)
				} else {
					slog.Warn("vault: failed to parse JWT claims",
						"identity", id.Name,
						"error", err,
					)
				}
			}
		}

		// Warn if token is expired
		if !id.ExpiresAt.IsZero() && time.Now().After(id.ExpiresAt) {
			slog.Warn("vault: token is EXPIRED",
				"identity", id.Name,
				"expired_at", id.ExpiresAt.Format(time.RFC3339),
			)
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
		return nil, fmt.Errorf("vault: identity %q not found", name)
	}
	return id, nil
}

// GetAll returns all identities.
func (v *Vault) GetAll() []*Identity {
	v.mu.RLock()
	defer v.mu.RUnlock()

	ids := make([]*Identity, 0, len(v.identities))
	for _, id := range v.identities {
		ids = append(ids, id)
	}
	return ids
}

// GetByRole returns all identities with the given role.
func (v *Vault) GetByRole(role string) []*Identity {
	v.mu.RLock()
	defer v.mu.RUnlock()

	var ids []*Identity
	for _, id := range v.identities {
		if strings.EqualFold(id.Role, role) {
			ids = append(ids, id)
		}
	}
	return ids
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

// InjectAuth applies an identity's authentication to an HTTP request.
func (v *Vault) InjectAuth(req *http.Request, identityName string) error {
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

// HeadersFor returns the authentication headers for an identity.
func (v *Vault) HeadersFor(identityName string) (map[string]string, error) {
	id, err := v.Get(identityName)
	if err != nil {
		return nil, err
	}

	id.mu.RLock()
	defer id.mu.RUnlock()

	result := make(map[string]string, len(id.Headers))
	for k, val := range id.Headers {
		result[k] = val
	}
	return result, nil
}

// IdentifyRequest determines which identity made a request by matching headers/cookies.
func (v *Vault) IdentifyRequest(req *http.Request) string {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for name, id := range v.identities {
		id.mu.RLock()

		matched := false
		for key, val := range id.Headers {
			if req.Header.Get(key) == val {
				matched = true
				break
			}
		}

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

// IsExpired checks if an identity's token has expired.
func (id *Identity) IsExpired() bool {
	id.mu.RLock()
	defer id.mu.RUnlock()

	if id.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(id.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the token expires.
// Returns 0 if already expired or no expiry is known.
func (id *Identity) TimeUntilExpiry() time.Duration {
	id.mu.RLock()
	defer id.mu.RUnlock()

	if id.ExpiresAt.IsZero() {
		return 0
	}
	d := time.Until(id.ExpiresAt)
	if d < 0 {
		return 0
	}
	return d
}

// UpdateToken updates an identity's authentication token.
func (id *Identity) UpdateToken(headerKey, headerValue string, expiresAt time.Time) {
	id.mu.Lock()
	defer id.mu.Unlock()

	id.Headers[headerKey] = headerValue
	id.ExpiresAt = expiresAt
}
