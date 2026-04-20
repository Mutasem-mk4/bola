// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package vault

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/Mutasem-mk4/bola/internal/config"
)

// makeTestJWT creates a minimal valid JWT token string for testing.
func makeTestJWT(exp int64) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"sub": "user1",
		"exp": exp,
		"iat": time.Now().Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

func TestDetectTokenTypeJWT(t *testing.T) {
	token := makeTestJWT(time.Now().Add(time.Hour).Unix())
	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeJWT {
		t.Errorf("expected JWT, got %s", tt)
	}
}

func TestDetectTokenTypeBearer(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Bearer some-opaque-token-not-jwt",
	}

	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeBearer {
		t.Errorf("expected Bearer, got %s", tt)
	}
}

func TestDetectTokenTypeBasic(t *testing.T) {
	headers := map[string]string{
		"Authorization": "Basic dXNlcjpwYXNz",
	}

	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeBasic {
		t.Errorf("expected Basic, got %s", tt)
	}
}

func TestDetectTokenTypeCookie(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc123"}}
	tt := DetectTokenType(nil, cookies)
	if tt != TokenTypeCookie {
		t.Errorf("expected Cookie, got %s", tt)
	}
}

func TestExtractJWTExpiry(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := makeTestJWT(exp)

	got, err := ExtractJWTExpiry(token)
	if err != nil {
		t.Fatalf("extracting JWT expiry: %v", err)
	}

	if got.Unix() != exp {
		t.Errorf("expected exp %d, got %d", exp, got.Unix())
	}
}

func TestVaultNew(t *testing.T) {
	token := makeTestJWT(time.Now().Add(time.Hour).Unix())

	identities := []config.IdentityConfig{
		{
			Name: "admin",
			Role: "admin",
			Headers: map[string]string{
				"Authorization": "Bearer " + token,
			},
		},
		{
			Name: "guest",
			Role: "guest",
		},
	}

	v, err := New(identities)
	if err != nil {
		t.Fatalf("creating vault: %v", err)
	}

	names := v.List()
	if len(names) != 2 {
		t.Errorf("expected 2 identities, got %d", len(names))
	}

	admin, err := v.Get("admin")
	if err != nil {
		t.Fatalf("getting admin: %v", err)
	}
	if admin.TokenType != TokenTypeJWT {
		t.Errorf("expected JWT for admin, got %s", admin.TokenType)
	}
	if admin.ExpiresAt.IsZero() {
		t.Error("expected non-zero expiry for JWT admin")
	}
}

func TestIdentifyRequest(t *testing.T) {
	identities := []config.IdentityConfig{
		{
			Name:    "user1",
			Role:    "user",
			Headers: map[string]string{"Authorization": "Bearer token-for-user1"},
		},
		{
			Name: "user2",
			Role: "user",
			Cookies: []config.CookieConfig{
				{Name: "session", Value: "user2-session-val"},
			},
		},
	}

	v, _ := New(identities)

	// Test header-based identification
	req1, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	req1.Header.Set("Authorization", "Bearer token-for-user1")
	if name := v.IdentifyRequest(req1); name != "user1" {
		t.Errorf("expected user1, got %q", name)
	}

	// Test cookie-based identification
	req2, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	req2.AddCookie(&http.Cookie{Name: "session", Value: "user2-session-val"})
	if name := v.IdentifyRequest(req2); name != "user2" {
		t.Errorf("expected user2, got %q", name)
	}

	// Test unknown request
	req3, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	if name := v.IdentifyRequest(req3); name != "" {
		t.Errorf("expected empty string for unknown, got %q", name)
	}
}

func TestApplyAuth(t *testing.T) {
	identities := []config.IdentityConfig{
		{
			Name:    "user1",
			Role:    "user",
			Headers: map[string]string{"Authorization": "Bearer my-token"},
		},
	}

	v, _ := New(identities)

	req, _ := http.NewRequest("GET", "http://example.com/api/test", nil)
	if err := v.ApplyAuth(req, "user1"); err != nil {
		t.Fatalf("applying auth: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer my-token" {
		t.Errorf("expected Bearer my-token, got %q", got)
	}
}

func TestIsExpired(t *testing.T) {
	id := &Identity{
		Name:      "test",
		ExpiresAt: time.Now().Add(-time.Hour),
	}
	if !id.IsExpired() {
		t.Error("expected token to be expired")
	}

	id2 := &Identity{
		Name:      "test2",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if id2.IsExpired() {
		t.Error("expected token to not be expired")
	}
}
