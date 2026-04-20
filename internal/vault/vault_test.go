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
func makeTestJWT(t *testing.T, sub string, exp int64) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := map[string]interface{}{
		"sub": sub,
		"exp": exp,
		"iat": time.Now().Unix(),
	}
	claimsJSON, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fake-signature-for-testing"))
	return fmt.Sprintf("%s.%s.%s", header, payload, sig)
}

func TestDetectTokenTypeJWT(t *testing.T) {
	token := makeTestJWT(t, "user1", time.Now().Add(time.Hour).Unix())
	headers := map[string]string{"Authorization": "Bearer " + token}
	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeJWT {
		t.Errorf("expected JWT, got %s", tt)
	}
}

func TestDetectTokenTypeBearer(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer some-opaque-token"}
	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeBearer {
		t.Errorf("expected Bearer, got %s", tt)
	}
}

func TestDetectTokenTypeBasic(t *testing.T) {
	headers := map[string]string{"Authorization": "Basic dXNlcjpwYXNz"}
	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeBasic {
		t.Errorf("expected Basic, got %s", tt)
	}
}

func TestDetectTokenTypeAPIKey(t *testing.T) {
	headers := map[string]string{"X-Api-Key": "my-api-key-123"}
	tt := DetectTokenType(headers, nil)
	if tt != TokenTypeAPIKey {
		t.Errorf("expected APIKey, got %s", tt)
	}
}

func TestDetectTokenTypeCookie(t *testing.T) {
	cookies := []*http.Cookie{{Name: "session", Value: "abc123"}}
	tt := DetectTokenType(nil, cookies)
	if tt != TokenTypeCookie {
		t.Errorf("expected Cookie, got %s", tt)
	}
}

func TestParseJWTClaims(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	token := makeTestJWT(t, "user42", exp)

	claims, err := ParseJWTClaims(token)
	if err != nil {
		t.Fatalf("parsing JWT: %v", err)
	}
	if claims.Subject != "user42" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "user42")
	}
	if claims.ExpiresAt.Unix() != exp {
		t.Errorf("exp: got %d, want %d", claims.ExpiresAt.Unix(), exp)
	}
}

func TestParseJWTClaimsInvalid(t *testing.T) {
	_, err := ParseJWTClaims("not-a-jwt")
	if err == nil {
		t.Fatal("expected error for invalid JWT")
	}
}

func TestVaultNew(t *testing.T) {
	token := makeTestJWT(t, "admin", time.Now().Add(time.Hour).Unix())
	identities := []config.IdentityConfig{
		{
			Name:    "admin",
			Role:    "admin",
			Headers: map[string]string{"Authorization": "Bearer " + token},
		},
		{
			Name: "guest",
			Role: "guest",
			Cookies: []config.CookieConfig{
				{Name: "session", Value: "xyz"},
			},
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
		t.Errorf("admin token type: got %s, want JWT", admin.TokenType)
	}
	if admin.Subject != "admin" {
		t.Errorf("admin subject: got %q", admin.Subject)
	}
}

func TestGetByRole(t *testing.T) {
	identities := []config.IdentityConfig{
		{Name: "admin1", Role: "admin", Headers: map[string]string{"Authorization": "Bearer a"}},
		{Name: "user1", Role: "user", Headers: map[string]string{"Authorization": "Bearer b"}},
		{Name: "user2", Role: "user", Headers: map[string]string{"Authorization": "Bearer c"}},
	}
	v, _ := New(identities)

	users := v.GetByRole("user")
	if len(users) != 2 {
		t.Errorf("expected 2 users, got %d", len(users))
	}

	admins := v.GetByRole("admin")
	if len(admins) != 1 {
		t.Errorf("expected 1 admin, got %d", len(admins))
	}
}

func TestIdentifyRequest(t *testing.T) {
	identities := []config.IdentityConfig{
		{Name: "user1", Role: "user", Headers: map[string]string{"Authorization": "Bearer token-1"}},
		{Name: "user2", Role: "user", Cookies: []config.CookieConfig{{Name: "session", Value: "sess-2"}}},
	}
	v, _ := New(identities)

	req1, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req1.Header.Set("Authorization", "Bearer token-1")
	if name := v.IdentifyRequest(req1); name != "user1" {
		t.Errorf("expected user1, got %q", name)
	}

	req2, _ := http.NewRequest("GET", "http://example.com/test", nil)
	req2.AddCookie(&http.Cookie{Name: "session", Value: "sess-2"})
	if name := v.IdentifyRequest(req2); name != "user2" {
		t.Errorf("expected user2, got %q", name)
	}

	req3, _ := http.NewRequest("GET", "http://example.com/test", nil)
	if name := v.IdentifyRequest(req3); name != "" {
		t.Errorf("expected empty, got %q", name)
	}
}

func TestInjectAuth(t *testing.T) {
	identities := []config.IdentityConfig{
		{Name: "a", Role: "admin", Headers: map[string]string{"Authorization": "Bearer my-token"}},
	}
	v, _ := New(identities)

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	if err := v.InjectAuth(req, "a"); err != nil {
		t.Fatalf("injecting auth: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer my-token" {
		t.Errorf("got %q", got)
	}
}

func TestIsExpired(t *testing.T) {
	expired := &Identity{Name: "old", ExpiresAt: time.Now().Add(-time.Hour)}
	if !expired.IsExpired() {
		t.Error("expected expired")
	}

	valid := &Identity{Name: "new", ExpiresAt: time.Now().Add(time.Hour)}
	if valid.IsExpired() {
		t.Error("expected not expired")
	}

	noExpiry := &Identity{Name: "none"}
	if noExpiry.IsExpired() {
		t.Error("no expiry should not be expired")
	}
}

func TestTimeUntilExpiry(t *testing.T) {
	id := &Identity{Name: "test", ExpiresAt: time.Now().Add(5 * time.Minute)}
	dur := id.TimeUntilExpiry()
	if dur < 4*time.Minute || dur > 6*time.Minute {
		t.Errorf("unexpected duration: %v", dur)
	}

	expired := &Identity{Name: "old", ExpiresAt: time.Now().Add(-time.Hour)}
	if expired.TimeUntilExpiry() != 0 {
		t.Error("expired token should return 0")
	}
}
