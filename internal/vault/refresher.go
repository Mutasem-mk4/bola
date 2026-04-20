// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Refresher monitors identity tokens and auto-refreshes them before expiry.
type Refresher struct {
	vault    *Vault
	client   *http.Client
	interval time.Duration
	buffer   time.Duration // refresh this long before actual expiry
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewRefresher creates a new token refresh monitor.
func NewRefresher(vault *Vault) *Refresher {
	return &Refresher{
		vault:    vault,
		client:   &http.Client{Timeout: 10 * time.Second},
		interval: 15 * time.Second,
		buffer:   30 * time.Second, // refresh 30s before expiry
		stopCh:   make(chan struct{}),
	}
}

// Start begins monitoring tokens in the background.
func (r *Refresher) Start(ctx context.Context) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		ticker := time.NewTicker(r.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				r.checkAll()
			case <-r.stopCh:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	slog.Debug("vault: token refresher started", "interval", r.interval, "buffer", r.buffer)
}

// Stop halts the background refresh monitor.
func (r *Refresher) Stop() {
	close(r.stopCh)
	r.wg.Wait()
	slog.Debug("vault: token refresher stopped")
}

// checkAll inspects all identities and refreshes those expiring soon.
func (r *Refresher) checkAll() {
	for _, id := range r.vault.GetAll() {
		id.mu.RLock()
		expiresAt := id.ExpiresAt
		hasRefresh := id.RefreshToken != "" && id.RefreshURL != ""
		id.mu.RUnlock()

		if expiresAt.IsZero() || !hasRefresh {
			continue
		}

		timeLeft := time.Until(expiresAt)
		if timeLeft <= r.buffer && timeLeft > 0 {
			slog.Info("vault: token expiring soon, refreshing",
				"identity", id.Name,
				"expires_in", timeLeft.Round(time.Second),
			)
			if err := r.RefreshNow(id); err != nil {
				slog.Error("vault: token refresh failed",
					"identity", id.Name,
					"error", err,
				)
			}
		} else if timeLeft <= 0 {
			slog.Warn("vault: token already expired",
				"identity", id.Name,
				"expired_at", expiresAt.Format(time.RFC3339),
			)
			if err := r.RefreshNow(id); err != nil {
				slog.Error("vault: expired token refresh failed",
					"identity", id.Name,
					"error", err,
				)
			}
		}
	}
}

// RefreshNow performs an immediate token refresh for a single identity.
func (r *Refresher) RefreshNow(id *Identity) error {
	id.mu.RLock()
	refreshToken := id.RefreshToken
	refreshURL := id.RefreshURL
	id.mu.RUnlock()

	if refreshToken == "" || refreshURL == "" {
		return fmt.Errorf("vault: no refresh_token or refresh_url configured for %q", id.Name)
	}

	payload := map[string]string{
		"refresh_token": refreshToken,
		"grant_type":    "refresh_token",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("vault: marshaling refresh payload: %w", err)
	}

	req, err := http.NewRequest("POST", refreshURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vault: creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("vault: executing refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault: refresh returned HTTP %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("vault: reading refresh response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("vault: parsing refresh response: %w", err)
	}

	// Try common token field names
	var newToken string
	for _, key := range []string{"access_token", "token", "jwt", "id_token", "Authorization"} {
		if v, ok := result[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				newToken = s
				break
			}
		}
	}

	if newToken == "" {
		return fmt.Errorf("vault: no token found in refresh response (keys: %s)", joinKeys(result))
	}

	// Strip "Bearer " prefix if present in the response value
	newToken = strings.TrimPrefix(newToken, "Bearer ")

	// Extract new expiry
	var newExpiry time.Time
	if claims, err := ParseJWTClaims(newToken); err == nil {
		newExpiry = claims.ExpiresAt
	} else {
		newExpiry = time.Now().Add(time.Hour) // default fallback
	}

	// Update the identity
	id.UpdateToken("Authorization", "Bearer "+newToken, newExpiry)

	// Update refresh token if a new one was provided
	if rt, ok := result["refresh_token"]; ok {
		if s, ok := rt.(string); ok && s != "" {
			id.mu.Lock()
			id.RefreshToken = s
			id.mu.Unlock()
		}
	}

	slog.Info("vault: token refreshed successfully",
		"identity", id.Name,
		"new_expiry", newExpiry.Format(time.RFC3339),
	)

	return nil
}

// joinKeys returns a comma-separated list of map keys for error messages.
func joinKeys(m map[string]interface{}) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}
