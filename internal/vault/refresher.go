// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package vault

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
		interval: 30 * time.Second,
		buffer:   60 * time.Second, // refresh 60s before expiry
		stopCh:   make(chan struct{}),
	}
}

// Start begins monitoring tokens in the background.
func (r *Refresher) Start() {
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
			}
		}
	}()
}

// Stop halts the background refresh monitor.
func (r *Refresher) Stop() {
	close(r.stopCh)
	r.wg.Wait()
}

// checkAll inspects all identities and refreshes those expiring soon.
func (r *Refresher) checkAll() {
	for _, id := range r.vault.All() {
		if id.IsExpiringSoon(r.buffer) && id.RefreshToken != "" && id.RefreshURL != "" {
			if err := r.refresh(id); err != nil {
				fmt.Printf("[!] Failed to refresh token for %q: %v\n", id.Name, err)
			}
		}
	}
}

// refresh performs the token refresh flow for a single identity.
func (r *Refresher) refresh(id *Identity) error {
	id.mu.RLock()
	refreshToken := id.RefreshToken
	refreshURL := id.RefreshURL
	id.mu.RUnlock()

	payload := map[string]string{
		"refresh_token": refreshToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling refresh payload: %w", err)
	}

	req, err := http.NewRequest("POST", refreshURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("executing refresh request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh returned status %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading refresh response: %w", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing refresh response: %w", err)
	}

	// Try common token field names
	var newToken string
	for _, key := range []string{"access_token", "token", "jwt", "id_token"} {
		if v, ok := result[key]; ok {
			if s, ok := v.(string); ok {
				newToken = s
				break
			}
		}
	}

	if newToken == "" {
		return fmt.Errorf("no token found in refresh response")
	}

	// Extract new expiry if JWT
	var newExpiry time.Time
	if exp, err := ExtractJWTExpiry(newToken); err == nil {
		newExpiry = exp
	} else {
		// Default to 1 hour if we can't parse
		newExpiry = time.Now().Add(time.Hour)
	}

	// Update the new refresh token if provided
	if rt, ok := result["refresh_token"]; ok {
		if s, ok := rt.(string); ok {
			id.mu.Lock()
			id.RefreshToken = s
			id.mu.Unlock()
		}
	}

	id.UpdateToken("Authorization", "Bearer "+newToken, newExpiry)
	fmt.Printf("[+] Refreshed token for %q (expires: %s)\n", id.Name, newExpiry.Format(time.RFC3339))

	return nil
}
