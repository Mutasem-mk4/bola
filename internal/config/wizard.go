// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package config

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/charmbracelet/lipgloss"
)

// RunWizard starts an interactive terminal session to generate a configuration.
func RunWizard() (*Config, error) {
	fmt.Println(lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#00FF00")).
		Render("\n--- BOLA Configuration Wizard ---\n"))

	fmt.Println("This wizard will help you set up your target and identities.")
	fmt.Println("You can always edit the bola.yaml file manually later.")
	fmt.Println()

	var qs = []*survey.Question{
		{
			Name: "baseURL",
			Prompt: &survey.Input{
				Message: "Target Base URL (e.g., https://api.example.com):",
				Default: "https://",
			},
			Validate: survey.Required,
		},
		{
			Name: "proxyAddr",
			Prompt: &survey.Input{
				Message: "Proxy Listen Address:",
				Default: "127.0.0.1:8080",
			},
		},
	}

	answers := struct {
		BaseURL   string
		ProxyAddr string
	}{}

	err := survey.Ask(qs, &answers)
	if err != nil {
		return nil, err
	}

	// Normalize Base URL
	if !strings.HasPrefix(answers.BaseURL, "http") {
		answers.BaseURL = "https://" + answers.BaseURL
	}
	answers.BaseURL = strings.TrimSuffix(answers.BaseURL, "/")

	cfg := DefaultConfig()
	cfg.Target.BaseURL = answers.BaseURL
	cfg.Proxy.Listen = answers.ProxyAddr

	// Identities
	fmt.Println("\n--- Identity Setup ---")
	fmt.Println("You need at least two identities (e.g., admin and user) to test for BOLA.")

	for i := 1; i <= 2; i++ {
		var idName string
		prompt := &survey.Input{
			Message: fmt.Sprintf("Name for Identity %d (e.g., admin):", i),
		}
		if i == 1 {
			prompt.Default = "admin"
		} else {
			prompt.Default = "user1"
		}

		err = survey.AskOne(prompt, &idName)
		if err != nil {
			return nil, err
		}

		cfg.Identities = append(cfg.Identities, IdentityConfig{
			Name:    idName,
			Role:    strings.ToLower(idName),
			Headers: make(map[string]string),
		})
	}

	// Scope
	var includePath string
	err = survey.AskOne(&survey.Input{
		Message: "Include Scope Pattern (e.g., /api/v1/*):",
		Default: "/api/*",
	}, &includePath)
	if err == nil && includePath != "" {
		cfg.Target.Scope.Include = []string{includePath}
	}

	fmt.Println(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FFFF")).
		Render("\n[+] Configuration baseline generated!"))

	return cfg, nil
}
