// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package reporter provides terminal, JSON, and Markdown report generation.
package reporter

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

// Color palette
var (
	colorRed     = lipgloss.Color("#FF6B6B")
	colorYellow  = lipgloss.Color("#F9CA24")
	colorBlue    = lipgloss.Color("#45B7D1")
	colorGreen   = lipgloss.Color("#4ECDC4")
	colorMagenta = lipgloss.Color("#6C5CE7")
	colorGray    = lipgloss.Color("#636E72")
	colorWhite   = lipgloss.Color("#DFE6E9")
)

// Styles
var (
	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorMagenta)

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(lipgloss.Color("#2D3436")).
			Padding(0, 2)

	highStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorRed)

	mediumStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorYellow)

	lowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBlue)

	labelStyle = lipgloss.NewStyle().
			Foreground(colorGray)

	valueStyle = lipgloss.NewStyle().
			Foreground(colorWhite)

	successStyle = lipgloss.NewStyle().
			Foreground(colorGreen)

	dividerStyle = lipgloss.NewStyle().
			Foreground(colorGray)
)

const banner = `
  ██████╗  ██████╗ ██╗      █████╗
  ██╔══██╗██╔═══██╗██║     ██╔══██╗
  ██████╔╝██║   ██║██║     ███████║
  ██╔══██╗██║   ██║██║     ██╔══██║
  ██████╔╝╚██████╔╝███████╗██║  ██║
  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
  Identity Orchestration Engine for BOLA/IDOR Detection
`

// PrintTerminal outputs findings to the terminal with lipgloss styling.
func PrintTerminal(findings []*graph.Finding) {
	fmt.Println(bannerStyle.Render(banner))

	if len(findings) == 0 {
		fmt.Println(successStyle.Render("  ✓ No BOLA/IDOR vulnerabilities detected"))
		fmt.Println()
		return
	}

	// Summary
	high, medium, low := countByConfidence(findings)
	fmt.Println(titleStyle.Render(" SCAN RESULTS "))
	fmt.Println()
	fmt.Printf("  %s %s   %s %s   %s %s\n",
		highStyle.Render("●"),
		highStyle.Render(fmt.Sprintf("HIGH: %d", high)),
		mediumStyle.Render("●"),
		mediumStyle.Render(fmt.Sprintf("MEDIUM: %d", medium)),
		lowStyle.Render("●"),
		lowStyle.Render(fmt.Sprintf("LOW: %d", low)),
	)
	fmt.Println()
	fmt.Println(dividerStyle.Render("  " + strings.Repeat("─", 72)))
	fmt.Println()

	// Individual findings
	for i, f := range findings {
		// Skip deduplicated findings
		if strings.HasPrefix(f.Notes, "[DEDUPLICATED]") {
			continue
		}

		printFinding(i+1, f)
	}
}

// printFinding renders a single finding to the terminal.
func printFinding(index int, f *graph.Finding) {
	confStyle := lowStyle
	confIcon := "🔵"
	switch f.ConfidenceLevel {
	case graph.ConfidenceHigh:
		confStyle = highStyle
		confIcon = "🔴"
	case graph.ConfidenceMedium:
		confStyle = mediumStyle
		confIcon = "🟡"
	}

	method := ""
	path := ""
	if f.Endpoint != nil {
		method = f.Endpoint.Method
		path = f.Endpoint.Path
	}

	fmt.Printf("  %s %s %s\n",
		confIcon,
		confStyle.Render(fmt.Sprintf("[%s]", f.ConfidenceLevel)),
		valueStyle.Render(fmt.Sprintf("#%d", index)),
	)

	fmt.Printf("  %s %s %s\n",
		labelStyle.Render("Endpoint:"),
		valueStyle.Render(method),
		valueStyle.Render(path),
	)

	fmt.Printf("  %s %s → %s\n",
		labelStyle.Render("Identity:"),
		valueStyle.Render(f.OwnerIdentity),
		confStyle.Render(f.TesterIdentity),
	)

	fmt.Printf("  %s %s → %s\n",
		labelStyle.Render("Status:"),
		valueStyle.Render(fmt.Sprintf("%d", f.OwnerStatus)),
		confStyle.Render(fmt.Sprintf("%d", f.TesterStatus)),
	)

	fmt.Printf("  %s %.1f%%     %s %.1f%%\n",
		labelStyle.Render("Similarity:"),
		f.Similarity*100,
		labelStyle.Render("Size Δ:"),
		f.SizeDelta*100,
	)

	if f.Notes != "" {
		fmt.Printf("  %s %s\n",
			labelStyle.Render("Notes:"),
			valueStyle.Render(f.Notes),
		)
	}

	fmt.Printf("  %s\n", labelStyle.Render("Reproduce:"))
	fmt.Printf("    %s\n", valueStyle.Render(f.CurlCommand))

	fmt.Println()
	fmt.Println(dividerStyle.Render("  " + strings.Repeat("─", 72)))
	fmt.Println()
}

// countByConfidence counts findings by confidence level.
func countByConfidence(findings []*graph.Finding) (high, medium, low int) {
	for _, f := range findings {
		if strings.HasPrefix(f.Notes, "[DEDUPLICATED]") {
			continue
		}
		switch f.ConfidenceLevel {
		case graph.ConfidenceHigh:
			high++
		case graph.ConfidenceMedium:
			medium++
		case graph.ConfidenceLow:
			low++
		}
	}
	return
}
