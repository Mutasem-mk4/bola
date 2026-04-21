// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package reporter

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/Mutasem-mk4/bola/internal/graph"
)

var (
	colorRed     = lipgloss.Color("#FF6B6B")
	colorYellow  = lipgloss.Color("#F9CA24")
	colorBlue    = lipgloss.Color("#45B7D1")
	colorGreen   = lipgloss.Color("#4ECDC4")
	colorMagenta = lipgloss.Color("#6C5CE7")
	colorGray    = lipgloss.Color("#636E72")
	colorWhite   = lipgloss.Color("#DFE6E9")
)

var (
	bannerStyle  = lipgloss.NewStyle().Bold(true).Foreground(colorMagenta)
	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(colorWhite).Background(lipgloss.Color("#2D3436")).Padding(0, 2)
	highStyle    = lipgloss.NewStyle().Bold(true).Foreground(colorRed)
	mediumStyle  = lipgloss.NewStyle().Bold(true).Foreground(colorYellow)
	lowStyle     = lipgloss.NewStyle().Bold(true).Foreground(colorBlue)
	labelStyle   = lipgloss.NewStyle().Foreground(colorGray)
	valueStyle   = lipgloss.NewStyle().Foreground(colorWhite)
	successStyle = lipgloss.NewStyle().Foreground(colorGreen)
	dividerStyle = lipgloss.NewStyle().Foreground(colorGray)
)

const bannerArt = `
  ██████╗  ██████╗ ██╗      █████╗
  ██╔══██╗██╔═══██╗██║     ██╔══██╗
  ██████╔╝██║   ██║██║     ███████║
  ██╔══██╗██║   ██║██║     ██╔══██║
  ██████╔╝╚██████╔╝███████╗██║  ██║
  ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝
  Identity Orchestration Engine for BOLA/IDOR Detection
`

// PrintBanner outputs the ASCII banner with version info.
func PrintBanner(version string) {
	fmt.Println(bannerStyle.Render(bannerArt))
	fmt.Printf("  %s\n\n", labelStyle.Render("v"+version))
}

// PrintSummary outputs aggregate scan statistics.
func PrintSummary(stats graph.Stats) {
	fmt.Println(titleStyle.Render(" SCAN RESULTS "))
	fmt.Println()
	fmt.Printf("  %s %d   %s %d   %s %d   %s %d\n",
		labelStyle.Render("Endpoints:"), stats.Endpoints,
		labelStyle.Render("Resources:"), stats.Resources,
		labelStyle.Render("Requests:"), stats.Requests,
		labelStyle.Render("Findings:"), stats.Findings,
	)
	fmt.Println()
}

// PrintFindings outputs all findings to the terminal with lipgloss styling.
func PrintFindings(findings []*graph.Finding) {
	if len(findings) == 0 {
		fmt.Println(successStyle.Render("  ✓ No BOLA/IDOR vulnerabilities detected"))
		fmt.Println()
		return
	}

	high, medium, low := countByConfidence(findings)
	fmt.Printf("  %s %s   %s %s   %s %s\n",
		highStyle.Render("●"), highStyle.Render(fmt.Sprintf("HIGH: %d", high)),
		mediumStyle.Render("●"), mediumStyle.Render(fmt.Sprintf("MEDIUM: %d", medium)),
		lowStyle.Render("●"), lowStyle.Render(fmt.Sprintf("LOW: %d", low)),
	)
	fmt.Println()
	fmt.Println(dividerStyle.Render("  " + strings.Repeat("─", 72)))
	fmt.Println()

	for i, f := range findings {
		if strings.HasPrefix(f.Notes, "[DEDUPLICATED]") {
			continue
		}
		printFinding(i+1, f)
	}
}

func printFinding(index int, f *graph.Finding) {
	confStyle := lowStyle
	confColor := lipgloss.Color("#45B7D1")
	if f.ConfidenceLevel == graph.ConfidenceHigh {
		confStyle = highStyle
		confColor = lipgloss.Color("#FF4757")
	} else if f.ConfidenceLevel == graph.ConfidenceMedium {
		confStyle = mediumStyle
		confColor = lipgloss.Color("#FFA502")
	}

	method, path := "", ""
	if f.Endpoint != nil {
		method = f.Endpoint.Method
		path = f.Endpoint.Path
	}

	// Card Header
	headerLeft := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF")).Background(confColor).Padding(0, 1).Render(string(f.ConfidenceLevel))
	headerRight := labelStyle.Render(fmt.Sprintf("Finding #%d", index))

	header := lipgloss.JoinHorizontal(lipgloss.Top, headerLeft, "  ", headerRight, "\n")

	// Details Grid
	details := fmt.Sprintf("%s %s %s\n%s %s → %s\n%s %s → %s\n%s %.1f%%     %s %.1f%%",
		labelStyle.Render("Endpoint: "), valueStyle.Render(method), valueStyle.Render(path),
		labelStyle.Render("Identity: "), valueStyle.Render(f.OwnerIdentity), confStyle.Render(f.TesterIdentity),
		labelStyle.Render("Status:   "), valueStyle.Render(fmt.Sprintf("%d", f.OwnerStatus)), confStyle.Render(fmt.Sprintf("%d", f.TesterStatus)),
		labelStyle.Render("Sim Score:"), f.Similarity*100, labelStyle.Render("Size Δ:"), f.SizeDelta*100,
	)

	// Notes & Reproduction
	extra := ""
	if f.Notes != "" {
		extra += "\n\n" + labelStyle.Render("Notes:") + "\n" + valueStyle.Render(f.Notes)
	}

	extra += "\n\n" + labelStyle.Render("Reproduce:") + "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#A4B0BE")).Render(fmt.Sprintf("  $ %s", f.CurlCommand))

	// Assemble Card
	cardContent := lipgloss.JoinVertical(lipgloss.Left, header, details, extra)
	card := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(confColor).
		Padding(1, 2).
		MarginBottom(1).
		Width(70).
		Render(cardContent)

	fmt.Println(card)
}

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
