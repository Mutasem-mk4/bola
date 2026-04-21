// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/Mutasem-mk4/bola/internal/proxy"
)

// ProxyModel represents the TUI state for the proxy dashboard.
type ProxyModel struct {
	CapturedCount int
	EndpointCount int
	ResourceCount int
	IdentityCount int
	Events        []proxy.DiscoveryEvent
	TargetURL     string
	ProxyAddr     string
	StartTime     time.Time

	proxyChan     chan proxy.DiscoveryEvent
	width, height int
}

// NewProxyModel creates a new dashboard state.
func NewProxyModel(target, addr string, identities int, ch chan proxy.DiscoveryEvent) *ProxyModel {
	return &ProxyModel{
		TargetURL:     target,
		ProxyAddr:     addr,
		IdentityCount: identities,
		StartTime:     time.Now(),
		proxyChan:     ch,
		Events:        make([]proxy.DiscoveryEvent, 0),
	}
}

// waitForEvent is a tea.Cmd that waits for a new discovery event.
func waitForEvent(ch chan proxy.DiscoveryEvent) tea.Cmd {
	return func() tea.Msg {
		return <-ch
	}
}

func (m *ProxyModel) Init() tea.Cmd {
	return waitForEvent(m.proxyChan)
}

func (m *ProxyModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}

	case proxy.DiscoveryEvent:
		m.CapturedCount++
		if msg.Type == proxy.DiscoveryEndpoint {
			m.EndpointCount++
		} else if msg.Type == proxy.DiscoveryResource {
			m.ResourceCount++
		}

		// Keep last 15 events
		m.Events = append([]proxy.DiscoveryEvent{msg}, m.Events...)
		if len(m.Events) > 15 {
			m.Events = m.Events[:15]
		}

		return m, waitForEvent(m.proxyChan)
	}

	return m, nil
}

// Styling
var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF00")).
			Padding(0, 1)

	statBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#444444")).
			Padding(0, 1).
			Width(20)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#AAAAAA"))

	valueStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FFFFFF"))

	endpointStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	resourceStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FFFF"))
	status2xxStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00"))
	status4xxStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF0000"))
)

func (m *ProxyModel) View() string {
	if m.width < 40 {
		return "Terminal too small."
	}

	// Header
	header := headerStyle.Render("BOLA SENTINEL — LIVE DISCOVERY RADAR")
	info := fmt.Sprintf(" Target: %s  |  Proxy: %s  |  Uptime: %s",
		m.TargetURL, m.ProxyAddr, time.Since(m.StartTime).Round(time.Second))

	// Stats
	stats := lipgloss.JoinHorizontal(lipgloss.Top,
		statBoxStyle.Render(fmt.Sprintf("%s\n%s", labelStyle.Render("Requests"), valueStyle.Render(fmt.Sprint(m.CapturedCount)))),
		statBoxStyle.Render(fmt.Sprintf("%s\n%s", labelStyle.Render("Endpoints"), valueStyle.Render(fmt.Sprint(m.EndpointCount)))),
		statBoxStyle.Render(fmt.Sprintf("%s\n%s", labelStyle.Render("Resources"), valueStyle.Render(fmt.Sprint(m.ResourceCount)))),
		statBoxStyle.Render(fmt.Sprintf("%s\n%s", labelStyle.Render("Identities"), valueStyle.Render(fmt.Sprint(m.IdentityCount)))),
	)

	// Events Feed
	feed := "\n " + labelStyle.Render("LIVE DISCOVERY FEED") + "\n"
	for _, ev := range m.Events {
		line := ""
		if ev.Type == proxy.DiscoveryEndpoint {
			statusStyle := status2xxStyle
			if ev.Status >= 400 {
				statusStyle = status4xxStyle
			}
			line = fmt.Sprintf(" [%s] %s %-40s %s",
				statusStyle.Render(fmt.Sprint(ev.Status)),
				ev.Method,
				endpointStyle.Render(ev.Path),
				labelStyle.Render("("+ev.Identity+")"),
			)
		} else {
			line = fmt.Sprintf(" [NEW] RESOURCE %-35s %s %s",
				resourceStyle.Render(ev.Value),
				labelStyle.Render("on"),
				endpointStyle.Render(ev.Path),
			)
		}
		feed += " " + line + "\n"
	}

	// Controls
	footer := "\n " + lipgloss.NewStyle().Foreground(lipgloss.Color("#666666")).Render("Press Ctrl+C to stop and proceed to scan...")

	return lipgloss.JoinVertical(lipgloss.Left,
		header,
		info,
		"\n",
		stats,
		feed,
		footer,
	)
}
