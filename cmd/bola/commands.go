// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/Mutasem-mk4/bola/internal/config"
	"github.com/Mutasem-mk4/bola/internal/dedup"
	"github.com/Mutasem-mk4/bola/internal/graph"
	"github.com/Mutasem-mk4/bola/internal/proxy"
	"github.com/Mutasem-mk4/bola/internal/reporter"
	"github.com/Mutasem-mk4/bola/internal/tester"
	"github.com/Mutasem-mk4/bola/internal/vault"
)

// loadConfig reads and validates the configuration file.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf("loading config %q: %w\n\n"+
			"  Hint: Run 'bola config init' to generate a starter config.", cfgFile, err)
	}

	// Apply CLI flag overrides
	if proxyListen != "" {
		cfg.Proxy.Listen = proxyListen
	}
	if scanWorkers > 0 {
		cfg.Testing.Workers = scanWorkers
	}
	if scanRate > 0 {
		cfg.Testing.RateLimit = scanRate
	}
	if scanMinConfidence != "" {
		cfg.Analysis.MinConfidence = strings.ToUpper(scanMinConfidence)
	}
	if reportMinConfidence != "" {
		cfg.Analysis.MinConfidence = strings.ToUpper(reportMinConfidence)
	}

	return cfg, nil
}

// setupLogging configures slog based on verbosity flags.
func setupLogging() {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	if quiet {
		level = slog.LevelError
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))
}

// runConfigInit writes the example YAML config to disk. No wizard, no prompts
// — just a perfectly commented config file ready to edit.
func runConfigInit() error {
	const filename = "bola.yaml"
	if _, err := os.Stat(filename); err == nil {
		fmt.Printf("[!] %s already exists. Overwrite? (y/n) ", filename)
		var confirm string
		fmt.Scanln(&confirm)
		if strings.ToLower(confirm) != "y" {
			fmt.Println("[*] Cancelled. Your existing config is unchanged.")
			return nil
		}
	}

	if err := os.WriteFile(filename, []byte(config.ExampleConfig()), 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	fmt.Println()
	fmt.Println("  ✓ Config written to bola.yaml")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Println("    1. Edit bola.yaml — add your target URL and session tokens")
	fmt.Println("    2. Run: bola proxy        (browse your target as each user)")
	fmt.Println("       OR:  bola import <file.har>   (import from Burp/ZAP)")
	fmt.Println("    3. Run: bola scan         (find the vulnerabilities)")
	fmt.Println("    4. Run: bola report       (view results)")
	fmt.Println()
	return nil
}

// runProxy starts the MITM proxy and builds the resource graph.
// No TUI — just clean stdout with live capture events.
func runProxy() error {
	setupLogging()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	db, err := graph.Open(cfg.Output.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	v, err := vault.New(cfg.Identities)
	if err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}

	// Start token refresher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := vault.NewRefresher(v)
	refresher.Start(ctx)
	defer refresher.Stop()

	p, err := proxy.New(cfg, db, v)
	if err != nil {
		return fmt.Errorf("creating proxy: %w", err)
	}

	// Print startup instructions
	printProxyBanner(cfg)

	// Track captured stats
	var reqCount, idCount atomic.Int64

	// Consume discovery events in background (print live)
	go func() {
		for ev := range p.Events {
			reqCount.Add(1)
			if ev.Type == proxy.DiscoveryResource {
				idCount.Add(1)
			}
			if !quiet {
				printProxyEvent(ev)
			}
		}
	}()

	// Start the proxy in a background goroutine
	go func() {
		if err := p.Start(); err != nil && err != http.ErrServerClosed {
			slog.Error("proxy server failed", "error", err)
		}
	}()

	// Wait for Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Graceful shutdown
	cancel()
	p.Stop()

	// Print summary
	stats := db.Stats()
	fmt.Println()
	fmt.Println("  ───────────────────────────────────────────")
	fmt.Printf("  Captured: %d requests, %d endpoints, %d resources\n",
		stats.Requests, stats.Endpoints, stats.Resources)
	fmt.Println()
	if stats.Endpoints > 0 {
		fmt.Println("  Next step: bola scan")
	} else {
		fmt.Println("  No traffic captured. Make sure your browser proxy is set to " + cfg.Proxy.Listen)
	}
	fmt.Println()

	return nil
}

// printProxyBanner prints clear startup instructions.
func printProxyBanner(cfg *config.Config) {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("  ║              bola proxy is running                          ║")
	fmt.Println("  ╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("  ║  Proxy address:  %-42s║\n", cfg.Proxy.Listen)
	fmt.Println("  ║                                                             ║")
	fmt.Println("  ║  STEP 1: Set your browser proxy to " + cfg.Proxy.Listen + strings.Repeat(" ", 24-len(cfg.Proxy.Listen)) + "║")
	fmt.Println("  ║  STEP 2: Log in as User A, browse the application           ║")
	fmt.Println("  ║  STEP 3: Log out, log in as User B, browse the same pages   ║")
	fmt.Println("  ║  STEP 4: Press Ctrl+C when done                             ║")
	fmt.Println("  ║                                                             ║")
	fmt.Printf("  ║  CA cert: %-51s║\n", cfg.Proxy.TLS.CACert+"  (install for HTTPS)")
	fmt.Println("  ╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Println("  Identities loaded:")
	for _, id := range cfg.Identities {
		fmt.Printf("    • %s (%s)\n", id.Name, id.Role)
	}
	fmt.Println()
	fmt.Println("  Live capture:")
}

// printProxyEvent prints a single captured event line.
func printProxyEvent(ev proxy.DiscoveryEvent) {
	switch ev.Type {
	case proxy.DiscoveryEndpoint:
		statusColor := "\033[32m" // green for 2xx
		if ev.Status >= 400 {
			statusColor = "\033[31m" // red for 4xx/5xx
		}
		fmt.Printf("    %s[%d]\033[0m %s %-50s (%s)\n",
			statusColor, ev.Status, ev.Method, ev.Path, ev.Identity)
	case proxy.DiscoveryResource:
		fmt.Printf("    \033[36m[ID]\033[0m  %-20s on %s (%s)\n",
			ev.Value, ev.Path, ev.Identity)
	}
}

// runImport parses a HAR file and builds the resource graph.
func runImport() error {
	setupLogging()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	// Get HAR file path from flag or positional arg
	harFile := importHARFile
	if harFile == "" {
		return fmt.Errorf("HAR file path is required\n\n" +
			"  Usage: bola import --har <file.har>\n" +
			"  Export HAR from: Burp Suite → File → Export → HTTP History → HAR\n" +
			"                   ZAP → File → Export → Messages → HAR")
	}

	if _, err := os.Stat(harFile); os.IsNotExist(err) {
		return fmt.Errorf("HAR file not found: %s\n\n"+
			"  Check the path and try again.", harFile)
	}

	db, err := graph.Open(cfg.Output.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	v, err := vault.New(cfg.Identities)
	if err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}

	if !quiet {
		fmt.Printf("[*] Importing HAR file: %s\n", harFile)
	}

	count, err := proxy.ImportHAR(harFile, cfg, db, v)
	if err != nil {
		return fmt.Errorf("importing HAR: %w", err)
	}

	if !quiet {
		stats := db.Stats()
		fmt.Printf("[+] Imported %d requests from HAR file\n", count)
		fmt.Printf("[+] Resource graph: %d endpoints, %d resources\n",
			stats.Endpoints, stats.Resources)
		fmt.Println()
		if stats.Endpoints > 0 {
			fmt.Println("  Next step: bola scan")
		} else {
			fmt.Println("  No in-scope requests found. Check your scope patterns in bola.yaml")
		}
		fmt.Println()
	}

	return nil
}

// runScan performs cross-identity authorization testing.
func runScan() error {
	setupLogging()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	db, err := graph.Open(cfg.Output.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	v, err := vault.New(cfg.Identities)
	if err != nil {
		return fmt.Errorf("creating vault: %w", err)
	}

	// Check if we have data to scan
	stats := db.Stats()
	if stats.Endpoints == 0 {
		fmt.Println()
		fmt.Println("  ⚠  No endpoints in resource graph.")
		fmt.Println()
		fmt.Println("  You need to capture traffic first:")
		fmt.Println("    • Run: bola proxy        (then browse your target)")
		fmt.Println("    • Or:  bola import --har <file.har>")
		fmt.Println()
		return nil
	}

	// Start token refresher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	refresher := vault.NewRefresher(v)
	refresher.Start(ctx)
	defer refresher.Stop()

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[*] Scan interrupted, generating report...")
		cancel()
	}()

	t := tester.New(cfg, db, v)

	if !quiet {
		fmt.Printf("[*] Scanning %d endpoints with %d resources across %d identities\n",
			stats.Endpoints, stats.Resources, len(cfg.Identities))
		fmt.Printf("[*] Workers: %d, Rate limit: %d/s, Jitter: %v\n",
			cfg.Testing.Workers, cfg.Testing.RateLimit, cfg.Testing.Jitter)
	}

	if err := t.Run(ctx); err != nil && ctx.Err() == nil {
		return fmt.Errorf("running scan: %w", err)
	}

	// Deduplicate findings
	dd := dedup.New(db)
	if err := dd.Run(); err != nil {
		return fmt.Errorf("deduplicating findings: %w", err)
	}

	// Generate reports
	return generateReports(cfg, db)
}

// runReport generates reports from existing findings.
func runReport() error {
	setupLogging()
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	db, err := graph.Open(cfg.Output.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// Apply format override
	if reportFormat != "" && reportFormat != "all" {
		switch reportFormat {
		case "terminal":
			cfg.Output.JSON = ""
			cfg.Output.Markdown = ""
			cfg.Output.Terminal = true
		case "json":
			cfg.Output.Terminal = false
			cfg.Output.Markdown = ""
		case "markdown":
			cfg.Output.Terminal = false
			cfg.Output.JSON = ""
		}
	}

	return generateReports(cfg, db)
}

// generateReports creates all configured report outputs.
func generateReports(cfg *config.Config, db *graph.DB) error {
	minConf := graph.Confidence(cfg.Analysis.MinConfidence)
	findings, err := db.ListFindings(minConf)
	if err != nil {
		return fmt.Errorf("listing findings: %w", err)
	}

	stats := db.Stats()

	if cfg.Output.Terminal {
		reporter.PrintBanner(version)
		reporter.PrintSummary(stats)
		reporter.PrintFindings(findings)
	}

	if cfg.Output.JSON != "" {
		if err := reporter.ExportJSON(findings, cfg.Output.JSON, version); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
		if !quiet {
			fmt.Printf("[+] JSON report: %s\n", cfg.Output.JSON)
		}
	}

	if cfg.Output.Markdown != "" {
		if err := reporter.ExportMarkdown(findings, cfg.Output.Markdown, cfg.Target.BaseURL); err != nil {
			return fmt.Errorf("writing Markdown report: %w", err)
		}
		if !quiet {
			fmt.Printf("[+] Markdown report: %s\n", cfg.Output.Markdown)
		}
	}

	if !quiet {
		fmt.Printf("[+] Total findings: %d (min confidence: %s)\n",
			len(findings), cfg.Analysis.MinConfidence)
	}

	// Print helpful diagnosis when no findings
	if len(findings) == 0 && !quiet {
		fmt.Println()
		fmt.Println("  No findings detected. This could mean:")
		fmt.Println("    • The application is properly secured (great!)")
		fmt.Println("    • Not enough traffic was captured (try browsing more)")
		fmt.Println("    • Try lowering --min-confidence to LOW")
		fmt.Println("    • Ensure you have at least 2 identities in bola.yaml")
		fmt.Println()
	}

	return nil
}
