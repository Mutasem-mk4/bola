// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
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
		return nil, fmt.Errorf("loading config %q: %w", cfgFile, err)
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

// runConfigInit generates an example configuration file.
func runConfigInit() error {
	const filename = "bola.yaml"
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s already exists — remove it first or use a different name", filename)
	}
	if err := os.WriteFile(filename, []byte(config.ExampleConfig()), 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	fmt.Printf("[+] Generated %s — edit it with your target and identities\n", filename)
	return nil
}

// runProxy starts the MITM proxy and builds the resource graph.
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

	// Handle graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[*] Shutting down proxy...")
		cancel()
		p.Stop()
	}()

	if !quiet {
		fmt.Printf("[*] Starting MITM proxy on %s\n", cfg.Proxy.Listen)
		fmt.Printf("[*] CA certificate: %s\n", cfg.Proxy.TLS.CACert)
		fmt.Println("[*] Configure your browser to use this proxy")
		fmt.Println("[*] Press Ctrl+C to stop and proceed to scanning")
	}

	return p.Start()
}

// runImport parses a HAR file and builds the resource graph.
func runImport() error {
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

	if !quiet {
		fmt.Printf("[*] Importing HAR file: %s\n", importHARFile)
	}

	count, err := proxy.ImportHAR(importHARFile, cfg, db, v)
	if err != nil {
		return fmt.Errorf("importing HAR: %w", err)
	}

	if !quiet {
		fmt.Printf("[+] Imported %d requests from HAR file\n", count)
		stats := db.Stats()
		fmt.Printf("[+] Resource graph: %d endpoints, %d resources\n",
			stats.Endpoints, stats.Resources)
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
		stats := db.Stats()
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

	return nil
}
