// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Mutasem-mk4/bola/internal/analyzer"
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
	return cfg, nil
}

// runConfigInit generates an example configuration file.
func runConfigInit() error {
	const filename = "bola.yaml"
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("%s already exists; remove it first or use a different name", filename)
	}
	if err := os.WriteFile(filename, []byte(config.ExampleConfig()), 0644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	fmt.Printf("[+] Generated %s — edit it with your target and identities\n", filename)
	return nil
}

// runProxy starts the MITM proxy and builds the resource graph.
func runProxy() error {
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
	refresher := vault.NewRefresher(v)
	refresher.Start()
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
		p.Stop()
	}()

	if !quiet {
		fmt.Printf("[*] Starting MITM proxy on %s\n", cfg.Proxy.Listen)
		fmt.Println("[*] Configure your browser to use this proxy")
		fmt.Println("[*] Press Ctrl+C to stop and proceed to scanning")
	}

	return p.Start()
}

// runImport parses a HAR file and builds the resource graph.
func runImport(harFile string) error {
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
		fmt.Printf("[*] Importing HAR file: %s\n", harFile)
	}

	count, err := proxy.ImportHAR(harFile, cfg, db, v)
	if err != nil {
		return fmt.Errorf("importing HAR: %w", err)
	}

	if !quiet {
		fmt.Printf("[+] Imported %d requests from HAR file\n", count)
		ec, _ := db.CountEndpoints()
		rc, _ := db.CountResources()
		fmt.Printf("[+] Resource graph: %d endpoints, %d resources\n", ec, rc)
	}

	return nil
}

// runScan performs cross-identity authorization testing.
func runScan() error {
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

	// Start token refresher during scan
	refresher := vault.NewRefresher(v)
	refresher.Start()
	defer refresher.Stop()

	// Create analyzer
	az := analyzer.New(cfg.Analysis.SimilarityThreshold, cfg.Analysis.DetectErrorPatterns)

	// Create and run tester
	t := tester.New(cfg, db, v, az)

	if !quiet {
		ec, _ := db.CountEndpoints()
		rc, _ := db.CountResources()
		fmt.Printf("[*] Scanning %d endpoints with %d resources across %d identities\n",
			ec, rc, len(cfg.Identities))
	}

	if err := t.Run(); err != nil {
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
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	db, err := graph.Open(cfg.Output.Database)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	return generateReports(cfg, db)
}

// generateReports creates all configured report outputs.
func generateReports(cfg *config.Config, db *graph.DB) error {
	minConf := graph.Confidence(cfg.Analysis.MinConfidence)
	findings, err := db.ListFindings(minConf)
	if err != nil {
		return fmt.Errorf("listing findings: %w", err)
	}

	// Terminal output
	if cfg.Output.Terminal {
		reporter.PrintTerminal(findings)
	}

	// JSON report
	if cfg.Output.JSON != "" {
		if err := reporter.WriteJSON(findings, cfg.Output.JSON); err != nil {
			return fmt.Errorf("writing JSON report: %w", err)
		}
		if !quiet {
			fmt.Printf("[+] JSON report: %s\n", cfg.Output.JSON)
		}
	}

	// Markdown report
	if cfg.Output.Markdown != "" {
		if err := reporter.WriteMarkdown(findings, cfg.Output.Markdown, cfg.Target.BaseURL); err != nil {
			return fmt.Errorf("writing Markdown report: %w", err)
		}
		if !quiet {
			fmt.Printf("[+] Markdown report: %s\n", cfg.Output.Markdown)
		}
	}

	if !quiet {
		fc, _ := db.CountFindings()
		fmt.Printf("[+] Total findings: %d\n", fc)
	}

	return nil
}
