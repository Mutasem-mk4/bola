// SPDX-License-Identifier: MIT
// Copyright (C) 2025 Mutasem Kharma

// Package main implements the bola CLI — a next-generation Identity
// Orchestration Engine for automated BOLA/IDOR detection.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version and build information, set by ldflags during build.
var (
	version        = "dev"
	buildGoVersion = "unknown"
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var (
	cfgFile string
	verbose bool
	quiet   bool
)

var rootCmd = &cobra.Command{
	Use:   "bola",
	Short: "BOLA/IDOR detection via identity orchestration",
	Long: `bola — Next-generation Identity Orchestration Engine for automated
Broken Object Level Authorization (BOLA/IDOR) detection.

Unlike replay-only tools (Autorize, AuthMatrix), bola understands resource
ownership. It dynamically builds a resource graph from live proxy traffic or
HAR imports, then systematically tests cross-identity access to every
discovered resource.

Quick Start (3 minutes):
  1. Generate config:   bola config init
  2. Edit bola.yaml:    add your target URL and session tokens
  3. Capture traffic:   bola proxy
  4. Run tests:         bola scan
  5. View reports:      bola report

Developed by Mutasem — Cybersecurity & Software Engineer
https://github.com/Mutasem-mk4`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print bola version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("bola %s (built with %s)\n", version, buildGoVersion)
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate an example bola.yaml configuration file",
	Long: `Generate a fully-commented bola.yaml with sensible defaults.
Edit the file to add your target URL and session tokens, then run bola proxy.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigInit()
	},
}

// Proxy flags
var proxyListen string

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start the MITM proxy and build the resource graph",
	Long: `Start an HTTP/HTTPS proxy that transparently intercepts traffic.
While browsing the target application, bola silently maps every endpoint,
extracts object IDs from responses, and builds an ownership resource graph.

The MITM CA certificate is auto-generated on first run.
Install it in your browser to inspect HTTPS traffic.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProxy()
	},
}

var importHARFile string

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a HAR file to build the resource graph",
	Long: `Parse a Burp Suite or ZAP Proxy HAR export to build the resource
graph without live proxy interception.

Usage: bola import --har traffic.har`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runImport()
	},
}

// Scan flags
var scanWorkers int
var scanRate int
var scanMinConfidence string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run cross-identity authorization tests",
	Long: `For every resource in the resource graph, replay the request using
each other identity. Compare responses to detect BOLA/IDOR vulnerabilities
with confidence scoring.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan()
	},
}

// Report flags
var reportFormat string
var reportMinConfidence string

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from existing scan results",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReport()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "bola.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-essential output")

	proxyCmd.Flags().StringVar(&proxyListen, "listen", "", "override proxy listen address")

	importCmd.Flags().StringVar(&importHARFile, "har", "", "HAR file to import")
	_ = importCmd.MarkFlagRequired("har")

	scanCmd.Flags().IntVar(&scanWorkers, "workers", 0, "override worker count")
	scanCmd.Flags().IntVar(&scanRate, "rate", 0, "override rate limit")
	scanCmd.Flags().StringVar(&scanMinConfidence, "min-confidence", "", "minimum confidence (HIGH/MEDIUM/LOW)")

	reportCmd.Flags().StringVar(&reportFormat, "format", "all", "output format (terminal|json|markdown|all)")
	reportCmd.Flags().StringVar(&reportMinConfidence, "min-confidence", "", "minimum confidence filter")

	configCmd.AddCommand(configInitCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(reportCmd)
}
