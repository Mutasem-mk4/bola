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
	Version        = "dev"
	BuildGoVersion = "unknown"
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

Usage:
  1. Configure identities:  bola config init
  2. Capture traffic:       bola proxy --config bola.yaml
  3. Run tests:             bola scan --config bola.yaml
  4. Generate reports:      bola report --config bola.yaml`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print bola version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("bola %s (built with %s)\n", Version, BuildGoVersion)
	},
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate an example bola.yaml configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runConfigInit()
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
}

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Start the MITM proxy and build the resource graph",
	Long: `Start an HTTP/HTTPS proxy that transparently intercepts traffic.
While you browse the target application, bola silently maps every endpoint,
extracts object IDs from responses, and builds an ownership resource graph.

Configure your browser or API client to use the proxy at the address
specified in your bola.yaml configuration (default: 127.0.0.1:8080).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runProxy()
	},
}

var importCmd = &cobra.Command{
	Use:   "import [har-file]",
	Short: "Import a HAR file to build the resource graph",
	Long: `Parse a Burp Suite or ZAP Proxy HAR export to build the resource
graph without live proxy interception. This is useful when you've already
captured traffic in another tool.`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runImport(args[0])
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run cross-identity authorization tests",
	Long: `For every resource discovered in the resource graph, replay the
request using each other identity. Compare responses to detect BOLA/IDOR
vulnerabilities with confidence scoring.

The resource graph must be built first using 'bola proxy' or 'bola import'.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runScan()
	},
}

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate reports from existing scan results",
	Long: `Generate terminal, JSON, and/or Markdown reports from the findings
stored in the bola database. Useful for re-generating reports with different
formats or after manual review.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runReport()
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "bola.yaml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress non-essential output")

	configCmd.AddCommand(configInitCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(proxyCmd)
	rootCmd.AddCommand(importCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(reportCmd)
}
