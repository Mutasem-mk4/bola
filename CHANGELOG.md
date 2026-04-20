# Changelog

All notable changes to bola will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-04-20

### Added
- MITM HTTP/HTTPS proxy engine using goproxy
- Object ID extraction from URL paths, query parameters, JSON bodies, and headers
- Support for UUID, integer, MongoDB ObjectID, and hash-type identifiers
- HAR 1.2 file import (Burp Suite / ZAP Proxy compatibility)
- SQLite-backed resource graph with endpoints, resources, and relationships
- Multi-identity vault with JWT, Cookie, Bearer, and Basic auth auto-detection
- JWT expiration extraction and monitoring
- Token auto-refresh via refresh_token flows
- Cross-identity authorization replay engine with configurable workers and rate limiting
- Multi-step workflow support (parent-child resource chain testing)
- Response comparison using Jaccard similarity on flattened JSON key sets
- Multi-factor confidence scoring (status code, body size, structure, error detection)
- False-positive detection for "200 with error body" responses
- Path normalization and smart finding deduplication
- Terminal output with lipgloss hacker-aesthetic styling
- JSON report export (nuclei/httpx compatible structure)
- HackerOne/Bugcrowd-ready Markdown report generation
- Curl reproduction commands for every finding
- YAML configuration with validation and defaults
- `bola config init` for generating example configuration
- Man page (troff format)
- Debian packaging files (control, rules, changelog, copyright)
- nFPM configuration for .deb and .rpm generation
- GitHub Actions CI/CD: lint, test, multi-arch build, release
- crAPI integration test workflow
- Dependabot for Go modules and GitHub Actions
