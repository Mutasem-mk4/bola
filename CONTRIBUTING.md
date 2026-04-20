# Contributing to bola

Thank you for your interest in contributing to bola! This document provides
guidelines and information for contributors.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/bola`
3. Create a branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `make test`
6. Run lint: `make lint`
7. Commit with a clear message
8. Push and open a Pull Request

## Development Setup

### Prerequisites

- Go >= 1.21
- golangci-lint (for linting)

### Build & Test

```bash
make build-only    # Build for current platform
make test          # Run all tests with race detector
make lint          # Run golangci-lint
make dev           # Test + build (quick dev cycle)
```

## Code Guidelines

### Style

- Follow standard Go conventions (`gofmt`, `goimports`)
- All `.go` files must have SPDX license headers:
  ```go
  // SPDX-License-Identifier: MIT
  // Copyright (C) 2025 Mutasem Kharma
  ```
- Use `internal/` packages for non-public APIs
- Write table-driven tests where possible
- Keep functions focused and under 50 lines when practical

### Commit Messages

Use clear, descriptive commit messages:
- `feat: add GraphQL endpoint support`
- `fix: handle empty response body in analyzer`
- `docs: update installation instructions`
- `test: add integration test for HAR import`
- `refactor: extract ID classification logic`

### Pull Request Process

1. Ensure all tests pass
2. Ensure lint passes with no warnings
3. Update CHANGELOG.md if applicable
4. Update documentation if you changed behavior
5. Add tests for new functionality
6. Fill out the PR template

## Architecture

See [README.md](README.md#-architecture) for the full architecture overview.

Key principles:
- Each package in `internal/` has a single responsibility
- The `graph.DB` is the central data store
- The `vault.Vault` manages all identity state
- Packages communicate via well-defined interfaces, not globals

## Priority Contribution Areas

- **Token formats:** API keys, HMAC signatures, custom auth schemes
- **Protocol support:** GraphQL, gRPC-web, WebSocket
- **Import formats:** OpenAPI/Swagger spec, Postman collections
- **Analysis:** Better false-positive detection heuristics
- **Performance:** Concurrent proxy processing optimization

## Reporting Bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md).
Include your bola version, OS, and a minimal reproduction case.

## Security

If you discover a security vulnerability, please follow the process
in [SECURITY.md](SECURITY.md). Do not open a public issue.

## License

By contributing, you agree that your contributions will be licensed
under the MIT License.
