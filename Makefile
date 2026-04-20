# SPDX-License-Identifier: MIT
# Copyright (C) 2025 Mutasem Kharma
#
# Makefile for bola — BOLA/IDOR detection engine
#
# Required tools:
#   - Go >= 1.21
#
# Typical workflow:
#   make build      # build the bola binary
#   make test       # run all tests
#   make install    # install to /usr/bin and /usr/share/man

.PHONY: build build-only install uninstall clean lint test man completions dev

# Version info
VERSION     ?= 0.1.0
GO_VERSION   = $(shell go version 2>/dev/null | awk '{print $$3}')
GOARCH      ?= $(shell go env GOARCH)
DESTDIR     ?=

# Build flags — static binary, no CGO
LDFLAGS = -s -w \
	-X github.com/Mutasem-mk4/bola/cmd/bola.Version=$(VERSION) \
	-X github.com/Mutasem-mk4/bola/cmd/bola.BuildGoVersion=$(GO_VERSION)

# Build the bola binary (default target).
build:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH) go build -trimpath \
		-ldflags="$(LDFLAGS)" -o bin/bola ./cmd/bola

# Build without setting GOOS (for local dev on any platform).
build-only:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/bola ./cmd/bola

# Install bola binary and man page to system paths.
# Respects DESTDIR for package building (e.g., dpkg-buildpackage).
install: build
	install -Dm 0755 bin/bola $(DESTDIR)/usr/bin/bola
	install -Dm 0644 man/bola.1 $(DESTDIR)/usr/share/man/man1/bola.1

# Uninstall bola from system paths.
uninstall:
	rm -f $(DESTDIR)/usr/bin/bola
	rm -f $(DESTDIR)/usr/share/man/man1/bola.1

# Clean build artifacts.
clean:
	rm -rf bin/ dist/ release-dist/
	rm -f coverage.out

# Run golangci-lint.
lint:
	golangci-lint run ./...

# Run all tests with race detector.
test:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

# Compress man page for distribution.
man:
	gzip -k man/bola.1

# Generate shell completions.
completions: build
	bin/bola completion bash > completions/bola.bash
	bin/bola completion zsh  > completions/bola.zsh
	bin/bola completion fish > completions/bola.fish

# Cross-compilation check (build verification, not functional on non-Linux).
check-build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o /dev/null ./cmd/bola
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o /dev/null ./cmd/bola

# Quick development cycle: test + build.
dev: test build-only
