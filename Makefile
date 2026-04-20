# SPDX-License-Identifier: MIT
# Makefile for bola — Identity Orchestration Engine for BOLA/IDOR Detection

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GO_VERSION  := $(shell go version | awk '{print $$3}')
BINARY      := bola
DIST        := dist
MODULE      := github.com/Mutasem-mk4/bola
LDFLAGS     := -s -w -X main.version=$(VERSION) -X main.buildGoVersion=$(GO_VERSION)
BUILD_FLAGS := -trimpath -ldflags="$(LDFLAGS)"

.PHONY: all build build-arm64 build-only test lint clean install dev check-build help

all: lint test build

## build: Build static binary for linux/amd64
build: test
	@echo "==> Building bola $(VERSION) for linux/amd64"
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY) ./cmd/bola
	@echo "==> Binary: $(DIST)/$(BINARY)"

## build-arm64: Build static binary for linux/arm64
build-arm64: test
	@echo "==> Building bola $(VERSION) for linux/arm64"
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY)-arm64 ./cmd/bola
	@echo "==> Binary: $(DIST)/$(BINARY)-arm64"

## build-only: Build without running tests first
build-only:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=$${GOARCH:-amd64} go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY) ./cmd/bola

## test: Run all tests with race detector and coverage
test:
	@echo "==> Running tests..."
	go test -race -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

## lint: Run golangci-lint
lint:
	@echo "==> Linting..."
	golangci-lint run --timeout=5m

## clean: Remove build artifacts
clean:
	@echo "==> Cleaning..."
	rm -rf $(DIST)/ coverage.out bola-report.* bola.db

## install: Install binary and man page
install: build
	@echo "==> Installing bola to /usr/local/bin"
	install -D -m 0755 $(DIST)/$(BINARY) /usr/local/bin/$(BINARY)
	install -D -m 0644 man/bola.1 /usr/share/man/man1/bola.1
	@echo "==> Installed. Run 'bola --help' to get started."

## uninstall: Remove installed files
uninstall:
	rm -f /usr/local/bin/$(BINARY)
	rm -f /usr/share/man/man1/bola.1

## dev: Quick dev cycle (test + build for current OS)
dev: test
	@mkdir -p $(DIST)
	go build $(BUILD_FLAGS) -o $(DIST)/$(BINARY) ./cmd/bola
	@echo "==> Built $(DIST)/$(BINARY)"

## check-build: Cross-compile check for both architectures
check-build:
	@echo "==> Cross-compile check: linux/amd64"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o /dev/null ./cmd/bola
	@echo "    ✓ linux/amd64"
	@echo "==> Cross-compile check: linux/arm64"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o /dev/null ./cmd/bola
	@echo "    ✓ linux/arm64"

## completions: Generate shell completions
completions:
	@mkdir -p completions
	go run ./cmd/bola completion bash > completions/bola.bash
	go run ./cmd/bola completion zsh  > completions/bola.zsh
	@echo "==> Shell completions generated"

## help: Show this help
help:
	@echo "bola $(VERSION) — Build targets:"
	@echo ""
	@grep -E '^## ' Makefile | sed 's/## /  /' | sort
