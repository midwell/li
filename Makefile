# SPDX-FileCopyrightText: 2026 Forsway Scandinavia AB
#
# SPDX-License-Identifier: Apache-2.0
#
# li is a library module. It produces no binary and no container image, so the
# build/docker/push targets the network-function repositories carry have no
# counterpart here; everything else mirrors them so the same commands work.

PROJECT_NAME             := li
VERSION                  ?= $(shell cat ./VERSION 2>/dev/null || echo "dev")

# Extract minimum Go version from go.mod file
GOLANG_MINIMUM_VERSION   ?= $(shell awk '/^go / {print $$2}' go.mod 2>/dev/null || echo "1.25")

## Build configuration
GO_PACKAGES              ?= ./...

## Directory configuration
COVERAGE_DIR             := .coverage

## Tool versions (for reproducible builds)
GOLANGCI_LINT_VERSION    ?= latest

# Default target
.DEFAULT_GOAL := help

## Help target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  %-20s %s\n", $$1, $$2 }' $(MAKEFILE_LIST) | sort

## Build targets
build: ## Compile all packages
	@echo "Building $(PROJECT_NAME)..."
	@CGO_ENABLED=0 go build $(GO_PACKAGES)

all: build ## Compile all packages (alias for compatibility)

## Testing targets
$(COVERAGE_DIR): ## Create coverage directory
	@mkdir -p $(COVERAGE_DIR)

test: $(COVERAGE_DIR) ## Run unit tests with coverage
	@echo "Running unit tests..."
	@docker run --rm \
		-v $(CURDIR):/$(PROJECT_NAME) \
		-w /$(PROJECT_NAME) \
		golang:$(GOLANG_MINIMUM_VERSION) \
		go test \
			-race \
			-failfast \
			-coverprofile=$(COVERAGE_DIR)/coverage-unit.txt \
			-covermode=atomic \
			-v \
			$(GO_PACKAGES)

test-local: $(COVERAGE_DIR) ## Run unit tests locally (without Docker)
	@echo "Running unit tests locally..."
	@go test \
		-race \
		-failfast \
		-coverprofile=$(COVERAGE_DIR)/coverage-unit.txt \
		-covermode=atomic \
		-v \
		$(GO_PACKAGES)

## Code quality targets
fmt: ## Format Go code
	@echo "Formatting Go code..."
	@go fmt ./...

lint: ## Run linter
	@echo "Running linter..."
	@docker run --rm \
		-v $(CURDIR):/app \
		-w /app \
		golangci/golangci-lint:$(GOLANGCI_LINT_VERSION) \
		golangci-lint run -v --config /app/.golangci.yml

lint-local: ## Run linter locally (without Docker)
	@echo "Running linter locally..."
	@golangci-lint run -v --config .golangci.yml

check-reuse: ## Check REUSE compliance
	@echo "Checking REUSE compliance..."
	@docker run --rm \
		-v $(CURDIR):/$(PROJECT_NAME) \
		-w /$(PROJECT_NAME) \
		omecproject/reuse-verify:latest \
		reuse lint

check: fmt lint check-reuse ## Run all code quality checks

## Utility targets
clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf $(COVERAGE_DIR)

print-version: ## Print current version
	@echo $(VERSION)

env: ## Print environment variables
	@echo "PROJECT_NAME=$(PROJECT_NAME)"
	@echo "VERSION=$(VERSION)"
	@echo "GOLANG_MINIMUM_VERSION=$(GOLANG_MINIMUM_VERSION)"

## Phony targets
.PHONY: all \
        build \
        check \
        check-reuse \
        clean \
        env \
        fmt \
        help \
        lint \
        lint-local \
        print-version \
        test \
        test-local
