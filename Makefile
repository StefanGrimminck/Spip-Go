SHELL := /bin/bash

.PHONY: all fmt check-fmt test e2e build vet

all: test

# Format Go source files (requires Go toolchain in PATH)
fmt:
	@echo "Formatting Go files..."
	@go fmt ./...

# Check formatting (lists files that are not gofmt'd)
check-fmt:
	@echo "Checking Go formatting..."
	@gofmt -l . | tee /dev/stderr

test:
	@echo "Running unit tests..."
	@go test ./internal/... ./pkg/...

e2e:
	@echo "Running e2e tests inside container (requires Docker)"
	@./scripts/run_e2e_in_container.sh

build:
	@echo "Building spip-agent..."
	@go build -o spip-agent ./cmd/spip-agent

vet:
	@echo "Running go vet..."
	@go vet ./...
