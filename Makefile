BINARY     := i-hate-403
MODULE     := github.com/gyan-cell/i-hate-403
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS    := -ldflags="-s -w -X main.Version=$(VERSION)"
BUILD_DIR  := .
CMD        := ./cmd/i-hate-403

GO         := go
GOFLAGS    :=

.PHONY: all build test lint vet clean install tidy help

## build: compile the i-hate-403 binary
all: build

build:
	@echo "  BUILD  $(BINARY) $(VERSION)"
	$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(CMD)

## test: run all unit tests
test:
	@echo "  TEST"
	$(GO) test -race -count=1 ./internal/... ./cmd/...

## test-verbose: run tests with verbose output
test-verbose:
	$(GO) test -race -v -count=1 ./internal/... ./cmd/...

## vet: run go vet static analysis
vet:
	$(GO) vet ./...

## lint: run golangci-lint (must be installed separately)
lint:
	@which golangci-lint > /dev/null 2>&1 || (echo "golangci-lint not found: https://golangci-lint.run/usage/install/" && exit 1)
	golangci-lint run ./...

## tidy: tidy go modules
tidy:
	$(GO) mod tidy

## install: install the binary to GOPATH/bin
install:
	@echo "  INSTALL $(BINARY)"
	$(GO) install $(LDFLAGS) $(CMD)

## clean: remove build artifacts
clean:
	@echo "  CLEAN"
	rm -f $(BUILD_DIR)/$(BINARY)

## help: show this help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
