BINARY  := bin/secretum
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: help build run test cover lint fmt tidy up down clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-8s %s\n", $$1, $$2}'

build: ## Build the service binary
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/secretum

run: ## Run the service locally
	go run ./cmd/secretum

test: ## Run tests with the race detector
	go test -race -count=1 ./...

cover: ## Run tests and print coverage summary
	go test -race -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code
	golangci-lint fmt

tidy: ## Tidy go.mod
	go mod tidy

up: ## Start the local stack (app, PostgreSQL, S3 storage)
	docker compose up -d --build

down: ## Stop the local stack
	docker compose down

clean: ## Remove build artifacts
	$(RM) -r bin coverage.out
