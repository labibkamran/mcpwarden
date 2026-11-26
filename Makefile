VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := bin/mcpwarden

GOVULNCHECK_VERSION := v1.10.0

.PHONY: check build test cover lint fmt vet vuln tidy clean

# check runs everything CI runs, in the same order.
check: vet lint test vuln build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) ./cmd/mcpwarden

test:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

lint:
	golangci-lint run

fmt:
	golangci-lint fmt

vet:
	go vet ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

tidy:
	go mod tidy

clean:
	rm -rf bin dist coverage.out
