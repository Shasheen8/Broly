BINARY_NAME=broly
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT)"
GOFLAGS=-trimpath

export PKG_CONFIG_PATH := $(PKG_CONFIG_PATH):/opt/homebrew/lib/pkgconfig

.PHONY: all build install test lint clean validate-rules

all: build

build:
	go build $(GOFLAGS) $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/broly

install:
	go install $(GOFLAGS) $(LDFLAGS) ./cmd/broly

test:
	go test -race -count=1 ./...

lint:
	golangci-lint run ./...

validate-rules:
	go run ./cmd/broly validate-rules

clean:
	rm -rf bin/
	go clean

release-snapshot:
	goreleaser release --snapshot --clean

fmt:
	gofmt -w -s .

vet:
	go vet ./...

check: fmt vet test validate-rules
