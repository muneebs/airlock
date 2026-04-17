.PHONY: build test test-unit test-integration vet fmt lint install clean dist release snapshot changelog

BINARY = airlock
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
GOPATH := $(shell go env GOPATH 2>/dev/null || echo $(HOME)/go)

LDFLAGS = -s -w -X github.com/muneebs/airlock/cmd/airlock/cli.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

test: test-unit test-integration

test-unit:
	go test ./internal/... -count=1 -race

test-integration:
	go test ./test/integration/... -count=1 -race

vet:
	go vet ./...

fmt:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then \
		echo "Formatting issues found in:"; echo "$$out"; \
		echo "Run 'gofmt -w .' to fix."; \
		exit 1; \
	fi; \
	echo "Formatting OK."

lint: vet fmt

install: build
	@mkdir -p $(GOPATH)/bin
	@cp $(BINARY) $(GOPATH)/bin/$(BINARY)
	@echo "Installed to $(GOPATH)/bin/$(BINARY)"

dist:
	goreleaser build --clean --snapshot

snapshot:
	goreleaser release --clean --snapshot

release:
	goreleaser release --clean

changelog:
	@goreleaser changelog 2>/dev/null || (echo "goreleaser not installed. Install with: brew install goreleaser/tap/goreleaser" && exit 1)

clean:
	rm -f $(BINARY)