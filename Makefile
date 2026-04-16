.PHONY: build test test-unit test-integration vet fmt lint install clean

BINARY = airlock

build:
	go build -o $(BINARY) .

test: test-unit test-integration

test-unit:
	go test ./internal/... -count=1 -race

test-integration:
	go test ./test/integration/... -count=1 -race

vet:
	go vet ./...

fmt:
	@gofmt -d . | grep -q . && echo "Formatting issues found. Run gofmt -w ." && exit 1 || echo "Formatting OK."

lint: vet fmt

install: build
	@cp $(BINARY) $(GOPATH)/bin/$(BINARY) 2>/dev/null || cp $(BINARY) $(HOME)/go/bin/$(BINARY)
	@echo "Installed to $(HOME)/go/bin/$(BINARY)"

clean:
	rm -f $(BINARY)