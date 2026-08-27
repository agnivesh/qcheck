.PHONY: build test test-short vet fmt lint

build:
	go build -o bin/qcheck .

test:
	go test ./...

test-short:
	go test -short ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

lint: vet
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed; skipping"
