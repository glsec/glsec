build:
	go build -o glsec ./cmd/glsec

test:
	go test ./...

lint:
	golangci-lint run ./...

.PHONY: build test lint
