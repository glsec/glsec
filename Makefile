# Copyright The glsec Authors
# SPDX-License-Identifier: Apache-2.0

build:
	go build -o glsec ./cmd/glsec

test:
	go test ./...

lint:
	golangci-lint run ./...

.PHONY: build test lint
