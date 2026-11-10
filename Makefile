VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: build test e2e

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X xdr/internal/cli.Version=$(VERSION)" -o bin/xdr ./cmd/xdr

test:
	go test ./...

e2e: build
	test/vm/e2e.sh
