VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: build test test-root e2e

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X xdr/internal/cli.Version=$(VERSION)" -o bin/xdr ./cmd/xdr

test:
	go test ./...

# Tests that need root: kernel tests in throwaway network namespaces.
test-root: build
	sudo env "GOMODCACHE=$$(go env GOMODCACHE)" "$$(command -v go)" test -count=1 -run Kernel ./internal/...
	sudo test/netns/fw.sh

e2e: build
	test/vm/e2e.sh
