VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: build bpf test test-root e2e e2e-net

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X xdr/internal/cli.Version=$(VERSION)" -o bin/xdr ./cmd/xdr

# Rebuilds the eBPF object and its Go bindings (needs clang, llvm and
# libbpf-dev). The results are checked in: a plain build needs none of it.
bpf:
	go generate ./internal/sensor

test:
	go test ./...

# Tests that need root: kernel tests in throwaway network namespaces.
test-root: build
	sudo env "GOMODCACHE=$$(go env GOMODCACHE)" "$$(command -v go)" test -count=1 -run Kernel ./internal/...
	sudo test/netns/fw.sh
	sudo FW_NO_NAT=1 test/netns/fw.sh

e2e: build
	test/vm/e2e.sh

e2e-net: build
	test/vm/e2e-net.sh
