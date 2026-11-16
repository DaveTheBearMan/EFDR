VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: build bpf test test-root e2e e2e-fleet remote-check remote-reset remote-fleet remote-gate remote-block remote-detect remote-console remote-protect

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

e2e-fleet: build
	test/vm/e2e-fleet.sh

# The same tests on the hosts of inventory.ini (see test/vm/backend-ssh.sh).
remote-check:
	test/vm/remote.sh check
remote-reset:
	test/vm/remote.sh reset
remote-fleet: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-fleet.sh
remote-gate: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-gate.sh
remote-block: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-block.sh
remote-detect: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-detect.sh
remote-console: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-console.sh
remote-protect: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-protect.sh
