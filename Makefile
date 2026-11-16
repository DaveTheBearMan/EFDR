VERSION := $(shell git describe --always --dirty 2>/dev/null || echo dev)

.PHONY: build bpf embed-baseline test test-root e2e e2e-fleet remote-check remote-reset remote-fleet remote-gate remote-block remote-detect remote-console remote-protect remote-deploy

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X xdr/internal/cli.Version=$(VERSION)" -o bin/xdr ./cmd/xdr

# Rebuilds the eBPF object and its Go bindings (needs clang, llvm and
# libbpf-dev). The results are checked in: a plain build needs none of it.
bpf:
	go generate ./internal/sensor

# Rebuilds the embedded baseline from a clean image mounted (read-only is
# fine) at IMAGE_ROOT, then the binary that carries it. Run as root so the
# capture can read every file.
EMBED_OUT ?= internal/baseline/data/base.json.gz
embed-baseline: build
	@test -n "$(IMAGE_ROOT)" || { echo "set IMAGE_ROOT to the mounted clean image"; exit 1; }
	bin/xdr capture --root "$(IMAGE_ROOT)" --out "$(EMBED_OUT)"
	$(MAKE) build

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
remote-deploy: build
	XDR_E2E_BACKEND=ssh test/vm/e2e-deploy.sh
