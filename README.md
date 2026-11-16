# XDR

A host defense platform for blue-team competitions: one static Go binary that runs as an **agent** on every Linux target and as a **controller** on the operator's jump box. Red-team footholds die fast and stay dead, scored services stay up, and everything is visible and approvable from one web console.

Written for one known OS (Ubuntu 24.04) and one competition, so it hard-codes what a general product would make configurable. Everything is pre-staged: nothing is built live.

## What it does

| Area | Behaviour |
|------|-----------|
| Drift | Hashes the box against a clean baseline across the persistence locations and reports what was added or altered; the console offers to remove a file (with undo). |
| Process response | Detects reverse shells, C2 callbacks and unexpected listeners; kills them (or reports `would-kill` while kill is off). Scored services are held for a click, gray accounts are alert-only. |
| Firewall | Detect-first: policy accept, with blocks only for endpoints the fleet has found malicious. Egress is judged by process. Agent ports open only to the jump box and peers. |
| SSH gate | A PAM hook holds unapproved sessions and ends them after a grace window; blue and recovery accounts and break-glass tokens keep the team in. |
| Fleet | Embedded etcd on the controller, a peer mesh, signed rules written from each detection and pushed to every box, hunts for dropped implants. |
| Console | One HTTPS page: alerts, approvals, hosts, break-glass, credential rotation, and a per-host kill on/off switch. |
| Self-protection | Six launch points, three binary copies, two guards that watch each other, tamper detection that names and kills the writer, a reconnect ladder that undoes planted isolation, controller reinstall over SSH, and a signed uninstall. |

## Build

    make build          # bin/xdr, static (CGO_ENABLED=0)
    go test ./...       # unit tests

`make embed-baseline IMAGE_ROOT=<root of a clean image>` bakes a baseline into the binary; otherwise a baseline is captured on each target at install time.

## Quick start

The day-1 runbook is [`deploy/README.md`](deploy/README.md). In short:

    # jump box
    printf '%s\n' "$PASSWORD" | xdr controller install --dir /root/xdr-ctl --name JUMP_IP
    xdr controller add-target --dir /root/xdr-ctl --host web01 --out web01.tgz \
        --listeners facts.json --scored tcp/80 --blue alice --recovery xdrrecover --recovery-key rec.pub
    # target
    tar -xzf web01.tgz && ./install-target.sh

Then open `https://JUMP_IP:8443`. Kill starts **off**; switch it on per host in the console once the incidents look right.

## Docs

- [`docs/GUIDE.md`](docs/GUIDE.md): operator guide (concepts, console, tokens, what to expect).
- [`deploy/README.md`](deploy/README.md): day-1 install runbook.
- [`docs/superpowers/specs/2026-11-10-xdr-design.md`](docs/superpowers/specs/2026-11-10-xdr-design.md): design and the builder's calls.
- [`docs/superpowers/plans/`](docs/superpowers/plans/): the plans each stage was built from.

## Tests

Unit tests run anywhere. End-to-end suites run on real boxes through an `inventory.ini` (a controller host and targets, reached over SSH): `make remote-check`, then `remote-protect`, `remote-gate`, `remote-console`, `remote-block`, `remote-detect`, `remote-fleet`, `remote-deploy`. Pick the ones that cover the area you changed. `make test-root` covers the kernel-facing code (nftables, fanotify) and needs sudo.

## Scope

Strictly on-box response: kill, block, remove. Nothing is ever done to red-team infrastructure. Windows hosts and rootkit detection are out of scope.
