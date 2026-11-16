# Operator guide

Short version of how XDR behaves and what to do with it. Install steps are in [`deploy/README.md`](../deploy/README.md).

## The parts

- **Controller** (jump box): `xdr controller run`, started by `xdr-controller.service`. It holds the CA, the signing key, embedded etcd, the incident log and the console. Its directory (`/root/xdr-ctl`) is the crown jewels: keep it on the jump box only.
- **Agent** (each target): installed by `xdr install` with its config, bundle and baseline. It runs as `xdr-agent.service`, watched by two guard units, a timer, cron, a generator and an apt hook.
- **Console**: `https://JUMP:8443`, one password, TLS 1.3. Reach it through an SSH tunnel if you are not on the jump box.

## Reading the console

- **Hosts**: up or silent, kill on/off/from-config, last beat.
- **Alerts and incidents**: each line is a detection with the process chain, user and action: `killed`, `would-kill` (kill is off), `held` (a scored service, waiting for you), `alert` (gray account or paused), `removed`, `repaired`.
- **Approvals**: SSH sessions waiting at the gate, new accounts, files XDR offers to remove (with undo for 24 h), held processes.

## Kill

Kill starts **off**: process detections only log `would-kill`. Watch a host for a few minutes, then turn kill on for that host (or all) in the Hosts panel; the agent keeps the choice across restarts. Kill never touches:

- scored services (held for your click instead),
- gray accounts (alert only),
- anything while a **pause** token is active.

Tamper, the isolation ladder, the SSH gate and account locking do not depend on the kill switch.

## Firewall

The table is policy-accept. Blocks exist only for endpoints the fleet found malicious (an implant's callback, for example), and each block is an incident. Agent ports are reachable only from the jump box and peers. Scored ports stay open to everyone.

## SSH and accounts

Blue users and the recovery account get in. Everyone else is held and ends after the grace window unless you approve the session. If you are locked out, use the recovery account with its off-box key and a break-glass token. Rotate credentials from the console; the new secrets appear there once.

## Break-glass tokens

Mint in the console or with `xdr controller mint-breakglass`; use on the box with `xdr breakglass -` (paste, Ctrl-D). They are signed, host-bound, time-boxed and single-use.

| Action | Effect |
|--------|--------|
| `pause` | agent and tamper detection stand down for the window |
| `approve-session` | lets your own SSH session through |
| `uninstall` | the agent removes the whole install |

Upgrading `xdr` over a running agent counts as tamper (the installer is killed) unless a pause token is active.

## Self-protection, in one paragraph

Deleting or stopping XDR is repaired within seconds to a minute by whichever launch point survives. A process that rewrites its files is killed (a scored service or gray account is only alerted). If red team isolates a box (foreign firewall drops, blackhole routes, `hosts.deny`), the agent undoes it and reports `isolation` then `isolation-over`. If an agent goes silent, the controller can reinstall it over SSH (configure `reinstall` in `controller.json`).

## When something looks wrong

1. Host **silent**: SSH in as the recovery account, `systemctl status xdr-agent`, `xdr incidents | tail`.
2. Something scored broke: pause the box with a token, then look at the incident that touched it.
3. Remove XDR from a box: an `uninstall` token, or `xdr uninstall --token T` if the agent is dead.
