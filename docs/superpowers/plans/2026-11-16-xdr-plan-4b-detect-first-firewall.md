# XDR Plan 4b: Detect-first Firewall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The host firewall is policy accept. It drops only traffic to endpoints the fleet has found malicious (signed `remote` rules) and protects the agents' own ports. An outbound connection is judged by the process behind it, never by an allowlist. DNS passes unless the opt-in lockdown is on.

**Architecture:**
- **fw:** `Build(cfg, blocks, now)` gives a policy-accept ruleset: loopback, invalid state, the agent ports from the jump box and peers only, one drop of outbound and forwarded packets per block, and (only with `dns.pin`) the old port-53 lockdown.
- **agent:** takes its blocks from the signed rules it has validated and applies the table the moment they change, so one find is cut on every box.
- **detect:** `egress` looks at the process: base-image services are normal, base-image shells, interpreters and network tools alert, anything else is killed and proposed as a block rule.

**Tech Stack:** Go 1.27, CGO_ENABLED=0, google/nftables (netlink), existing detect/respond/rules packages.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md`: §6 Egress and DNS bullets, §8 nftables and DNS bullets (all rewritten 2026-11-16), §7.1 rule validation.

## Global Constraints

- One static binary, `CGO_ENABLED=0`; no new dependency.
- Default-deny is not an option (user, 2026-11-16): no chain of our table has policy drop, and nothing in the agent may infer "malicious" from "not on a list of allowed destinations".
- Never take a scored service offline by our own action: a scored service (guard_exes, or a listener on a scored port) is held, never killed, and no block rule may name a protected address (jump box, peers, ssh_from, the resolver). A remote rule never blocks inbound traffic.
- Response stays on-box. Gray accounts are alert-only (reverse shells still killed). The jump box address is config only; nothing from the packet in code or tests; test addresses from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (the real-box test uses the boxes' own private addresses, from `inventory.ini`, which is not committed).
- The shared default password from the packet is never written anywhere.

## Review Focus

1. **A block that would cut the box off or a scorer.** Expected: a remote rule naming the jump box, a peer, an `ssh_from` address or the resolver never reaches the table, and a rule never drops inbound packets. → Task 1 `TestBuild_ProtectedNeverBlocked`, `TestBuild_InboundNeverBlocked`; Task 4 `TestBlocks_ProtectedRuleRefused`.
2. **Ordinary outbound traffic.** Expected: `apt`, `chronyd`, `systemd-resolved` and a service's own children raise nothing; `python3`, `bash`, `curl` alert at Medium and stay alive; a container process or a scored service is never killed for a connection alone; a non-baseline binary is killed. → Task 3 `TestEgress_ByProcess`, `TestDecide_Egress`.
3. **An old config.** Expected: a config still naming `allow_out`, `dhcp` or `dhcp_server` is refused at load, naming the key; silently ignoring them would leave the operator believing traffic is being allowed or blocked. → Task 5 `TestLoad_OldFirewallKeysRefused`.
4. **A table flipped to drop, or removed, or the agent dead.** Expected: a chain whose policy was changed to drop (a self-inflicted outage) is repaired as drift; with the agent dead the table, blocks included, stays; `xdr fw remove` removes it. → Task 2 `TestKernel_DriftPolicyFlippedToDrop`.
5. **A flood of block proposals.** Expected: at most 512 blocks reach the table, in a fixed order, and the excess is one `fw-block-cap` alert, not a refused table. → Task 1 `TestBuild_BlockCap`; Task 4 `TestBlocks_CapAlertOnce`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/fw/rules.go` | `Block`, `Ruleset.Policy`, `Build(cfg, blocks, now)`, evaluator default |
| `internal/fw/nft.go` | policy per ruleset in `Apply`, `read` and `Drifted` |
| `internal/detect/policy.go`, `detect.go` | `Known` (replaces `AllowedOut`); `egress` by process |
| `internal/respond/kill.go` | `Decide` for the egress and dns kinds |
| `internal/agent/agent.go`, `agent/blocks.go` | blocks from validated rules; `syncTable`; DNS lockdown gated by `dns.pin` |
| `internal/config/config.go` | `DNS.Pin`; `allow_out`, `dhcp`, `dhcp_server` removed |
| `internal/cli/agent.go` | `xdr fw` with no blocks |
| `test/vm/e2e-block.sh`, `e2e-detect.sh`, `Makefile`, `deploy/agent.example.json` | real-box tests |

---

### Task 1: The policy-accept ruleset

**Files:** Modify `internal/fw/rules.go`, `internal/fw/rules_test.go`, `internal/config/config.go` (add `DNS.Pin` only)

**Interfaces:**
- Produces: `type Block struct{ Addr netip.Addr; Proto string; Port uint16 }` (Proto `tcp` or `udp`, Port non-zero) and `const MaxBlocks = 512`.
- Produces: `Ruleset{Policy Action; Input, Output, Forward []Rule}` and `Build(c *config.Config, blocks []Block, now time.Time) Ruleset`. `Verdict` returns `Policy` when no rule matches.
- Produces: `config.DNS.Pin bool "pin"`: the opt-in lockdown; false by default.
- `Build`, all chains `Policy: Accept`, rules in this order:
  1. loopback accept on input and output; `ct invalid` drop on all three;
  2. input: for each of `jump ∪ peers`, accept tcp to each `xdr_port`; then drop tcp to each `xdr_port` from anyone else;
  3. output and forward: one drop per block: `Dst` the address, `Proto`, `DPort`. Blocks inside `c.Protected()` are skipped; the rest are sorted by address, then protocol, then port, and cut to `MaxBlocks`;
  4. only when `c.DNS.Pin`: output accepts `Mark: DNSMark` to the resolver on udp 53 when `c.DNSOn(now)`, then drops udp and tcp to port 53 and tcp to 853.
- Nothing refers to `Scored`, `AllowOut`, `DHCP`, `DHCPServer` or `SSHFrom` any more; SSH is not filtered.

- [ ] **Step 1: Failing tests**, replacing the old `Build` tests (delete the cases that assert default-deny):
  - `TestBuild_PolicyAccept`: each of the three chains' `Policy` is `Accept`; a tcp packet to `203.0.113.9:443` out, a udp packet in from `198.51.100.4`, and a forwarded one are all accepted.
  - `TestBuild_Blocks`: block `203.0.113.9 tcp 4444`: output and forward drop tcp to `203.0.113.9:4444`; accept tcp to `203.0.113.9:4445`, udp to `203.0.113.9:4444` and tcp to `203.0.113.10:4444`.
  - `TestBuild_InboundNeverBlocked`: a packet in from `203.0.113.9` with source port 4444 is accepted, a reply included.
  - `TestBuild_ProtectedNeverBlocked`: blocks naming the jump address, a peer, an `ssh_from` address and `dns.resolver` give no rule (compare the output chain with `Build(c, nil, now)`).
  - `TestBuild_AgentPorts`: input tcp to 7443 from the jump box and from a peer is accepted; from `198.51.100.4` dropped; tcp to 22 from `198.51.100.4` accepted.
  - `TestBuild_BlockCap`: 600 blocks give exactly 512 output drops, the 512 lowest by address; the same set in another order builds the same ruleset (`String()` equal).
  - `TestBuild_DNSPin`: without `pin`, udp to `192.0.2.1:53` is accepted. With `pin`: dropped, accepted again with `Mark: DNSMark` to the resolver once `enabled`, tcp to port 853 dropped.
- [ ] **Step 2: Run** `go test ./internal/fw`. Expected: FAIL (undefined `Block`, `Policy`, signature).
- [ ] **Step 3: Implement.** `Rule.matches` and `String()` are unchanged; `String()` also prints the chain policies so a policy change shows as drift.
- [ ] **Step 4: Run** `go test ./internal/fw ./internal/config`. Expected: PASS (the netlink tests in `nft_test.go` compile again after Task 2).
- [ ] **Step 5: Commit** `feat(fw): policy-accept ruleset with a blocklist`.

### Task 2: The translator keeps the policy

**Files:** Modify `internal/fw/nft.go`, `internal/fw/nft_test.go`

**Interfaces:**
- Consumes: `Ruleset.Policy`.
- Produces: `Apply` creates each chain with the policy of the ruleset; `read` and `Drifted` treat a chain whose policy differs from the one last applied as drift; `Foreign` is unchanged.

- [ ] **Step 1: Failing tests** (root, in the netns of `inNetns`):
  - `TestKernel_ApplyPolicyAccept`: apply `Build(cfg, []Block{{203.0.113.9, tcp, 4444}}, now)`; `nft list chain inet xdr output` shows `policy accept` and a drop of `203.0.113.9` port 4444; an outbound connection to `203.0.113.9:4445` on a local dummy address is not dropped and one to 4444 is.
  - `TestKernel_DriftPolicyFlippedToDrop`: after `Apply`, set the output chain's policy to drop with `nft`; `Drifted()` is true; `Apply` puts it back to accept.
  - Adapt `TestKernel_DriftPolicyAndExtraChain` to the new policy.
- [ ] **Step 2: Run** `make test-root` (or `sudo -n go test ./internal/fw -run Kernel`). Expected: FAIL.
- [ ] **Step 3: Implement** in `Apply`, `read` and `Drifted`: the wanted policy comes from the ruleset, remembered on `Firewall` for `Drifted`.
- [ ] **Step 4: Run** the same. Expected: PASS.
- [ ] **Step 5: Commit** `feat(fw): chains carry the ruleset's policy`.

### Task 3: Egress is judged by the process

**Files:** Modify `internal/detect/policy.go`, `internal/detect/detect.go`, `internal/respond/kill.go`, their tests, `internal/agent/agent.go` (`wanted`)

**Interfaces:**
- Produces: `(p *Policy) Known(dst netip.AddrPort, proto string) bool`: loopback, multicast, broadcast, a local address, and the jump and peer addresses on `xdr_ports`. It replaces `AllowedOut`, which is deleted.
- Produces: `(p *Policy) egress(s *proc.Snapshot, pr *proc.Proc, dst netip.AddrPort, proto string) (kind, detail string, sev model.Severity)`:
  - `""` when `Known`, or when `pr` is a base-image program (`p.Baseline(pr)`) with `Class(pr) == ""`;
  - otherwise `kind` is `dns` for ports 53 and 853 and `egress` for the rest; `detail` is `tcp to 203.0.113.9:4444`; `sev` is Medium for a baseline program (a shell, interpreter or network tool) and High for the rest, a nil `pr` (it exited) included.
- Produces: `Decide`, for kinds `egress` and `dns`, after the guarded check: `alert` for a baseline process, a gray one, and a process in a container (`proc.Container(pr.Cgroup) != ""`); `kill` for the rest. Every other kind decides as before.
- Agent: `wanted` skips events whose destination is `Known`.

- [ ] **Step 1: Failing tests**
  - `TestEgress_ByProcess`, rows (process → connection to `203.0.113.9:4444` unless noted → kind, severity):
    - `chronyd` (baseline, class none) → none;
    - the baseline `python3` → egress, Medium;
    - `/tmp/x` (not in baseline) → egress, High;
    - the same to `127.0.0.1`, to the jump box on 7443 and to `224.0.0.251` → none;
    - non-baseline to `192.0.2.1:53` → dns, High; baseline `systemd-resolved` to it → none;
    - nil `pr` → egress, High.
  - `TestDecide_Egress`: non-baseline → kill; baseline python3 → alert; gray user's non-baseline → alert; non-baseline in a container → alert; non-baseline apache (guarded) → held; `revshell-stdio` from a baseline `bash` → kill as before.
  - Adapt the existing detect and agent tests that expected an allowlist verdict.
- [ ] **Step 2: Run** `go test ./internal/detect ./internal/respond ./internal/agent`. Expected: FAIL.
- [ ] **Step 3: Implement.** Both callers of `p.egress` in `detect.go` (sweep and event) pass the process, or nil.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(detect): judge outbound connections by the process, not an allowlist`.

### Task 4: The agent keeps the blocklist and the DNS lockdown opt-in

**Files:** Create `internal/agent/blocks.go`, `internal/agent/blocks_test.go`; Modify `internal/agent/agent.go`, `internal/cli/agent.go`

**Interfaces:**
- Consumes: `fw.Block`, `fw.Build`, the validated rules `takeRules` keeps (kind `remote`, port non-zero, proto tcp or udp).
- Produces: `(a *agent) syncTable(now time.Time, report bool)` (caller holds `a.mu`): builds the ruleset from `a.cfg`, `a.blocks`, applies it when its text differs from `a.applied`, repairs drift; this is the firewall half of today's `assert`, which now calls it.
- Produces: `takeRules` sets `a.blocks` from the rules it kept and calls `syncTable` when they changed. One `fw-block` Medium incident per block added (`blocked 203.0.113.9:4444/tcp: rule ID from HOST`), one `fw-unblock` per block removed, one `fw-block-cap` High alert per distinct overflow.
- `dnsguard.Assert`, the DNS stub and `onQuery` run only when `a.cfg.DNS.Pin`; a reload that changes `dns.pin` is refused like a changed `dns.listen`.
- `xdr fw print|apply|try` build with no blocks.

- [ ] **Step 1: Failing tests** (`rig` with a `fakeFW` that records the last `Ruleset`):
  - `TestBlocks_FromSignedRules`: a set with a remote rule `203.0.113.9:4444/tcp` gives one `fw-block` incident and a ruleset whose output chain drops it; the same set again gives no second incident; a set without it gives `fw-unblock` and no drop.
  - `TestBlocks_ProtectedRuleRefused`: a remote rule naming the jump address gives `rules-refused` and no block.
  - `TestBlocks_CapAlertOnce`: 600 rules give 512 drops and one `fw-block-cap`; the next sweep gives no second.
  - `TestDNS_UntouchedWithoutPin`: with `pin` false the `etc` files are byte-identical after `guard`, no stub is started and `dns-files` is never recorded; with `pin` true the files are written as before (adapt the existing dnsguard agent tests to set `Pin`).
  - `TestReload_RefusesPinChange`.
- [ ] **Step 2: Run** `go test ./internal/agent -run 'Blocks|DNS|Reload'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/agent ./internal/cli`. Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): fleet blocklist in the firewall; DNS lockdown opt-in`.

### Task 5: Remove the allowlist from the config

**Files:** Modify `internal/config/config.go`, `internal/config/config_test.go`, `deploy/agent.example.json`, `internal/agent/*_test.go`, `test/vm/e2e-fleet.sh`, `test/vm/e2e-gate.sh`

**Interfaces:**
- Produces: `Config` without `AllowOut`, `DHCP`, `DHCPServer` (the `Dest` type goes too); `Protected()` is jump, peers, `ssh_from` and the resolver. `scored` stays: it still marks scored services for the guard.

- [ ] **Step 1: Failing tests**
  - `TestLoad_OldFirewallKeysRefused`: each of `"allow_out":[]`, `"dhcp":true`, `"dhcp_server":["192.0.2.1"]` makes `Load` fail with the key name in the error.
  - `TestExampleConfigLoads` (the example no longer has the three keys), `TestProtected` without `allow_out`/`dhcp_server`.
- [ ] **Step 2: Run** `go test ./internal/config`. Expected: FAIL.
- [ ] **Step 3: Implement.** Fix every compile error and test that used a removed field; the e2e scripts' generated configs drop `dhcp_server` (and `e2e-fleet.sh`/`e2e-gate.sh` stop calling `dhcp_server`).
- [ ] **Step 4: Run** `go vet ./... && go test ./...`. Expected: PASS.
- [ ] **Step 5: Commit** `refactor(config): drop allow_out, dhcp and dhcp_server`.

### Task 6: Block on the real boxes

**Files:** Create `test/vm/e2e-block.sh`; Modify `Makefile` (`remote-block`)

**Interfaces:**
- Consumes: the ssh backend (`BOXES`, `x`, `push`, `jb`, `jx`, `start_agent`, `inc`, `wait_inc`), `test/vm/beacon`, and `vm-group-3` as a plain host (no agent) running listeners on 4444 and 4445.
- Setup: agents on `BOXES[0]` and `BOXES[1]` as in `e2e-fleet.sh` (peers of each other); the third target runs `python3 -m http.server` on 4444 and 4445. Its address is not in any config, so it is blockable.
- Cases, each `ok <name>`; the script ends `E2E-BLOCK PASS`:
  1. `policy-accept`: `nft list chain inet xdr output` on both agents shows `policy accept` and no drop; both can fetch `:4444` and `:4445` from the third host.
  2. `dns-untouched`: `/etc/resolv.conf`, `/etc/hosts` and `/etc/nsswitch.conf` equal their pristine copies; nothing listens on `127.0.0.1:53`; `getent hosts` of a name the box resolved before still answers.
  3. `baseline-alerts`: on box 1, `python3` connects to the third host's `:4445` and stays up; an `egress` alert at Medium names it; no rule is proposed.
  4. `nonbaseline-killed-blocked`: on box 1, `/opt/beacon/beacon` connects to the third host's `:4444`; it is killed; a remote rule for it is signed; within 5 s both agents' output chains drop that address and port.
  5. `block-holds`: from box 2 a fetch of `:4444` times out; `:4445` still answers.
  6. `agent-dead`: stop box 2's agent; the drop is still in its table and the fetch still times out.
  7. `revoke`: `xdr rules revoke` the rule; within 5 s the drop is gone from both tables and the fetch of `:4444` works.
  8. `protected-refused`: a remote rule proposed for the jump box's address is refused by the controller (`rules.Guard`), the table stays empty. (Drive it with `xdr controller` or a crafted proposal as `e2e-fleet.sh` does for its cases.)
- [ ] **Step 1: Write the script and the Makefile target.**
- [ ] **Step 2: Run** `make remote-block`. Expected: all 8 `ok`, `E2E-BLOCK PASS`. Run it twice.
- [ ] **Step 3: Run** `make remote-fleet` and `make remote-gate`. Expected: PASS (no regression).
- [ ] **Step 4: Commit** `test: detect-first firewall on the real boxes`.

### Task 7: Port the single-box attack test to the real boxes

**Files:** Create `test/vm/e2e-detect.sh` (from `e2e-net.sh`); Modify `Makefile`; delete `test/vm/e2e-net.sh` and its target when the port passes

**Interfaces:**
- Consumes: `e2e-net.sh`'s cases, `jb`/`ssh` backend; the catcher that listened on the LXD host now listens on the jump box (a process on `vm-1`, so the attacker is reachable from the target).
- Keeps these cases, adapted to the new model: `sensor-ebpf`, `listener`, `revshell`, `service-shell`, `rawsock`, `drift` (a flipped policy and an extra chain), `foreign-nat`, `agent-dead` (the table and blocks stay).
- Drops, because they asserted default-deny or the old DNS stub: `pre-existing-revshell` (an open connection is no longer cut by the table; the process is still killed by the revshell detection, so it becomes a plain `revshell` run that starts before the agent), `dns-off`, `dns-on`, `dns-expiry`, `fallback`.
- [ ] **Step 1: Port the script and add `remote-detect`.**
- [ ] **Step 2: Run** `make remote-detect`. Expected: every kept case `ok`, `E2E-DETECT PASS`.
- [ ] **Step 3: Remove `e2e-net.sh`, its Makefile target and the LXD-only guard text that mentions it.**
- [ ] **Step 4: Commit** `test: single-box attack test on the real boxes`.

---

## Builder's calls in this plan (recorded for the spec)

- A remote rule blocks outbound and forwarded packets to that address, port and protocol only; never inbound.
- SSH is not filtered by nftables: the gate and `AllowUsers` do it. This drops the `ssh_from` allow, which on the competition network was the whole subnet anyway.
- The agent ports are protected on input only; there is no output rule for them.
- A container process is alert-only for egress: it cannot be told from a scored service's child by its binary.
- `dns.pin` keeps the old lockdown whole (files, stub, switch, port-53 drops) and is off by default; with it off, switching off later needs no clean-up because nothing was written.
- Old configs are refused, not translated.
