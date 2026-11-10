# XDR — Design

Date: 2026-11-10
Source notes: `XDR_INITIAL.md` (original brainstorm; this document supersedes it where they differ)

## 1. Intent

A purpose-built Linux host defense platform for a blue-team competition. The red team gets root on our boxes and uses C2 implants, reverse shells, SSH logins, raw-socket tools and apt/dpkg-hook backdoors to keep access. The XDR finds and removes their footholds, blocks their callbacks, and is very hard for them to remove — while never taking our own scored services offline.

It only has to work once, for one competition, on a known OS. That justifies hard-coding (baseline hashes, rules, UI embedded in the binary) over general-purpose configurability.

**Success:** red team footholds die fast and stay dead, scored services stay up, the operator sees everything from one console, and the red team cannot get rid of the XDR.

## 2. Goals, non-goals, anti-goals

**Goals**
- Kill reverse shells and C2 callbacks automatically, write a detection rule from each one, push it to every box, and alert the operator.
- Close egress almost completely; every blocked attempt is an alert tied to a process.
- Detect "added" and "altered" persistence against a clean baseline across all known persistence locations (§6).
- Gate SSH: unapproved manual sessions are killed after a short grace window.
- Self-protection: removal should be extremely hard for a root attacker (§9).
- One web console on the control plane (operator's jump box) for monitoring and approvals.

**Non-goals (this version)**
- Rootkit detection (possible future stage).
- Any action against red team infrastructure. Competition rules: we may do anything on our own boxes, we may not touch red team boxes. Auto-response is strictly on-box (kill / block / remove); no scanning or connecting back to attacker IPs.
- Windows, other distros, general configurability.

**Anti-goals (failure even if it "works")**
- Taking a scored service offline through our own action (killing mysqld, blocking scorer traffic, rotating a credential the scorer uses).
- Locking our own team out (fail-closed with no working break-glass).
- Building anything live during the competition — everything is pre-staged.

## 3. Environment and constraints

- Targets: Ubuntu 24.04, matched to the competition's exact point release. Linux only.
- Scored services: Apache (in Docker, HTTP/HTTPS), SMTP, MySQL.
- We start with root.
- Legitimate outbound traffic from target boxes: **none**, other than replies to inbound score checks, blue-team access, and XDR traffic (peers, etcd, control plane).
- Operator works from a desktop (primary) / laptop / phone, connecting to the control plane.
- Deployment: Ansible during the setup window; nothing built live.

## 4. Architecture

**Language / build (decided):** Go. One static binary (`CGO_ENABLED=0`), role chosen by subcommand/flag:
- `agent` — runs on every target box.
- `controller` — runs on the jump box: web UI, approvals, off-box watchdog, off-box baseline source of truth.
- small CLI subcommands (break-glass, approve, status).

**Embedded in the binary via `go:embed` (decided):** clean baseline hashes and file inventories, default rules, the web UI, precompiled eBPF objects. The binary's own hash is pinned so peers/controller can verify before reinstalling.

**Kernel interfaces, no userspace tools required on targets (decided):**
- eBPF via `cilium/ebpf`, CO-RE objects compiled ahead of time against `/sys/kernel/btf/vmlinux` (present on 24.04). No clang/bcc/bpftool on targets. Fallback when eBPF can't load: `/proc` polling + netlink proc connector.
- Firewall via `google/nftables` (netlink). No `nft` binary needed; relies on stock nf_tables kernel modules.

**Jump box is out of red team scope (decided by operator):** it is the trust anchor — signing key, authoritative state, off-box baseline.

**State:** etcd, single node on the jump box *(builder's call: since the jump box is out of scope, no etcd members on red-team-rooted hosts)*, reached over the management interface, authenticated with per-node client certs and RBAC (a node can write only its own keys and read shared rules). Shared state: rules, incidents, approvals, heartbeats, session approvals. Agents keep enforcing with last-known state (cached locally) if etcd is unreachable.

**Rule promotion (builder's call):** agents write *proposed* rules under their own keys. The controller validates each one and promotes it to the shared rule set automatically — no human in the loop — so fleet-wide kill stays fast. Validation rejects any rule that would:
- match a baseline binary by hash (bash, python3, perl, nc, etc. are only targeted via narrower patterns: parent→child, cmdline, remote endpoint, specific cron entry/unit);
- match a scored-service binary or process;
- block an allowlisted address (scorer, blue team, XDR).
Non-baseline binary hashes, remote IPs and parent→child patterns are promoted. A compromised node can therefore only push narrow rules that the controller has checked. Promoted rules are **signed with the jump box key**, and agents enforce only signed rules.

**Fleet communication (decided: boxes must learn about problems on other boxes immediately):**
- **Primary channel:** agents hold etcd *watches* (push, not polling), so new rules, incidents and hunt requests reach every box in well under a second.
- **Backup channel:** agents also form a direct peer mesh over the management interface (mTLS, per-node certs). They relay signed rules and hunt requests to each other. If the jump box or etcd is unreachable, boxes keep sharing. A compromised peer can't forge rules because it lacks the signing key.
- **Heartbeats** go over both channels, so a dead or silenced agent is noticed by its peers and by the controller.

**Trust model:**
- Trusted hashes come from the clean box and are embedded in the binary / held on the jump box — never read from on-box dpkg md5sums.
- Per-node etcd credentials; compromise of one node's creds cannot rewrite global rules or other nodes' state.
- Resurrection (peer/controller reinstall) pushes the pinned-hash artifact; the receiver verifies the hash. Never fetch a binary from a peer's filesystem.
- Commands from the control plane (approve, break-glass, uninstall) are signed with a key that lives only on the jump box.

## 5. Baseline

We have the competition's **exact base image** (without scored services) and a **per-host list of scored-service packages** (apache, docker, mysql, postfix, …). No console access to the boxes. So the baseline has three layers:

1. **Base OS — hard-coded.** Captured from the exact base image, offline, and embedded in the binary. Fully trusted.
2. **Scored-service packages — verified off-box.** *(Builder's call:)* we pre-install each host's package list on a copy of the base image to pre-compute the expected units, users, groups, files and SUID/caps. At T-0 the agent reports the exact installed package versions. The controller takes the matching `.deb`s from the Ubuntu archive (pre-cached on the jump box for the versions we expect, fetched otherwise) and computes the trusted file hashes itself. On-box dpkg md5sums are never trusted.
3. **Competition-specific config and data — "needs triage".** These are things we can't know in advance: scored-service config files, the docroot, the Docker image and container, MySQL users/grants/UDFs/triggers, postfix `aliases`/`master.cf`, extra users the organizers create, and `authorized_keys`. They're captured at T-0 and shown in the console as a triage list. Each item can be approved as known-good or flagged. Until approved, they aren't auto-removed, but every *change* after T-0 is still detected. Process/network detection and egress blocking apply from the first second regardless.

- Scored-service deltas from layer 2 are pre-marked known-good.
- Captured as: file hashes (packages + `debsums -ca`-equivalent including conffiles), user/group lists, unit/timer list, cron contents, SUID/SGID and file-capability sets, PAM stack, sshd_config, kernel module list, listener list, and the other locations in §6.
- At T-0 the agent sweeps the live box against the baseline before anything else — implants may already be present.

## 6. Detection

### 6.1 Network and process (primary focus)
- eBPF hooks on exec, connect, accept, bind, socket creation; every event attributed to pid, binary path + hash, uid, parent chain, container (cgroup), and origin (unit, cron, SSH session, web request).
- **Reverse shell:** shell/interpreter whose stdio fds are sockets, or a shell spawned by a network service (apache, mysqld, postfix children), or any new outbound connection to a non-allowlisted address.
- **Egress attempt:** any outbound connect not in the allowlist (dropped by nftables; eBPF supplies the process attribution). *(Builder's call:)* hardening first disables stock services that phone home (snapd, motd-news, apt-daily timers, ubuntu-advantage/pro, timesyncd unless NTP is needed, Docker's update/registry pulls), and that disabled state is part of the baseline. A blocked attempt by a remaining baseline process is **alert-only**; kill applies to non-baseline processes, shells/interpreters, and anything matching a rule.
- **DNS:** outbound DNS is blocked entirely. Any lookup attempt is an alert; high-entropy/long subdomains and bursts are scored higher.
- **Raw sockets:** processes holding `AF_PACKET`/`SOCK_RAW` sockets or attached socket BPF filters (rare on a stock server → high-signal).
- **Listeners:** any listener not in baseline; `docker-proxy` and scored ports allowlisted.
- **Container:** process and network events inside the Apache container are watched the same way (cgroup-aware).

### 6.2 "Added" (baseline diff)
- systemd services and timers (system and per-user `~/.config/systemd/user`), systemd generators.
- Users and groups (flag non-baseline users within the first 5 minutes), `/etc/shadow` changes on existing users.
- Cron (all locations), `at` jobs.
- apt/dpkg hooks.
- `authorized_keys` (all users), `sudoers`/`sudoers.d`, SUID/SGID set, file capabilities (`getcap`).
- `ld.so.preload`, `update-motd.d`, `rc.local`, `profile.d`/bashrc/shell rc files, `nsswitch.conf`, `/etc/hosts`, `resolv.conf`.
- Kernel modules (`lsmod`, `/etc/modules-load.d`), udev rules.
- SMTP: `/etc/aliases` and `.forward` pipe-to-command entries, `master.cf`.
- MySQL: new users/grants, UDFs in the plugin dir, triggers, events. *(Builder's call:)* the agent queries as MySQL root over the local unix socket (`auth_socket`, Ubuntu's default) — no new MySQL accounts, no scorer credentials touched. Falls back to on-disk inspection of the plugin dir if socket auth isn't available.
- Docker: new images/containers, exposed `docker.sock`.

### 6.3 "Altered" (content diff)
- Hash stock files vs clean baseline.
- Byte-diff `sshd_config` and the PAM stack (top backdoor targets); diff PAM modules on disk. Don't rip-and-replace live PAM — restore the known-good file contents.

## 7. Response

### 7.1 Reverse shell / C2 (automatic)
1. **Kill** the offending process and its descendants; the originating persistence (session, cron entry, unit) is handled in step 6 *(builder's call on scope)*. If the parent is a scored-service process, only the child branch dies.
2. **Flag** an incident: process, cmdline, hash, uid, parent chain, remote endpoint, origin.
3. **Write a detection** rule from the incident (binary hash, remote IP, parent→child pattern, originating cron entry/unit). The rule is pushed to every box via etcd and auto-kills on sight immediately.
4. **Hunt fleet-wide.** The red team usually installs its tools the same way on every Linux box, so a problem found on one box is checked on all of them. The incident's indicators are extracted:
   - file paths and hashes;
   - unit, timer and cron names and contents;
   - remote IPs and ports;
   - install method (apt hook, web shell path, user name, key fingerprint).

   Every other agent immediately searches its own filesystem, processes, units, cron, users and keys for them and reports back. Hunt requests can come from any peer, since searching is harmless. Kills and removals that result from a hunt follow the normal rule path: matches against an existing signed rule are acted on, and new matches become proposed rules. The console shows the incident with a per-host hunt result ("found on db01, mail01; clean on web01").
5. **Alert** the operator in the console.
6. The persistence that launched it (cron job, unit, web shell file) is disabled/quarantined automatically where safe, and its **removal** is queued for one-click approval.

### 7.2 Scored-service guard (decided)
Any process bound to a scored service's port (80/443, 25, 3306 — exact list from the competition) or that *is* the scored service process is never auto-killed or auto-deleted. Detections against it are held for approval with a "restore clean binary + restart" option. Children it spawns are still auto-killable.

### 7.3 SSH gate
- `pam_exec` at the session stage in `/etc/pam.d/sshd` only (not common-session) registers each new session as pending.
- logind terminate-session after a short grace window unless approved; fail-closed.
- Platform-launched sessions auto-approve; manual sessions approved in the console or via the break-glass/escape command.
- Exempt: agent account and recovery account. *(Builder's call:)* because there's no console access, the recovery account is the only way back in when the jump box or etcd is down, and it's the red team's best target. So it is:
  - accepted only from the jump box/operator IPs, on the management interface;
  - key-only, with the key held off-box;
  - excluded from the "new user" and "non-baseline session" rules;
  - alerted on every login.

  It's also enforced at the sshd level (`Match` block) and in our nftables table, so it doesn't depend on the agent.
- Agent re-asserts the known-good `/etc/pam.d/sshd` and `sshd_config` on drift.
- Auto-disable sessions whose user isn't in baseline.

### 7.4 Other response
- New users disabled until approved.
- Destroy rules (service / file-hash): dry-run + undo (quarantine copy), never match scored binaries.
- Session management: view/kill sessions; kill connections to non-baseline remotes.
- Kill unknown listeners (with the scored-service guard).
- **Tampering** with any XDR file, unit, rule, eBPF program or process is treated as confirmed red team: kill the actor, terminate its session, alert. Kill-first, even in a root shell (scored-service guard still applies).

## 8. Hardening and firewall

- SSH keys-only, password auth disabled. Rotate creds and replace all `authorized_keys` at T-0; regenerate host keys. **Do not rotate credentials the scorer uses** without checking the rules.
- Bind sshd to the management interface if topology allows.
- nftables: our own table with base chains on input, output and forward hooks.
  - Inbound: scored ports, SSH from blue-team/jump-box addresses, XDR on the mgmt interface.
  - Outbound: established/related only, plus XDR peers/etcd/controller.
  - Forward (Docker): same egress policy for the container. Because a drop in any nf_tables chain is final, Docker's own accept rules can't override ours.
  - Default-deny, inverted workflow: scored services allowed first, additions approved in the console.
- Postfix: disable reverse lookups (`smtpd_peername_lookup = no`) and anything else needing DNS; container gets a static hosts file — so DNS can stay fully blocked.
- Agent re-applies the ruleset on a short loop and alerts on drift.

## 9. Self-protection

- Enforcement lives in the kernel (nftables rules, pinned eBPF programs/maps on bpffs) and survives agent death.
- Multiple launch points, each a small "is the agent running with the right hash? if not, restore it" check: primary systemd unit (`Restart=always`), a second unit under a different name, a timer, cron `@reboot`, a systemd generator, an apt hook.
- Multiple binary copies in different paths, `chattr +i`.
- Two local watcher processes that watch each other.
- Peers detect a dead agent (missed heartbeat) and report it; the **controller** does the reinstall over SSH with its own key, pushing the pinned-hash binary. *(Builder's call, changing the original "peers reinstall each other": giving every box root access to every other box would hand the red team a lateral-movement credential. On-box resurrection is covered by the local launch points and watchers above.)*
- Tamper attempts are the highest-confidence signal (§7.4).
- Optional, verify on the competition kernel: eBPF-based blocking of signals to XDR processes (needs BPF LSM or kprobe override, which stock Ubuntu may not enable).
- One clean off switch: signed uninstall/pause from the jump box.

## 9a. Fleet connectivity self-healing (decided)

Fleet communication must always be recoverable. When a host notices it is cut off, it tries everything it can to reconnect, so we can regain control.

**Detecting isolation:** heartbeats are missing from the controller *and* all peers for a short window (e.g. 10s), or etcd and the mesh both fail to connect. Losing a single peer is just a peer alert. Isolation means losing everyone.

**Reconnect ladder.** Each step runs, then the agent re-tests connectivity. It stops at the first success:
1. Re-assert our nftables table and its allow rules for the management interface, fleet peers and the jump box.
2. Find and remove anything local that blocks fleet traffic:
   - foreign nftables tables/chains, iptables-legacy rules and `ip6tables` rules that drop or reject fleet addresses or ports;
   - `ip rule`/route blackholes, `tc` filters, `/etc/hosts.deny`.

   Each removal is logged as a tamper incident.
3. Restore the management interface: link up, baseline address, routes. Undo `ip link set down` and changed addresses.
4. Restore the known-good `sshd_config` and its listen address, then restart sshd (and `ssh.socket`) so the controller can get in.
5. Restart the agent's mesh/etcd clients. Re-open the agent's management listener, moving to pre-agreed alternate ports if the primary port is taken.
6. **Call home.** The agent dials *out* to the jump box on several pre-agreed ports and holds a reverse control channel open. Outbound to the jump box is always allowed in our table, so control is regained even when inbound is blocked.
7. Keep cycling the ladder with backoff (fast at first, capped at ~30s) until reconnected.

**Guardrails:**
- The ladder never touches scored-service ports or rules.
- It only opens access to the jump box, fleet peers and the management interface, never broad egress.
- It never reboots the host by default, since that drops scoring. A reboot step exists only as an opt-in for after a long isolation.

While isolated, the agent keeps enforcing locally from last-known signed rules. Once it reconnects, it reports what had blocked it and what it changed, and the console shows that as a tamper incident on that host.

## 10. Break-glass

An escape command to declare a session safe or pause enforcement. Must work if etcd and the control plane are down: falls back to a local file the agent reads, protected so the red team can't use it (signed token from the jump box key). Must be tested specifically against the fail-closed SSH gate.

*(Builder's call, given no console access:)* tokens are **minted in advance** on the jump box, each scoped to one host and one action (approve-session or pause), short-lived (e.g. 2h), and kept on the operator's laptop as well. They're delivered by SSHing in as the recovery account, which skips the gate, and running the escape command. The red team can't forge them because the signing key never leaves the jump box. Test cases: jump box down, etcd down, agent dead, and the gate closed on the operator's own session.

## 11. Control-plane console

Web UI served by the controller on the jump box. Primary use on desktop; must also work on phone. Mockup: https://claude.ai/artifact/EYEaRd2sYnpqMRyRJSoywX (design to be iterated later).

- Header: competition clock, etcd health.
- Summary: items needing the operator, auto-kills, agents up, egress blocked.
- **Alerts:** auto-handled incidents with process chain, endpoint, hash, origin, and a checklist of actions taken (killed / rule written / pushed / pending).
- **Approvals:** gated items (scored-port process, file/persistence removal with dry-run + undo, new users).
- **SSH sessions:** pending sessions with countdown, approve / kill; session list.
- **Hosts:** agent / firewall / baseline-drift / heartbeat per box; break-glass control.

## 12. Cut / demoted

- SSH port rotation — cut as prevention; optional probe tripwire/alert only, slow interval.

## 13. Open items

- **Apache container:** rebuild from a clean pinned image we pre-stage (leaning this way) vs. keep theirs and baseline the docroot/image. Either way: docroot diff, image/restart-policy inspect, container egress under our forward chain.
- Competition specifics to fill in when known: number and names of boxes, scored ports, whether a separate management interface exists, which accounts the scorer uses. (Kernel/point release comes from the base image we have.)
- Whether eBPF signal-blocking is available on the competition kernel (§9).

## 14. Left to the builder

Internal package layout, rule format, etcd key schema, UI framework (keep it embeddable, no CDN at runtime), grace-window and re-assert intervals, exact eBPF hook points, test strategy (a VM/container harness replicating Ubuntu 24.04 + the three scored services is expected).
