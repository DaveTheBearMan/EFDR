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

## 3a. Competition environment (from the packet, 2026-11-10)

Hostnames are placeholders and the mail server's network is not final, so nothing below is compiled in: it is deployment config, keyed by team number.

| Host | OS | IP | Scored service | XDR |
|------|----|----|----------------|-----|
| SecurityBlanket | Windows Server 2022 | 192.168.N.1 | AD, DNS | out of scope |
| PsychiatricBooth | Windows Server 2022 | 192.168.N.2 | IIS | out of scope |
| KiteTree | Ubuntu 24.04 | 192.168.N.3 | MySQL | agent |
| ToyPiano | Ubuntu 24.04 | 192.168.N.4 | SMTP | agent |
| Doghouse | Ubuntu 24.04 | 192.168.N.5 | Apache (Docker) | agent |

- One flat /24 per team (`192.168.N.0/24`, N = team number; team 1 shown in the packet), gateway `.254` (OpenStack router). Domain `TEAMN.PEANUTS.LOCAL`. **No separate management interface.**
- The scoring engine and the red team's attack boxes **share one subnet** outside ours. A source address therefore never proves "this is the scorer": scored ports stay open to that subnet, and every other control has to work without source-based trust.
- The two Windows boxes sit on our subnet and are not covered by this tool. Treat them as untrusted neighbours: a compromised Windows box is an attacker inside the /24. Nothing is allowed from `.1`/`.2` to the Linux boxes beyond what a scored service needs, and DNS replies from `.1`.
- DNS for the team is the AD box (`.1`). The Linux boxes do not use it by default (§8 DNS); when the switch is on, `.1` is the only resolver they may talk to.
- **Jump box placement is not known in advance:** it may be on the team subnet or on an attached network. Either way it is out of the red team's scope. Its address(es) are therefore deployment config set at T-0, never a compiled-in value or a subnet assumption, and every rule that names "the jump box" (SSH, etcd, mesh, call-home) is generated from that config. If it is on an attached network, agents reach it through the gateway and the egress allow is that one address and port.
- **Rotated passwords can be handed to the scoring engine** (operator decision, 2026-11-10), so nothing blocks rotating every blue-team and service credential at T-0. The console has to make that hand-off a copy-paste (§11).
- **Gray team accounts — never touched:** `grayteam`, `othergrayteam`, `violetgray`. No credential or key rotation, no disable, no session kill, no home-directory cleanup. Activity on them is alert-only (§7.3).
- Blue team accounts, identical on every box, all starting on one shared default password: admins (in `sudo`) `charliebrown`, `lucyvanpelt`, `linusvanpelt`, `peppermintpatty`, `marcie`; normal local users `snoopy`, `woodstock`, `sallybrown`, `schroeder`, `pigpen`. On Linux these are local accounts.

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

**State:** etcd, single node on the jump box *(builder's call: since the jump box is out of scope, no etcd members on red-team-rooted hosts)*, reached over the team subnet (or wherever the jump box sits, §13), authenticated with per-node client certs and RBAC (a node can write only its own keys and read shared rules). Shared state: rules, incidents, approvals, heartbeats, session approvals. Agents keep enforcing with last-known state (cached locally) if etcd is unreachable.

**Rule promotion (builder's call):** agents write *proposed* rules under their own keys. The controller validates each one and promotes it to the shared rule set automatically — no human in the loop — so fleet-wide kill stays fast. Validation rejects any rule that would:
- match a baseline binary by hash (bash, python3, perl, nc, etc. are only targeted via narrower patterns: parent→child, cmdline, remote endpoint, specific cron entry/unit);
- match a scored-service binary or process;
- block an allowlisted address (scorer, blue team, XDR).
Non-baseline binary hashes, remote IPs and parent→child patterns are promoted. A compromised node can therefore only push narrow rules that the controller has checked. Promoted rules are **signed with the jump box key**, and agents enforce only signed rules.
- *(Builder's calls, plan 3a:)*
  - etcd is embedded in `xdr controller run`; the jump box needs no etcd install. TLS 1.3 only, client certs required; a cert's CN is its etcd user. A host enrolled while the controller runs gets its etcd user within a second.
  - The controller keeps the highest version it published in `rules.version` beside etcd's data; if etcd's data is lost it goes on from there (`rules-reset`), since agents refuse any lower version.
  - Rule kinds so far: binary hash, and remote address+port+proto. A remote rule kills local processes connected to that endpoint and never blocks inbound traffic (the scorer shares a subnet with the red team); a socket on a scored port never matches. Parent→child and persistence rules come with plan 3b.
  - Proposals come from reverse-shell, service-shell and egress incidents that were killed, would have been (`kill: false`) or held. A base-image binary proposes only its endpoint.
  - Every rule is checked twice, by the controller before signing and by the agent before enforcing, against the baseline, `guard_exes` and protected addresses (the controller's `protect`; the agent's own jump, peers, ssh_from, allow_out, resolver and dhcp_server). Caps: 256 promoted rules per proposing host, 4096 in all.
  - The set carries a version that only rises; an agent refuses an older or badly signed set (`rules-refused`) and keeps the last verified one on disk, enforcing it from start, before etcd answers.
  - Only the operator removes a rule (`xdr rules revoke`), and a revoked rule is never promoted again. Rules do not expire.
  - A container's shells and interpreters propose no hash and match no hash rule: they are the image's own, in no host baseline. Neither the agent's nor the controller's own binary can ever be a hash rule.
  - The controller cuts what a proposer controls (detail to 256 bytes, exe to 512, seen no later than now) and refuses a set over 1 MiB, below etcd's request limit.
  - A host writing more than 600 keys a minute (proposals, incidents, heartbeats) loses its write access for good (`host-disabled`); the operator can do the same by hand (`xdr controller disable-host`). etcd history is compacted every 5 minutes, so a stream of puts cannot fill its quota.
  - Heartbeats are an etcd key on a 10 s lease; the controller reports `agent-silent` when it lapses (or none came within 15 s of its start) and `agent-back` on the next one. Agent incidents are copied into the controller's own log.

**Fleet communication (decided: boxes must learn about problems on other boxes immediately):**
- **Primary channel:** agents hold etcd *watches* (push, not polling), so new rules, incidents and hunt requests reach every box in well under a second.
- **Backup channel:** agents also form a direct peer mesh over the team subnet (mTLS, per-node certs). They relay signed rules and hunt requests to each other. If the jump box or etcd is unreachable, boxes keep sharing. A compromised peer can't forge rules because it lacks the signing key.
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

**Collection rules** *(added after the Plan 1 review; the scanned box is hostile input)*:

- Nothing is left out by path alone except the kernel's own views (`/proc`, `/sys`). The same filesystems mounted anywhere else are recorded as a directory and not entered.
- Trees that churn on a healthy box (logs, caches, mail spool, runtime dirs, database files) are not inventoried file by file, but a setuid/setgid or capability-carrying file, or anything in a persistence location, is recorded wherever it sits. Container storage (`/var/lib/docker`, `/var/lib/containerd`) is recorded as a directory only; its contents belong to the Docker inspector (§6.2).
- Per-instance identity files (machine-id, SSH host keys, netplan, hostname) are skipped only when they are plain files.
- The collector never follows a symlink, opens only regular files, and bounds every read. Anything it could not read is reported as an `error` finding at High or above — never a silent pass — and a scan with such findings exits non-zero.
- Account databases are parsed the way glibc parses them; a line glibc would skip is reported rather than dropped.
- The package layer vouches for a file's content and packaged mode only. Setuid/setgid bits or capabilities beyond what the `.deb` ships are a privilege finding. It does not vouch for dpkg's own database (`/var/lib/dpkg`), which surfaces at T-0 and is absorbed by triage.
- Until the console exists (Plan 6), "triage" is a full T-0 snapshot used as the top layer: everything present at T-0 is treated as approved in one step.
- Baseline files never contain password hashes and are written readable by their owner only.

## 6. Detection

### 6.1 Network and process (primary focus)
- eBPF hooks on exec, connect, accept, bind, socket creation; every event attributed to pid, binary path + hash, uid, parent chain, container (cgroup), and origin (unit, cron, SSH session, web request).
- **Reverse shell:** shell/interpreter whose stdio fds are sockets, or a shell spawned by a network service (apache, mysqld, postfix children), or any new outbound connection to a non-allowlisted address.
- **Egress attempt:** any outbound connect not in the allowlist (dropped by nftables; eBPF supplies the process attribution). *(Builder's call:)* hardening first disables stock services that phone home (snapd, motd-news, apt-daily timers, ubuntu-advantage/pro, timesyncd unless NTP is needed, Docker's update/registry pulls), and that disabled state is part of the baseline. A blocked attempt by a remaining baseline process is **alert-only**; kill applies to non-baseline processes, shells/interpreters, and anything matching a rule.
- **DNS:** outbound DNS is blocked by default (§8 DNS). Any lookup attempt while blocked is an alert; high-entropy/long subdomains and bursts are scored higher. With the DNS switch on, the same scoring runs on every query to the resolver and a query for a name outside the allowed list is an alert naming the process.
- **Raw sockets:** processes holding `AF_PACKET`/`SOCK_RAW` sockets or attached socket BPF filters (rare on a stock server → high-signal).
- **Listeners:** any listener not in baseline; `docker-proxy` and scored ports allowlisted.
- **Container:** process and network events inside the Apache container are watched the same way (cgroup-aware).
- *(Builder's calls, plan 2:)*
  - Hooked: exec, connect, sendmsg and socket creation. `accept` and `bind` are not hooked: listeners and accepted connections come from the socket tables, read by a 1 s sweep of `/proc` that also sees what existed before the agent started. Without eBPF the agent falls back to the netlink proc connector (exec only) and then to the sweep alone, and says which it runs.
  - An unknown listener or raw socket held by an unmodified baseline binary is **alert-only**; the firewall still blocks the port. Holders that are not baseline, or are shells, interpreters or net tools, are killed. `xdr listeners` prints the current listeners in the config's format so known ones can be listed, and the holders of packet and raw sockets as `{"proto": "packet"|"raw", "exe": …}` entries: such an entry makes that socket known while the binary matches the baseline (networkd's DHCP client on 24.04). Loopback listeners are low-severity alerts. Only `AF_PACKET` and IPv4/IPv6 `SOCK_RAW` sockets count as raw (netlink sockets are `SOCK_RAW` too). A classic BPF filter on an ordinary TCP/UDP socket is not detected.
  - *Service shell:* a shell or net tool whose ancestors, walked up from its parent, reach a guarded process (one in `guard_exes`, or holding a listener on a scored port) that holds a listening socket, before reaching pid 1, a kernel thread or another shell or net tool. `sshd` is never the service (with socket activation pid 1 holds port 22), and a shell under a shell is judged by its parent, not reported again. Legitimate CGI or `system()` shells of a web server die too; `"kill": false` is the switch for a first run.
  - A listening UDP socket is any bound UDP socket with no peer; a listener is "known" when any process holding it matches a `listeners` entry (port, protocol and executable) or is `docker-proxy`.

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
  - accepted only from the jump box/operator IPs (there is no management interface, §3a);
  - key-only, with the key held off-box;
  - excluded from the "new user" and "non-baseline session" rules;
  - alerted on every login.

  It's also enforced at the sshd level (`Match` block) and in our nftables table, so it doesn't depend on the agent.
- Agent re-asserts the known-good `/etc/pam.d/sshd` and `sshd_config` on drift.
- Auto-disable sessions whose user isn't in baseline.
- **Gray team accounts (§3a) are outside the gate.** Their sessions are never terminated and never need approval; each login raises an alert with source address and the session's process tree stays under the normal network/process detections (a reverse shell started from a gray session is still killed — that is a red-team tool on our box, not the account). The gate reads the protected-account list from signed config, not from `/etc/passwd`, so adding a user named like one doesn't earn the exemption, and a protected name with a changed UID or a UID of 0 is a critical alert.

### 7.4 Other response
- New users disabled until approved.
- Destroy rules (service / file-hash): dry-run + undo (quarantine copy), never match scored binaries.
- Session management: view/kill sessions; kill connections to non-baseline remotes.
- Kill unknown listeners (with the scored-service guard).
- **Tampering** with any XDR file, unit, rule, eBPF program or process is treated as confirmed red team: kill the actor, terminate its session, alert. Kill-first, even in a root shell (scored-service guard still applies).

## 8. Hardening and firewall

- SSH keys-only, password auth disabled, for the ten blue-team accounts and root. Rotate their creds (they all start on one shared default password, so this is the first action at T-0) and replace their `authorized_keys`; regenerate host keys. **Do not rotate credentials the scorer uses** without checking the rules.
- Gray team accounts keep whatever they had: password, keys, shell, sudo rights, and the authentication methods sshd offered them at T-0 (a `Match User` block preserves those while the global default tightens). T-0 tooling refuses to act on a protected account even if asked.
- No management interface exists (§3a). sshd listens on the one interface; `AllowUsers` pins blue-team and recovery accounts to the jump box address and leaves gray accounts reachable from the gray subnet.
- nftables: our own table with base chains on input, output and forward hooks.
  - Inbound: scored ports from anywhere; SSH from the jump box, and from the gray/red subnet because gray team shares it with the attackers (sshd's `AllowUsers` is what narrows that to gray accounts); XDR from the jump box and the other two agents only.
  - Outbound: established/related only, plus XDR peers/etcd/controller.
  - Forward (Docker): same egress policy for the container. Because a drop in any nf_tables chain is final, Docker's own accept rules can't override ours.
  - Default-deny, inverted workflow: scored services allowed first, additions approved in the console.
- **DNS (decided 2026-11-10): off, with a switch.**
  - *Default — hard-coded names.* No DNS leaves the box. The few names a box really needs (its own, the other team hosts, the domain, anything a scored service resolves) are written into `/etc/hosts` from signed config, `nsswitch.conf` is pinned to `files` for hosts, and the agent re-asserts both on drift. A DNS-tunnelling C2 has no resolver to talk through.
  - *Switch on, per host, from the console.* Lookups go through a local stub run by the agent, and only the agent may send to port 53, and only to the team resolver (`.1`). The stub forwards a query only if the name is on an allowed list held in signed config; anything else is refused and alerted with the asking process. Arbitrary subdomains therefore never leave the box, which is what a DNS C2 needs. Turning it on is an operator action, shows on the host card, and can carry an expiry so it doesn't stay open by accident.
  - Either way a query to any other server, or DNS over TCP/TLS/HTTPS to an outside address, is dropped by the egress policy and alerted.
- Postfix: disable reverse lookups (`smtpd_peername_lookup = no`) and anything else needing DNS; the container gets the same static hosts file — so the default (DNS off) holds for all three scored services.
- **Password rotation.** The controller generates each new password on the jump box and sends the agent only its hash (`chpasswd -e`); for service accounts (MySQL users and the like) where the service needs the cleartext, it is sent over the agent's mTLS channel and not stored on the target beyond what the service itself keeps. Cleartext lives in the controller's local store on the jump box, never in etcd where a rooted agent could read it. Gray accounts are refused (§3a).
- Agent re-applies the ruleset on a short loop and alerts on drift.
- *(Builder's calls, plan 2:)*
  - **The DNS stub always runs**, also with the switch off. `resolv.conf` points at it and it answers NXDOMAIN at once, so a scored service that does its own lookups fails fast instead of waiting on a dropped packet, and every name asked is logged with the asking process. With the switch on it forwards only allowed names. A refusal is NXDOMAIN, not REFUSED, so callers do not retry. The stub is UDP only.
  - "Only the agent may send to port 53" is a socket mark (`0x58445201`) on the stub's upstream socket. Root can forge the mark; the destination is still pinned to the team resolver.
  - **Established is not a free pass.** Only the reply direction of a tracked connection is accepted without a rule (a mirror of each allow rule); the original direction must match an allow rule on every packet. A reverse shell open before the table loads is cut; an in-flight scored or SSH session survives. On a host that tracked no connections before the table loaded, an open connection is picked up from whichever packet comes first: the rules for SSH from the jump box and for XDR to and from the jump box and peers therefore accept both directions (the far end is pinned to an address the red team cannot hold), so the operator's session survives; a scored session in which the server speaks first is cut once, and its client reconnects.
  - Outbound ping is dropped (ICMP tunnels); inbound echo is answered. DHCP client traffic is allowed unless `dhcp` is false: requests to the broadcast address and to `dhcp_server`, replies from `dhcp_server` (from anywhere when it is not set). Without it, renewals fall back to the broadcast rebind.
  - Drift is checked by reading the table back over netlink and comparing it byte for byte with what was written; any difference is re-applied and logged.
  - Other tables are not ours to change, but their base chains are watched: one that appears after the agent starts is an alert (`fw-foreign`), and so is a nat chain on output that runs after ours (priority above -10) at any time, since it could redirect traffic our table let out. Rules added to an existing chain of another table are not seen.
  - `xdr fw try` applies the table and takes it back unless `xdr fw confirm` runs within the timeout (to the table of the last confirmed try, or none); a hangup does not stop it and SIGINT/SIGTERM revert at once: there is no console to recover a wrong jump-box address. A config with no `jump` address is refused.
  - SIGHUP reloads the config, but a reload that changes `jump`, `ssh_from`, `ssh_port` or `xdr_ports` is refused: the agent applies its table with no trial and no revert, so those take a restart after `xdr fw try`. A changed `dns.listen` is refused too (the stub stays where it is bound). While the agent runs it re-applies its table within 3 s of any change, `xdr fw remove` and a `fw try` table included; both are for a box where the agent is stopped.
  - `"kill": false` in the config turns every kill into a logged `would-kill`.
  - Host-to-container traffic is egress like any other: a host process talking to a container address needs an `allow_out` entry for the bridge subnet. On a Docker host with `br_netfilter` loaded, container-to-container traffic on one bridge is expected to pass the forward chain too and be dropped unless `allow_out` covers it (not yet measured; plan 2's VM has no Docker).
  - The agent never removes the table on exit; only `xdr fw remove` does. With the agent dead, the table keeps dropping.

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
1. Re-assert our nftables table and its allow rules for fleet peers and the jump box.
2. Find and remove anything local that blocks fleet traffic:
   - foreign nftables tables/chains, iptables-legacy rules and `ip6tables` rules that drop or reject fleet addresses or ports;
   - `ip rule`/route blackholes, `tc` filters, `/etc/hosts.deny`.

   Each removal is logged as a tamper incident.
3. Restore the network interface: link up, baseline address, routes. Undo `ip link set down` and changed addresses.
4. Restore the known-good `sshd_config` and its listen address, then restart sshd (and `ssh.socket`) so the controller can get in.
5. Restart the agent's mesh/etcd clients. Re-open the agent's management listener, moving to pre-agreed alternate ports if the primary port is taken.
6. **Call home.** The agent dials *out* to the jump box on several pre-agreed ports and holds a reverse control channel open. Outbound to the jump box is always allowed in our table, so control is regained even when inbound is blocked.
7. Keep cycling the ladder with backoff (fast at first, capped at ~30s) until reconnected.

**Guardrails:**
- The ladder never touches scored-service ports or rules.
- It only opens access to the jump box, and fleet peers, never broad egress.
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
- **Hosts:** agent / firewall / baseline-drift / heartbeat per box; break-glass control; the DNS switch with its state and expiry.
- **Credentials:** every rotated password, by host and account, each with a copy button, plus one "copy all" that produces a block to paste to the scoring engine (host, service, account, password). Values are masked until revealed or copied, show when they were last rotated, and a rotate-again action lives beside each. Copy must work on the phone as well as the desktop. Served only to the authenticated operator, from the jump box's local store.

## 12. Cut / demoted

- SSH port rotation — cut as prevention; optional probe tripwire/alert only, slow interval.

## 13. Open items

- **Apache container:** rebuild from a clean pinned image we pre-stage (leaning this way) vs. keep theirs and baseline the docroot/image. Either way: docroot diff, image/restart-policy inspect, container egress under our forward chain.
- Still unknown from the packet: the scored ports, which names each scored service needs resolved (they go in the hard-coded hosts list), and whether the mail server moves to another network. Jump box placement stays unknown until the day and is handled as config (§3a).
- Whether eBPF signal-blocking is available on the competition kernel (§9).

## 14. Left to the builder

Internal package layout, rule format, etcd key schema, UI framework (keep it embeddable, no CDN at runtime), grace-window and re-assert intervals, exact eBPF hook points, test strategy (a VM/container harness replicating Ubuntu 24.04 + the three scored services is expected).
