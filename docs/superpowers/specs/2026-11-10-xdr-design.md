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
- Scored services: Apache (in Docker, HTTP/HTTPS), SMTP, MySQL, Samba.
- We start with root.
- Legitimate outbound traffic from target boxes: **none**, other than replies to inbound score checks, blue-team access, and XDR traffic (peers, etcd, control plane).
- Operator works from a desktop (primary) / laptop / phone, connecting to the control plane.
- Deployment: Ansible during the setup window; nothing built live.

## 3a. Competition environment (from the packet, 2026-11-10; revised 2026-11-11)

Hostnames are placeholders and the mail server's network is not final, so nothing below is compiled in: it is deployment config, keyed by team number.

| Host | OS | IP | Scored service | XDR |
|------|----|----|----------------|-----|
| SecurityBlanket | Windows Server 2019 | 192.168.N.1 | AD, DNS | out of scope |
| PsychiatricBooth | Windows Server 2019 | 192.168.N.2 | IIS | out of scope |
| KiteTree | Ubuntu 24.04 | 192.168.N.3 | MySQL | agent |
| ToyPiano | Ubuntu 24.04 | 192.168.N.4 | SMTP | agent |
| Doghouse | Ubuntu 24.04 | 192.168.N.5 | Apache (Docker) | agent |
| Typewriter (cloud) | Windows Server 2019 | 10.0.N.1 | IIS | out of scope |
| Snowman (cloud) | Ubuntu 24.04 | 10.0.N.2 | Samba | agent |

- Two networks per team (revised 2026-11-11): the **local** /24 (`192.168.N.0/24`, N = team number; team 1 shown in the packet), gateway `.254` (OpenStack router), with five boxes; and a **cloud** subnet (`10.0.N.0/24` by the packet's addresses) with two: a Windows IIS box and the Samba box. Domain `TEAMN.PEANUTS.LOCAL` (Windows only; Samba is not stated to join it). **No separate management interface.** So: 3 Windows and 4 Linux boxes, 4 agents.
- **The cloud subnet is routed, not shared.** Mesh, etcd and SSH to Snowman cross a router; whether the jump box can reach it, and whether it uses DHCP, a different gateway, or a cloud metadata address, is unknown until T-0. All of that is per-host config (peers, jump), never a subnet assumption. *(Since plan 4b the table is policy accept with a blocklist: DHCP, metadata and other outbound traffic pass unless the fleet blocks an endpoint, so there is no `dhcp` or `allow_out` to set.)*
- The scoring engine and the red team's attack boxes **share one subnet** outside ours. A source address therefore never proves "this is the scorer": scored ports stay open to that subnet, and every other control has to work without source-based trust.
- The Windows boxes (two local, one cloud) are not covered by this tool. Treat them as untrusted neighbours: a compromised Windows box is an attacker inside its subnet. Nothing is allowed from them to the Linux boxes beyond what a scored service needs, and DNS replies from the local `.1`.
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
  - Rule kinds so far: binary hash, and remote address+port+proto. A remote rule kills local processes connected to that endpoint and never blocks inbound traffic (the scorer shares a subnet with the red team); a socket on a scored port never matches. Parent→child and persistence rules came with plan 3b (below).
  - Proposals come from reverse-shell, service-shell and egress incidents that were killed, would have been (`kill: false`) or held. A base-image binary proposes only its endpoint.
  - Every rule is checked twice, by the controller before signing and by the agent before enforcing, against the baseline, `guard_exes` and protected addresses (the controller's `protect`; the agent's own jump, peers, ssh_from and resolver). Caps: 256 promoted rules per proposing host, 4096 in all.
  - The set carries a version that only rises; an agent refuses an older or badly signed set (`rules-refused`) and keeps the last verified one on disk, enforcing it from start, before etcd answers.
  - Only the operator removes a rule (`xdr rules revoke`), and a revoked rule is never promoted again. Rules do not expire.
  - A container's shells and interpreters propose no hash and match no hash rule: they are the image's own, in no host baseline. Neither the agent's nor the controller's own binary can ever be a hash rule.
  - The controller cuts what a proposer controls (detail to 256 bytes, exe to 512, seen no later than now) and refuses a set over 1 MiB, below etcd's request limit.
  - A host writing more than 600 keys a minute (proposals, incidents, heartbeats) loses its write access for good (`host-disabled`); the operator can do the same by hand (`xdr controller disable-host`). etcd history is compacted every 5 minutes, so a stream of puts cannot fill its quota.
  - Heartbeats are an etcd key on a 10 s lease; the controller reports `agent-silent` when it lapses (or none came within 15 s of its start) and `agent-back` on the next one. Agent incidents are copied into the controller's own log.
- *(Builder's calls, plan 3b:)*
  - Three more rule kinds. **Parent**: a parent exe spawning a given shell, interpreter or net tool, proposed from reverse-shell and service-shell kills. It never names a session launcher or script runner as the parent (systemd, init, sshd, sshd-session, cron, atd, login, sudo, su, tmux, screen, containerd-shim*, or any shell or interpreter), since that would kill every login or script. **Unit**: a systemd unit name plus the hash of its unit file, proposed only when the file is not a base-image file; it matches processes in that unit's cgroup. **Cron**: the command a crontab line runs, matched on `sh -c CMD` under cron and never naming a line from a base-image crontab.
  - A hunt is the indicators of one proposing incident: the binary (hash, size, path) unless it is a base-image binary, the remote endpoint, a non-stock unit, the cron command, and a non-baseline user. SSH key fingerprints wait for plan 4. The box that acted does not search itself; every other box does, once per hunt id.
  - A search reads only its own box. It hashes a file only when its size matches a hunted one, never enters /proc, /sys or container storage, and stops at 500,000 entries, 2 GiB read or 60 s (`hunt-partial`). It runs one at a time beside the event loop, with a queue of 16 and at most 30 hunts per sender per 10 minutes (`hunt-dropped`). A file at a hunted path with a new hash is a variant and is proposed as a hash rule.
  - Each box answers `hunt-hit` or `hunt-clean`. The controller sums each hunt up as `hunt <id> from <host>: found on …; clean on …; no answer from …` once every other enrolled host has answered, or after 60 s.
  - Hunts travel as etcd keys on a 10-minute lease. Only the sender's own key prefix may hold them, and a hunt whose sender differs from its key is dropped.
  - The mesh is HTTPS on the XDR port (`mesh.port`, normally 7443). It uses TLS 1.3 with host certs on both sides (host certs now serve as well as dial), checks the chain against the fleet CA, and requires the other end's CN to be another host.
    - Endpoints: `POST /beat` (version), `GET`/`POST /rules` (signed envelope, ≤ 2 MiB), `POST /hunt` (≤ 64 KiB). An address over 20 requests a second gets 429.
    - Beats go every 3 s. The side with the older set pulls, or is pushed, the newer one, which must verify against the rule key and be newer than the set in force. A set taken from etcd is pushed to peers at once.
    - Hunts are deduplicated by id over the last 1024 and passed on to every peer but the sender.
    - A peer with no inbound beat for 15 s gives `peer-silent`, and the next beat gives `peer-back`.

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
- **Reverse shell:** shell/interpreter whose stdio fds are sockets, or a shell spawned by a network service (apache, mysqld, postfix children), or a non-baseline binary making a new outbound connection (see Egress).
- **Egress (decided 2026-11-16, replacing the allowlist):** there is no outbound allowlist, because a scored service may need any destination and the packet cannot list them. A new outbound connection is judged by the process behind it, not by where it goes: a base-image program with no shell/interpreter/network-tool role (a service, `apt`, `chronyd`) is normal and raises nothing; a base-image shell, interpreter or network tool (`bash`, `python3`, `curl`, `nc`) gets an **alert** (a lead, Medium); a binary that is not in the base image is **killed** (unless it is a scored service, gray, or the agent) and its address and port are proposed as a block rule. *(Builder's call:)* hardening first disables stock services that phone home (snapd, motd-news, apt-daily timers, ubuntu-advantage/pro, timesyncd unless NTP is needed, Docker's update/registry pulls), and that disabled state is part of the baseline.
- **DNS (decided 2026-11-16):** DNS passes normally unless the lockdown switch is on (§8 DNS). A query to a name server other than the team resolver is judged like any outbound connection (above). With the lockdown on, lookups go through the agent's stub, every query is scored (high-entropy or long subdomains, bursts), and a query for a name outside the allowed list is an alert naming the process.
- **Raw sockets:** processes holding `AF_PACKET`/`SOCK_RAW` sockets or attached socket BPF filters (rare on a stock server → high-signal).
- **Listeners:** any listener not in baseline; `docker-proxy` and scored ports allowlisted.
- **Container:** process and network events inside the Apache container are watched the same way (cgroup-aware).
- *(Builder's calls, plan 2:)*
  - **Superseded 2026-11-16:** the default-deny table, the outbound allowlist (`allow_out`, DHCP rules, scored-port allows), the always-on DNS stub and "established is not a free pass" described below are replaced by the policy-accept table and the blocklist above (plan 4b). What still holds from this list: drift is read back and re-applied, foreign base chains are watched, `xdr fw try|confirm`, SIGHUP refusing a changed `jump`/`ssh_from`/`ssh_port`/`xdr_ports`, `kill: false`, and the table surviving the agent.
  - Hooked: exec, connect, sendmsg and socket creation. `accept` and `bind` are not hooked: listeners and accepted connections come from the socket tables, read by a 1 s sweep of `/proc` that also sees what existed before the agent started. Without eBPF the agent falls back to the netlink proc connector (exec only) and then to the sweep alone, and says which it runs.
  - An unknown listener or raw socket held by an unmodified baseline binary is **alert-only**. *(Residual risk, accepted 2026-11-16:* the table is policy accept, so the port is no longer closed by the firewall; killing a baseline service's extra listener could take a scored service offline. A red-team `sshd -p 2222 -f /tmp/x` is therefore reachable until an operator acts on the alert.*)* Holders that are not baseline, or are shells, interpreters or net tools, are killed. `xdr listeners` prints the current listeners in the config's format so known ones can be listed, and the holders of packet and raw sockets as `{"proto": "packet"|"raw", "exe": …}` entries: such an entry makes that socket known while the binary matches the baseline (networkd's DHCP client on 24.04). Loopback listeners are low-severity alerts. Only `AF_PACKET` and IPv4/IPv6 `SOCK_RAW` sockets count as raw (netlink sockets are `SOCK_RAW` too). A classic BPF filter on an ordinary TCP/UDP socket is not detected.
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
- Samba: `smb.conf` and its includes (`root preexec`/`preexec`/`postexec`, `magic script`, `add user script` and other script hooks, `usershare` definitions, writable shares that are exec-able paths such as a docroot or `/etc`), new Samba users in its passdb. *(Builder's call:)* Samba's passdb passwords are separate from Unix ones, so T-0 rotation (§10 tooling) covers them with `smbpasswd` for blue-team accounts the scorer uses, and never gray accounts.

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
- nftables: our own table with base chains on input, output and forward hooks, **policy accept** (decided 2026-11-16: default-deny is not an option, because malicious traffic has to be found before an address or port can be blocked, and a deny-first table would take a scored service offline). Its rules are only these:
  - Loopback and invalid-state housekeeping.
  - The agents' own ports (`xdr_ports`): accepted from the jump box and the other agents, dropped from everyone else.
  - The **blocklist**: every signed `remote` rule (address, port, protocol) the agent has validated becomes a drop of outbound and forwarded packets to that endpoint, so one find is cut on every box at once. Inbound traffic is never blocked (the scorer shares a subnet with the red team), a rule never names a protected address (jump box, peers, ssh_from, the resolver), and the blocklist is capped.
  - SSH is not filtered here: sshd's `AllowUsers` and the gate (§7.3) decide who gets in.
  - The table stays with the agent dead. Revoking a rule removes its drop within a sweep.
- **DNS (decided 2026-11-16): pass normally, with an opt-in lockdown.** By default the agent does not touch `/etc/hosts`, `nsswitch.conf` or `resolv.conf`, runs no stub, and drops no DNS; abuse is found through the egress and DNS detections (§6), and a malicious name server is blocked like any other endpoint. The earlier design is kept as `dns.pin`: hard-coded names in `/etc/hosts` from signed config, `nsswitch.conf` pinned to `files`, the stub answering NXDOMAIN or forwarding only names on the allowed list (per-host switch in the console), and only the agent allowed to send to port 53, to the team resolver. It is off unless a host's config turns it on.
- Postfix: disable reverse lookups (`smtpd_peername_lookup = no`) and anything else needing DNS; the container gets the same static hosts file — so that lookups cannot stall the three scored services.
- **Password rotation.** The controller generates each new password on the jump box and sends the agent only its hash (`chpasswd -e`); for service accounts (MySQL users and the like) where the service needs the cleartext, it is sent over the agent's mTLS channel and not stored on the target beyond what the service itself keeps. Cleartext lives in the controller's local store on the jump box, never in etcd where a rooted agent could read it. Gray accounts are refused (§3a).
- Agent re-applies the ruleset on a short loop and alerts on drift.
- *(Builder's calls, plan 2:)*
  - **Superseded 2026-11-16 (plan 4b):** the always-on DNS stub, "established is not a free pass", the dropped outbound ping and the DHCP rules below belong to the default-deny table, which the policy-accept table and the fleet's blocklist replaced (see §6.1). Drift read-back, foreign chains, `xdr fw try|confirm` and the SIGHUP rules still hold.
  - **The DNS stub always runs**, also with the switch off. `resolv.conf` points at it and it answers NXDOMAIN at once, so a scored service that does its own lookups fails fast instead of waiting on a dropped packet, and every name asked is logged with the asking process. With the switch on it forwards only allowed names. A refusal is NXDOMAIN, not REFUSED, so callers do not retry. The stub is UDP only.
  - "Only the agent may send to port 53" is a socket mark (`0x58445201`) on the stub's upstream socket. Root can forge the mark; the destination is still pinned to the team resolver.
  - **Established is not a free pass.** Only the reply direction of a tracked connection is accepted without a rule (a mirror of each allow rule); the original direction must match an allow rule on every packet. A reverse shell open before the table loads is cut; an in-flight scored or SSH session survives. On a host that tracked no connections before the table loaded, an open connection is picked up from whichever packet comes first: the rules for SSH from the jump box and for XDR to and from the jump box and peers therefore accept both directions (the far end is pinned to an address the red team cannot hold), so the operator's session survives; a scored session in which the server speaks first is cut once, and its client reconnects.
  - Outbound ping is dropped (ICMP tunnels); inbound echo is answered. DHCP client traffic is allowed unless `dhcp` is false: requests to the broadcast address and to `dhcp_server`, replies from `dhcp_server` (from anywhere when it is not set). Without it, renewals fall back to the broadcast rebind.
  - Drift is checked by reading the table back over netlink and comparing it byte for byte with what was written; any difference is re-applied and logged.
  - Other tables are not ours to change, but their base chains are watched: one that appears after the agent starts is an alert (`fw-foreign`), and so is a nat chain on output that runs after ours (priority above -10) at any time, since it could redirect traffic our table let out. Rules added to an existing chain of another table are not seen.
  - `xdr fw try` applies the table and takes it back unless `xdr fw confirm` runs within the timeout (to the table of the last confirmed try, or none); a hangup does not stop it and SIGINT/SIGTERM revert at once: there is no console to recover a wrong jump-box address. A config with no `jump` address is refused.
  - SIGHUP reloads the config, but a reload that changes `jump`, `ssh_from`, `ssh_port` or `xdr_ports` is refused: the agent applies its table with no trial and no revert, so those take a restart after `xdr fw try`. A changed `dns.listen` is refused too (the stub stays where it is bound). While the agent runs it re-applies its table within 3 s of any change, `xdr fw remove` and a `fw try` table included; both are for a box where the agent is stopped.
  - `"kill": false` in the config turns every kill into a logged `would-kill`.
  - Container traffic is forwarded traffic: a block rule applies to it as to the host's own.
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

*(Builder's calls, plan 6, 2026-11-16:)*
- **Layout.** `xdr install` puts the binary in three places (`/usr/local/sbin/xdr`, `/usr/lib/xdr/xdr`, `/var/lib/xdr/bin/xdr`), its hash in `/etc/xdr/pinned.sha256`, a manifest of everything it installed in `/var/lib/xdr/manifest.json`, a backup of the agent config, signature and fleet bundle, and makes all of it immutable (`chattr +i`).
- **Launch points.** Every one picks the first copy whose hash equals the pinned one and runs `xdr ensure` (or the agent): the agent's unit (`Restart=always`), two guard units with different names that watch each other, a 30 s timer, cron (`@reboot` and every minute), a systemd generator, and an apt `Post-Invoke` hook. `ensure` restores any file that differs from the manifest from a good copy (or the backup), re-enables and starts what is not running, and reports what it had to do as a `tamper` incident; with no good copy it says so and exits non-zero.
- **Tamper.** fanotify watches the installed files and their directories and names the process that touched them. A process running the pinned binary (the agent, a guard, `ensure`) is the box's own; any other actor is treated as red team: a `tamper` incident (Critical), its process tree killed, its login session terminated unless it is an auto, recovery or gray account (gray is alert-only as everywhere; a scored service is held; a pause token makes it an alert). A reverse shell from a gray session is still killed.
- **Not signed.** The pinned hash and manifest are not signed: a root attacker who gets past the kill can rewrite them together with the files. Accepted: the defence is that the writer is killed first, and the controller can reinstall.
- **Updates** are: take a pause token, `xdr install` the new binary, let the pause lapse. There is no in-place self-update.
- **Controller reinstall.** `xdr controller reinstall --host H` (and automatically after a host has been silent for `reinstall.after`, once per episode, at most every 5 min) pushes over SSH with the controller's own key (`controller.json` `reinstall`): the binary, a fresh enrolment bundle, the host's agent config signed on the spot, then runs `xdr install` on it. The key never goes to a target.
- **Isolation (9a).** A host is isolated when etcd and every peer have been out of reach for 10 s. The ladder then runs with backoff (2 s doubling to 30 s): (1) re-apply the table; (2) remove what blocks the fleet: foreign nftables tables with a drop or reject naming a fleet address or port, `iptables`/`ip6tables` (legacy) drop and reject rules naming them, `ip rule`/`ip route` blackhole, unreachable and prohibit entries for them, `hosts.deny` lines; each removal a `tamper` incident; (3) bring the link, address and default route back to what the agent saw at start; (4) restart sshd when nothing listens on its port. Step 5 is nothing: the etcd and mesh clients retry by themselves. Step 6 (call-home) is not built: the agent's outbound connection to the jump box is already the channel, and an alternate-port listener on the controller is future work. The ladder never touches scored ports or rules, only opens access to the jump box and the peers, and never reboots. `tc` filters are not examined.
- **Off switch.** A signed break-glass token with action `uninstall` removes the launch points, the files and the table (`xdr breakglass -`, the token on stdin so it stays out of argv, with the agent up, `xdr uninstall --token TOKEN` with it dead).
- **Not built.** Pinned eBPF programs and BPF-LSM signal blocking (optional in the spec; the stock kernel's support is unverified).

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

*(Builder's calls, plan 4:)*
- The whole agent config is signed (`agent.json.sig`, the jump box's rule key, purpose `config`), not just the protected-account list; a box enrolled at the default place needs the signature even if its config drops the fleet section. `xdr controller sign-config` signs it.
- Platform sessions are the `ssh.auto` accounts connecting from a jump address: they pass the gate and are approved at once. Gray and recovery skip the gate at PAM, so they log in with the agent dead; everyone else is refused at PAM while the agent is down (fail closed) unless a pause token for the host is in the spool.
- A pause token turns gate ends and automatic kills into alerts until it expires. An approve token approves one session, once; tokens dropped in the spool (`/var/lib/xdr/breakglass`) while the agent is down take effect when it is back. With the agent dead the gate finds the host's name in the fleet bundle's certificate.
- The agent refuses at login a session it would end at once (an account not in the baseline), and one logind does not know.
- Samba rotation sends the NT hash (`pdbedit --set-nt-hash`), so no cleartext leaves the jump box; MySQL credentials wait for the service inspectors (plan 6).
- Orders (session verdicts, user approvals, credential sets) ride etcd under `/xdr/to/<host>/`, readable by that host only, even when it is disabled. No new controller listener.
- New login accounts (uid >= 1000, a real shell, no scored service running as them) are locked with `usermod --lock --expiredate 1`; other new accounts are alerted on. An approval unlocks only what the agent locked.
- nftables already limits SSH to jump and `ssh_from`; per-account pinning is sshd's `AllowUsers`.

## 11. Control-plane console

Web UI served by the controller on the jump box. Primary use on desktop; must also work on phone. Mockup: https://claude.ai/artifact/EYEaRd2sYnpqMRyRJSoywX (design to be iterated later).

- Header: competition clock, etcd health.
- Summary: items needing the operator, auto-kills, agents up, egress blocked.
- **Alerts:** auto-handled incidents with process chain, endpoint, hash, origin, and a checklist of actions taken (killed / rule written / pushed / pending).
- **Approvals:** gated items (scored-port process, file/persistence removal with dry-run + undo, new users).
- **SSH sessions:** pending sessions with countdown, approve / kill; session list.
- **Hosts:** agent / firewall / baseline-drift / heartbeat per box; break-glass control; the DNS switch with its state and expiry.
- **Credentials:** every rotated password, by host and account, each with a copy button, plus one "copy all" that produces a block to paste to the scoring engine (host, service, account, password). Values are masked until revealed or copied, show when they were last rotated, and a rotate-again action lives beside each. Copy must work on the phone as well as the desktop. Served only to the authenticated operator, from the jump box's local store.

*(Builder's calls, plan 5, 2026-11-16: the console before self-protection, at the operator's request.)*
- **Scope.** The console is: the web UI in the controller, the agents' continuous baseline-drift report that feeds it, and the approvals it offers. The service inspectors (MySQL, Docker, Postfix, Samba) are not part of it and come later; "restore a clean binary" needs a package source the air-gapped boxes do not have, so it is not offered. The DNS switch is left out: DNS passes by default now, and the lockdown it switched is opt-in.
- **Approvals offered:** approve or kill an SSH session; approve a new user; remove a file the agent found (a *new* file in a persistence location, never a changed or removed base-image file), moved to a quarantine and restorable for 24 hours; kill a process the agent held because it is a scored service, after the operator says so; ignore any of them.
- **Drift report.** Each agent compares persistence locations against the baseline every 30 s (a fast walk of those directories only) and the whole disk every 10 min, and reports each new or changed finding once as a `file-drift` incident naming the path. The comparison for a partial walk is restricted to the same directories, so nothing outside them reads as removed.
- **Serving.** `controller.json` gets `"console": {"listen": "ADDR:PORT"}`; without it there is no console. It is HTTPS with the controller's own server certificate (signed by the fleet CA, which the operator can trust in a browser). One operator password, set with `xdr controller console-password`, stored hashed; a login gives an `HttpOnly`, `Secure`, `SameSite=Strict` cookie for 12 hours; failed logins are rate-limited; every change needs the cookie and a custom header.
- **Hostile text.** Everything an agent sends (process names, paths, details) is shown as text, never as markup, and the page sends a strict Content-Security-Policy: a red-team process named `<script>` must not run in the operator's browser.
- **Credentials page.** Served only to the logged-in operator from the jump box's store; masked until revealed or copied; "copy all" gives the block for the scoring engine; rotate-again is beside each entry.
- **State.** The console keeps the last 2000 incidents and which approvals were handled in `DIR/console-state.json`, so a controller restart does not bring back finished approvals.

## 12. Cut / demoted

- SSH port rotation — cut as prevention; optional probe tripwire/alert only, slow interval.

## 13. Open items

- **Apache container:** rebuild from a clean pinned image we pre-stage (leaning this way) vs. keep theirs and baseline the docroot/image. Either way: docroot diff, image/restart-policy inspect, container egress under our forward chain.
- Still unknown from the packet: the scored ports, which names each scored service needs resolved (they go in the hard-coded hosts list), and whether the mail server moves to another network. Jump box placement stays unknown until the day and is handled as config (§3a).
- Whether eBPF signal-blocking is available on the competition kernel (§9).

## 14. Left to the builder

Internal package layout, rule format, etcd key schema, UI framework (keep it embeddable, no CDN at runtime), grace-window and re-assert intervals, exact eBPF hook points, test strategy (a VM/container harness replicating Ubuntu 24.04 + the three scored services is expected).
