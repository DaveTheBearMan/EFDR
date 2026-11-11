# XDR Plan 3a: Controller, etcd and Signed Rules — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A kill on one box becomes a rule that kills the same thing on every box within a second. The agent proposes a narrow rule from each kill. The controller on the jump box checks the rule, signs it and publishes it. Every agent verifies the signature and enforces the rule. Heartbeats tell the controller when an agent goes quiet.

**Architecture:**
- `xdr controller run` runs on the jump box. It embeds a single-node etcd server (`go.etcd.io/etcd/server/v3/embed`), so the jump box needs no separate etcd install.
- etcd serves TLS only and requires client certs. Auth is on: a client cert's CN is its etcd user, and RBAC limits each host to its own key prefixes plus read access to the rule set.
- The rule set is one etcd key: a JSON payload signed with an ed25519 key that never leaves the jump box. It carries a version number that only goes up.
- Each agent runs a fleet client in its own goroutine:
  - it watches the rule key and keeps a verified copy on disk;
  - it writes proposals, incidents and a lease-backed heartbeat under its own prefix;
  - it never blocks the sweep or event loop.
- Detection gains two pure detectors: `rule-hash` and `rule-remote`. They feed the existing `Decide`/`KillTree` path, so the scored-service and gray-team guards apply to them unchanged.

**Tech Stack:** Go 1.27, `CGO_ENABLED=0`; `go.etcd.io/etcd/server/v3` and `go.etcd.io/etcd/client/v3` v3.7.3. A probe on 2026-11-11 confirmed that both build static (+~20 MB binary). Also `crypto/ed25519`, `crypto/x509`, `crypto/tls`, and the existing packages.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md` §4 (state, rule promotion, fleet communication primary channel, trust model), §7.1 step 3, §9 heartbeats. Roadmap: row 3, split here into 3a (this plan) and 3b (peer mesh relay, fleet-wide hunt, rules from persistence).

## Global Constraints

- One static binary, `CGO_ENABLED=0 go build -trimpath`. Both roles are subcommands: `xdr agent`, `xdr controller`.
- Nothing from the competition packet is compiled in. Addresses, host names and ports come from config. Tests use `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, hosts `web01`/`db01`/`mail01`.
- Response stays on-box. A `remote` rule kills local processes talking to that address. It never adds an inbound block, never connects to the address, never scans it. The scorer shares a subnet with the red team (§3a), so no rule may stop inbound traffic.
- Agents enforce only rule sets whose ed25519 signature verifies against `rules.pub`, and only when the version is higher than the last one accepted. An unsigned or older set is an incident (`rules-refused`), never applied.
- The signing key (`rules.key`) and the CA key (`ca-key.pem`) exist only in the controller directory, mode 0600, directory 0700. Enrolment bundles carry only `ca.pem`, the host's cert and key, and `rules.pub`.
- Every rule passes validation twice: on the controller before signing, and again on the agent before enforcing. Both use `rules.Validate`. Validation rejects:
  - an exe hash that is in the baseline;
  - an exe hash from a path in `guard_exes`;
  - a remote that is in a protected net, loopback, link-local, multicast, broadcast or unspecified, or has port 0.
- Rule hits go through `respond.Decide`. Guarded processes are `held`. Gray-team processes are `alert` for `rule-remote`; `rule-hash` on a gray account is also `alert`. With `kill: false`, a hit is `would-kill`.
- The fleet client must never stall the agent. All etcd I/O runs in its own goroutine. Callbacks into the agent take `a.mu` only for in-memory swaps. Etcd calls have a 5 s timeout.
- Etcd key schema (prefix `/xdr/`), fixed for 3a and 3b:
  - `/xdr/rules`: the signed envelope. Only the controller writes it.
  - `/xdr/proposed/<host>/<rule id>`: a proposal, written by the host and deleted by the controller once judged.
  - `/xdr/incidents/<host>/<unix-nanos>`: an incident line, written by the host and deleted by the controller once logged.
  - `/xdr/heartbeat/<host>`: heartbeat JSON on a 10 s lease, written by the host.
- Limits: at most 256 promoted rules per proposing host and 4096 in all. A proposal or incident value may be at most 16 KiB. Heartbeat lease TTL is 10 s with keepalive. The controller reports a host silent 15 s after its heartbeat goes away, or 15 s after start if it never sent one.
- Narration and copy follow the existing CLI: errors are `xdr <cmd>: …`, printable() for hostile strings.

## Calls made in this plan (not in the spec — review these)

- **Etcd is embedded in `xdr controller run`**, not installed as its own service. That is one less thing to deploy on the jump box, and the same binary on both ends.
- **Plan 3 is split.**
  - 3a has signed rules end to end, plus heartbeats.
  - 3b has:
    - the peer mTLS mesh relay (the backup channel);
    - fleet-wide hunt from incident indicators;
    - rules derived from persistence (cron entry, unit), which needs Plan 6's removal path.
- **Two rule kinds in 3a: `hash` and `remote`.**
  - `parent→child` is left to 3b. A pattern loose enough to catch a shell under a service is already the `service-shell` detector. A narrower one needs the persistence origin, which 3b brings.
  - A `remote` rule is addr + port + proto. It matches a process with a connected (non-listening) socket to that endpoint, or a connect/send event to it. A socket whose local port is a scored port never matches, so a scorer source address that ended up in a rule still cannot hit a scored service.
- **Proposals come from incidents** of kind `revshell-stdio`, `service-shell` and `egress`, with action `killed`, `would-kill` or `held`:
  - a `hash` rule when the incident has a SHA256 and the process was not a baseline binary;
  - a `remote` rule when it has a TCP/UDP remote with a port.

  `would-kill` proposes too, so a dry run exercises the whole path.
- **Revoke is by the operator only:** `xdr rules revoke --dir D ID` publishes the next version without that rule. Rules do not expire in 3a.
- **Incidents are copied to the controller's own log** (`<dir>/incidents.jsonl`) and to its stdout, so there is one fleet-wide record before the console exists. Controller-side kinds are `agent-silent`, `agent-back`, `rule-rejected` and `rule-promoted`.
- **The agent keeps the last verified set** at `/var/lib/xdr/rules.json` (envelope plus nothing else) and enforces it from start, before etcd is reached. The high-water version lives in the same file. A root attacker on the box can roll that file back, but such an attacker can already stop the agent. Plan 5 covers that.
- **The controller's protected nets are `protect` in its config.** Every agent's `jump`, `peers`, `ssh_from`, `allow_out[].to`, `dns.resolver` and `dhcp_server` belong there; Plan 7's Ansible fills them from one source. An agent checks its own copies of those fields again before enforcing, so a gap in `protect` is caught on the box.

## Review Focus

1. **A compromised host floods proposals.** It writes thousands of distinct valid-looking remote rules. Expected: after 256 promoted rules from that host, every further proposal is `rule-rejected` ("host limit") and the fleet set stops growing. → Task 6 `TestPromote_HostCap`.
2. **Controller restart.** The controller must continue from the version in etcd, not restart at 1. Otherwise every agent refuses every later set. → Task 6 `TestPromote_VersionSurvivesRestart`.
3. **Etcd unreachable when the agent starts, or for minutes.** Expected: the agent sweeps and kills from the cached set at once, writes one `fleet` alert after 10 s of failure and one when it reconnects, and the event loop never waits on etcd. → Task 8 `TestClient_UnreachableDoesNotBlock`, Task 9 `TestRun_CachedRulesBeforeEtcd`.
4. **A rule hash matches a scored service** whose binary is missing from `guard_exes` but which listens on a scored port. Expected: `held`, never killed. → Task 4 `TestRules_GuardedHeld`.
5. **A replayed older envelope or a bad signature in `/xdr/rules`** (an attacker with etcd root, or a bug). Expected: `rules-refused` incident, the set in force stays. → Task 8 `TestClient_RefusesOlderAndForged`.

---

### Task 1: Rule set, signing and verification

**Files:**
- Create: `internal/rules/rules.go`, `internal/rules/rules_test.go`

**Interfaces:**
- Produces:
  - `type Rule struct { ID, Kind, SHA256, Exe string; Addr netip.Addr; Port uint16; Proto string; From string; Seen time.Time; Detail string }`
    - JSON tags are snake_case, with `omitempty` on the match fields.
    - `Kind` is `"hash"` or `"remote"`. `Exe` is informational. `From` is the proposing host. `Seen` is the incident time.
  - `func (r *Rule) Key() string`:
    - `"hash:"+sha256` or `"remote:"+addr+":"+port+"/"+proto`;
    - this is what makes two rules the same.
  - `func (r *Rule) SetID()`: sets `ID` to the first 16 hex chars of sha256(Key()).
  - `type Set struct { Version uint64; Issued time.Time; Rules []Rule }`
  - `func (s *Set) Lookup() Index`, with:
    - `type Index struct { Hash map[string]*Rule; Remote map[RemoteKey]*Rule }`;
    - `type RemoteKey struct { Addr netip.Addr; Port uint16; Proto string }`.
  - `type Envelope struct { Payload []byte; Sig []byte }`: JSON `payload` and `sig`, base64 by default encoding.
  - `func Sign(s *Set, key ed25519.PrivateKey) (Envelope, error)`
  - `func Open(e Envelope, pub ed25519.PublicKey) (*Set, error)`:
    - errors are `ErrBadSignature` or a decode error;
    - every rule must have a `SetID`-consistent ID, else an error.
  - `func Marshal(e Envelope) ([]byte, error)` and `func Unmarshal(b []byte) (Envelope, error)`.
  - `func LoadPublic(path string) (ed25519.PublicKey, error)` and `func LoadPrivate(path string) (ed25519.PrivateKey, error)`:
    - both read PEM files with types `XDR RULES PUBLIC KEY` and `XDR RULES PRIVATE KEY`;
    - `LoadPrivate` refuses a file whose mode is broader than 0600.

- [ ] **Step 1: Write the failing tests**
  - `TestSign_RoundTrip`: sign a set with one rule of each kind; `Open` returns an equal set.
  - `TestOpen_Tampered`: flip one payload byte → `ErrBadSignature`; verify with another key → `ErrBadSignature`.
  - `TestOpen_IDMismatch`: a signed set whose rule ID does not match `SetID` → error.
  - `TestRule_Key`: the two kinds give distinct keys; an IPv4-mapped address keys the same as plain IPv4 (unmapped on `SetID`).
  - `TestLoadPrivate_Mode`: mode 0644 → error naming the mode.
- [ ] **Step 2: Run** `go test ./internal/rules/`. Expected: FAIL, with the package not existing.
- [ ] **Step 3: Implement.** Sign the exact payload bytes. `Open` verifies before it decodes the JSON.
- [ ] **Step 4: Run** `go test ./internal/rules/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: signed rule sets`

### Task 2: Rule validation and proposals from incidents

**Files:**
- Create: `internal/rules/validate.go`, `internal/rules/propose.go`, `internal/rules/validate_test.go`, `internal/rules/propose_test.go`

**Interfaces:**
- Consumes: Task 1 `Rule`; `incident.Incident`.
- Produces:
  - `type Guard struct { Baseline func(sha256 string) bool; GuardExes []string; Protect []netip.Prefix }`
  - `func (g Guard) Validate(r Rule) error`:
    - errors name the reason: "baseline hash", "guarded exe", "protected address", "not a unicast address", "no port", "bad hash", "bad proto", "unknown kind";
    - `SHA256` must be 64 lower-case hex characters;
    - `Proto` must be tcp or udp.
  - `func BaselineHashes(b *baseline.Baseline) func(string) bool`: a set built once over `b.Files[*].SHA256`. A nil b matches nothing.
  - `func FromIncident(in incident.Incident, baselineExe bool) []Rule`:
    - returns rules with `ID` set, `From = in.Host` and `Seen = in.Time`;
    - kinds and actions are as in the Calls section above;
    - `Detail` is `in.Kind+": "+in.Detail`, cut to 256 bytes.

- [ ] **Step 1: Write the failing tests**
  - `TestValidate` is table-driven, with one case per error string plus accepted cases: a non-baseline hash, and remote `203.0.113.9:4444/tcp` with protect `192.0.2.0/24`.
  - Rejected cases:
    - `192.0.2.7:443/tcp` (protected);
    - `127.0.0.1:1`, `fe80::1:1`, `224.0.0.1:1`, `255.255.255.255:1` and `0.0.0.0:1`;
    - port 0;
    - an upper-case hash.
  - `TestFromIncident`:
    - an egress `killed` incident with sha and remote gives two rules;
    - with `baselineExe` true it gives only the remote rule;
    - a `listener` kind gives none;
    - action `alert` gives none;
    - a remote with port 0 gives no remote rule.
- [ ] **Step 2: Run** `go test ./internal/rules/`. Expected: FAIL, with undefined `Guard` and `FromIncident`.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./internal/rules/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: rule validation and proposals from incidents`

### Task 3: PKI and enrolment, `xdr controller init|enroll`

**Files:**
- Create: `internal/pki/pki.go`, `internal/pki/pki_test.go`, `internal/cli/controller.go`, `internal/cli/controller_test.go`
- Modify: `internal/cli/cli.go` (dispatch `controller`; usage lines)

**Interfaces:**
- Produces:
  - `func Init(dir string, serverNames []string) error`:
    - creates `dir` (0700) containing:
      - `ca.pem` and `ca-key.pem` (ECDSA P-256 CA, 5-year validity);
      - `server.pem` and `server-key.pem`, whose SANs are the given IPs and DNS names;
      - `root.pem` and `root-key.pem` (client cert with CN `root`, for the controller's own etcd client);
      - `rules.key` and `rules.pub` (ed25519, PEM types as in Task 1);
    - refuses if `ca-key.pem` exists ("already initialised").
  - `func Enroll(dir, host, out string) error`:
    - `out/` (0700) gets `ca.pem`, `host.pem` and `host-key.pem` (CN = host, ExtKeyUsage ClientAuth) and `rules.pub`;
    - host must pass `config`'s hostname check;
    - appends host to `dir/hosts` (one per line, de-duplicated).
  - `func Hosts(dir string) ([]string, error)`
  - `func ServerTLS(dir string) (*tls.Config, error)` and `func ClientTLS(caPath, certPath, keyPath string) (*tls.Config, error)`
  - CLI:
    - `xdr controller init --dir D --name ADDR [--name …]`;
    - `xdr controller enroll --dir D --host H --out O`.

- [ ] **Step 1: Write the failing tests**
  - `TestInit_Files`: every file exists; private keys are 0600 and the dir is 0700; a second `Init` errors.
  - `TestEnroll_HandshakeAndCN`:
    - a TLS server from `ServerTLS` with `ClientAuth: RequireAndVerifyClientCert` completes a handshake with `ClientTLS` from the bundle;
    - the peer cert CN is `web01`;
    - a client cert from another CA fails.
  - `TestEnroll_NoSecretsInBundle`: the bundle has no `ca-key.pem` and no `rules.key`.
  - `TestEnroll_BadHost`: `"../x"` → error.
  - `TestController_InitEnrollCLI`: both run through `cli.Run`, exit 0.
- [ ] **Step 2: Run** `go test ./internal/pki/ ./internal/cli/ -run 'Init|Enroll|Controller'`. Expected: FAIL.
- [ ] **Step 3: Implement.** Write files with `O_EXCL` and the target mode.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: controller PKI and host enrolment`

### Task 4: Rule detectors

**Files:**
- Modify: `internal/detect/policy.go` (field), `internal/detect/detect.go` (Sweep and Event)
- Create: `internal/detect/rules_test.go`

**Interfaces:**
- Consumes: Task 1 `rules.Index`, `rules.RemoteKey`.
- Produces:
  - `Policy.Rules *rules.Index`: nil means no rules.
  - `Sweep` and `Event` also return detections of kind `rule-hash` and `rule-remote`:
    - severity Critical;
    - `Detail` is `"rule "+id+" from "+from+": "+rule.Detail`;
    - `Remote` is set for remote hits.
  - `rule-hash`:
    - `p.Hash(pr)` is in `Index.Hash`;
    - Event: on `Exec` for the event's pid.
  - `rule-remote`:
    - a connected, non-listening inet socket whose remote (unmapped) addr, port and proto are in `Index.Remote`, and whose local port is not a scored port for that proto;
    - Event: on `Connect` or `Send` whose `Dst` and `Proto` match.
  - Subjects are as for the other detectors: never self, never kernel threads.

- [ ] **Step 1: Write the failing tests** (fixture snapshots, as in the existing detect tests)
  - `TestRules_HashHit`: a fixture proc with a fake `Hash` returning a rule hash → one `rule-hash` detection.
  - `TestRules_RemoteHit`: a connected socket to `203.0.113.9:4444/tcp` → `rule-remote`; a listening socket, or a socket whose local port is scored tcp/80, → none.
  - `TestRules_EventConnect`: a Connect event to the rule's endpoint → a detection for that pid.
  - `TestRules_GuardedHeld`: the hash hit is on a proc listening on scored tcp/3306 (not in `guard_exes`), and `respond.Decide` returns `"held"`. This test lives in `internal/respond/kill_test.go` with the same fixture.
  - `TestRules_GrayAlert`: a hash hit on a gray uid → `Decide` returns `"alert"`. Also in respond.
  - `TestRules_NilIndex`: no rule detections and no panic.
- [ ] **Step 2: Run** `go test ./internal/detect/ ./internal/respond/`. Expected: FAIL, because Rules is undefined.
- [ ] **Step 3: Implement.** No change to `Decide` should be needed. If `TestRules_GrayAlert` fails, the gray branch already covers it, so confirm it and do not special-case.
- [ ] **Step 4: Run** `go test ./internal/detect/ ./internal/respond/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: kill on signed rule hits by hash and remote endpoint`

### Task 5: Embedded etcd with TLS and RBAC

**Files:**
- Create: `internal/controller/etcd.go`, `internal/controller/etcd_test.go`, `internal/fleet/keys.go`
- Modify: `go.mod`, `go.sum`

**Interfaces:**
- Consumes: Task 3 `ServerTLS`, `ClientTLS`, `Hosts`.
- Produces:
  - `internal/fleet/keys.go` holds the key schema:
    - `const Prefix = "/xdr/"`, `RulesKey = "/xdr/rules"`;
    - `func Proposed(host string) string` returns `"/xdr/proposed/"+host+"/"`;
    - `Incidents(host)`, `Heartbeat(host)`, `ProposedAll = "/xdr/proposed/"`, `IncidentsAll`, `HeartbeatAll`;
    - `func HostOf(key, prefix string) (string, bool)`.
  - `func StartEtcd(dir, listen string) (*embed.Etcd, *clientv3.Client, error)`:
    - data in `dir/etcd`; client URL `https://listen`; peer URL on `127.0.0.1:0`-style localhost only;
    - `ClientTLSInfo` uses the server cert with `ClientCertAuth: true` and `TrustedCAFile: ca.pem`;
    - waits for ready (10 s);
    - returns a root client using `root.pem`;
    - etcd's own logger at level error, to `dir/etcd.log`.
  - `func Bootstrap(ctx context.Context, c *clientv3.Client, hosts []string) error`. It is idempotent:
    - user `root` with role `root`;
    - for each host, user `<h>` with no password and role `host-<h>`, which has:
      - readwrite on prefixes `Proposed(h)` and `Incidents(h)`;
      - readwrite on key `Heartbeat(h)`;
      - read on `RulesKey`;
    - auth enabled last.
  - Users exist with no password; with client-cert auth on, the cert CN selects the user.

- [ ] **Step 1: Write the failing tests** (in a temp dir, listening on `127.0.0.1:<free port>`)
  - `TestEtcd_HostRBAC`. A client using the `web01` bundle:
    - may put `/xdr/proposed/web01/x`;
    - is denied (`rpctypes.ErrPermissionDenied`) on `/xdr/proposed/db01/x` and on `/xdr/rules`;
    - may get `/xdr/rules`;
    - may grant a lease and put `Heartbeat("web01")` with it.
  - `TestEtcd_NoCertRefused`: a client with only the CA → connection or auth error within 5 s.
  - `TestEtcd_BootstrapTwice`: Bootstrap after a restart on the same dir succeeds; a host enrolled since then gets its role.
- [ ] **Step 2: Run** `go test ./internal/controller/ -run Etcd`. Expected: FAIL, with the package missing.
- [ ] **Step 3: Implement.** Add the etcd dependencies with `go get go.etcd.io/etcd/server/v3@v3.7.3 go.etcd.io/etcd/client/v3@v3.7.3`.
- [ ] **Step 4: Run** `go test ./internal/controller/ -run Etcd` and `CGO_ENABLED=0 make build`. Expected: PASS, and a static binary (`file bin/xdr` says statically linked).
- [ ] **Step 5: Commit** `feat: embedded etcd with per-host certs and RBAC`

### Task 6: Promotion, incidents, heartbeats; `xdr controller run`, `xdr rules`

**Files:**
- Create: `internal/controller/controller.go`, `internal/controller/controller_test.go`, `internal/controller/config.go`
- Modify: `internal/cli/controller.go` (`run`), `internal/cli/cli.go` (`rules` command)

**Interfaces:**
- Consumes: Task 1 (`Sign`, `Open`, `Set`), Task 2 (`Guard`, `BaselineHashes`), Task 5 (`StartEtcd`, `Bootstrap`, `fleet` keys); `incident.Log`; the embedded baseline (`baseline.Embedded()` or the existing accessor in `internal/baseline/embedded.go`).
- Produces:
  - `type Config struct { Listen string; Protect []config.Net; GuardExes []string; Baselines []string }`:
    - JSON `listen`, `protect`, `guard_exes`, `baselines`;
    - `func LoadConfig(path string) (*Config, error)`: listen must parse as host:port.
  - `type Controller struct { … }` with:
    - `func New(dir string, c *clientv3.Client, g rules.Guard, key ed25519.PrivateKey, log *incident.Log) (*Controller, error)`: reads the current `/xdr/rules` and continues from its version;
    - `func (c *Controller) Run(ctx context.Context) error`: watches `ProposedAll`, `IncidentsAll` and `HeartbeatAll`, and rescans each prefix after a watch restart.
  - On a proposal:
    1. Decode and size-check it. Check that `From` equals the host in the key; if not, override it with the key's host.
    2. `SetID`, then check that its key matches the etcd key's id.
    3. Validate it.
    4. Check the caps.
    5. If the rule is new, append it, increment `Version`, set `Issued`, sign, and put the result to `RulesKey`. On success write a `rule-promoted` incident (alert, High).
    6. On any rejection write a `rule-rejected` incident (alert, Medium) with the reason.
    7. Delete the proposal key in all cases.
  - On an incident key: decode it, set `Host` from the key, `log.Add`, then delete the key.
  - Heartbeats:
    - track the last put per enrolled host;
    - a delete (lease expiry), or no put within 15 s of start, gives `agent-silent` (alert, High), once until the host's next put;
    - the next put gives `agent-back` (alert, Medium).
  - `func (c *Controller) Revoke(ctx, id string) error`: publishes the next version without that rule, or errors with "no rule <id>".
  - `func (c *Controller) Current() *rules.Set`
  - CLI:
    - `xdr controller run --dir D --config C`: prints each controller incident as a JSON line to stdout via `OnWrite`, and exits on SIGINT/SIGTERM;
    - `xdr rules list --dir D [--endpoint ADDR]`: prints `id kind match from seen`;
    - `xdr rules revoke --dir D [--endpoint ADDR] ID`;
    - `--endpoint` defaults to the `listen` in `D/controller.json`, and both use `root.pem`.

- [ ] **Step 1: Write the failing tests** (a real embedded etcd in a temp dir, one per test; inject a clock for the 15 s timers)
  - `TestPromote_Valid`:
    - web01 proposes a remote rule;
    - within 2 s `/xdr/rules` opens with `rules.pub` to version 1 containing it;
    - the proposal key is gone;
    - a `rule-promoted` line is in the log.
  - `TestPromote_Rejected`: a baseline-hash proposal → no new version, a `rule-rejected` line with "baseline hash", and the key deleted.
  - `TestPromote_Duplicate`: the same rule proposed by db01 → no new version.
  - `TestPromote_FromSpoof`: web01 writes a proposal claiming `From: "db01"` → the promoted rule has `From: "web01"`.
  - `TestPromote_HostCap`: with the cap lowered to 3 through a test field, the 4th distinct proposal is rejected with "host limit".
  - `TestPromote_VersionSurvivesRestart`: promote two rules, close everything, start again on the same dir, promote one more → version 3.
  - `TestRevoke`: version+1, the rule is gone, the others are kept; an unknown id → error.
  - `TestIncidents_Ingested`: web01 puts an incident with `Host: "evil"` → the log line has `host: web01`, and the key is deleted.
  - `TestHeartbeat_SilentAndBack`:
    - web01 grants a 2 s lease (test TTL) and heartbeats, then revokes the lease → `agent-silent`;
    - it heartbeats again → `agent-back`;
    - an enrolled db01 that never beats → `agent-silent` after the start window.
- [ ] **Step 2: Run** `go test ./internal/controller/`. Expected: FAIL.
- [ ] **Step 3: Implement.** All rule-set writes go through one goroutine, so versions are strictly sequential. Use a `Txn` comparing `ModRevision` of `RulesKey`, so a second controller started by mistake cannot interleave.
- [ ] **Step 4: Run** `go test -race ./internal/controller/ ./internal/cli/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: controller promotes, signs and publishes rules; ingests incidents; watches heartbeats`

### Task 7: Agent config for the fleet

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`, `deploy/agent.example.json`

**Interfaces:**
- Produces:
  - `Config.Fleet *Fleet`, JSON `fleet`, where `type Fleet struct { Endpoints []string; Dir string }`:
    - JSON `endpoints` and `dir`;
    - dir default `/etc/xdr/fleet`, holding `ca.pem`, `host.pem`, `host-key.pem` and `rules.pub`.
  - `Config.RulesCache string`, JSON `rules_cache`, default `/var/lib/xdr/rules.json`.
  - `func (c *Config) Protected() []netip.Prefix`: jump, peers, ssh_from, allow_out targets, the resolver as /32 or /128, and dhcp_server.
  - `Validate` errors:
    - "fleet.endpoints: <e> is not in jump" when an endpoint's address is not in `jump`;
    - "fleet.endpoints: port <p> is not in xdr_ports" when its port is not in `xdr_ports`;
    - "fleet.endpoints: empty" when the list is empty.
  - A nil `fleet` is valid: a standalone agent, as today.
  - `reload` refuses a change to `fleet`, as it does for jump.

- [ ] **Step 1: Write the failing tests**
  - `TestValidate` gains three cases, one per error string.
  - `TestProtected` lists every source field.
  - `TestReload_FleetChangeRefused` goes in `internal/agent`.
- [ ] **Step 2: Run** `go test ./internal/config/ ./internal/agent/ -run 'Validate|Protected|Reload'`. Expected: FAIL.
- [ ] **Step 3: Implement.** The example config gets a fleet block with endpoint `192.0.2.7:2379`, and 2379 is added to its `xdr_ports`.
- [ ] **Step 4: Run** the same command. Expected: PASS.
- [ ] **Step 5: Commit** `feat: fleet section in the agent config`

### Task 8: Agent fleet client

**Files:**
- Create: `internal/fleet/client.go`, `internal/fleet/client_test.go`

**Interfaces:**
- Consumes: Task 1 (`Open`, `Unmarshal`, `Marshal`), Task 5 keys, Task 7 `config.Fleet`.
- Produces:
  - `type Client struct { … }`
  - `func New(host string, f config.Fleet, cachePath string, pub ed25519.PublicKey) *Client`
  - `func (c *Client) Cached() (*rules.Set, error)`: reads and verifies the cache file. If the file is missing it returns `nil, nil`.
  - `func (c *Client) Run(ctx context.Context, onRules func(*rules.Set), onIncident func(incident.Incident))`:
    - dials with a 5 s timeout and retries with backoff from 1 s, doubling, capped at 30 s;
    - watches `RulesKey` from a fresh Get;
    - each verified set with a higher version is written atomically to the cache (temp file, fsync, rename, mode 0600), then passed to `onRules`;
    - a forged, undecodable or older set produces a `rules-refused` incident (alert, Critical) through `onIncident` and is otherwise ignored;
    - it keeps a lease of 10 s and refreshes `Heartbeat(host)` every 3 s with `{"time":…,"version":…}`;
    - after 10 s without a connection it calls `onIncident` once with `fleet` (alert, High, "etcd unreachable: …"), and once on reconnect with "reconnected".
  - `func (c *Client) Propose(rs []rules.Rule)` and `func (c *Client) Report(in incident.Incident)`:
    - both are non-blocking, with a queue of 256 that drops the oldest;
    - a sent item is put under the host's prefix;
    - items wait in the queue while disconnected.
  - `fleet` and `rules-refused` incidents are reported like any other. A failed send never creates a new incident, so reporting cannot loop.

- [ ] **Step 1: Write the failing tests** (an embedded etcd from Task 5 with real enrolment)
  - `TestClient_ReceivesAndCaches`:
    - the controller publishes version 1 → `onRules` is called within 1 s;
    - the cache file opens to the same set;
    - a new `Client.Cached()` returns it.
  - `TestClient_RefusesOlderAndForged`:
    - after v2, a root put of a validly signed v1 → `rules-refused`;
    - a put signed by another key → `rules-refused`;
    - `onRules` is not called again and the cache still holds v2.
  - `TestClient_HeartbeatPresent`: `Heartbeat("web01")` exists while running and is gone ≤ 12 s after cancel. Use the test TTL hook to keep this short.
  - `TestClient_ProposeAndReport`: the keys appear under web01's prefixes.
  - `TestClient_UnreachableDoesNotBlock`:
    - with endpoint `127.0.0.1:1`, `Propose` and `Report` return within 1 ms each, 1000 times;
    - one `fleet` incident after 10 s, using the test clock hook.
- [ ] **Step 2: Run** `go test ./internal/fleet/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -race ./internal/fleet/`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: agent fleet client: verified rule watch with cache, proposals, incidents, heartbeat`

### Task 9: Wire the fleet into the agent

**Files:**
- Modify: `internal/agent/agent.go`, `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: Task 2 (`FromIncident`, `Guard`), Task 4 (`Policy.Rules`), Task 7 (`Fleet`, `Protected`, `RulesCache`), Task 8 (`Client`).
- Produces:
  - `type fleet interface { Cached() (*rules.Set, error); Run(ctx, func(*rules.Set), func(incident.Incident)); Propose([]rules.Rule); Report(incident.Incident) }`
  - agent field `fleet fleet` (nil when the config has no fleet); `Options.Fleet` is unused (keep construction internal).
  - `func (a *agent) setRules(s *rules.Set)`:
    - under `a.mu`, every rule passes `rules.Guard{Baseline: BaselineHashes(base), GuardExes: cfg.GuardExes, Protect: cfg.Protected()}.Validate`;
    - refused rules give one `rules-refused` incident each (alert, High, the reason) and are dropped;
    - the rest become `a.pol.Rules`.
  - `record`: after `log.Add`, if fleet is set, `Report(in)`. Nothing else changes in `record`.
  - `handle`: after recording each incident, it calls `Propose(rules.FromIncident(in, a.pol.Baseline(p)))`. `p` is the proc the incident describes; with no proc, `baselineExe` is false.
  - In `Run`:
    - with a fleet config, load `rules.pub`, build the client, call `setRules(Cached())` before the first sweep, and start `go client.Run(ctx, a.setRules, a.recordLocked)`;
    - `recordLocked` takes `a.mu` and calls `record`.

- [ ] **Step 1: Write the failing tests** (a fake fleet in the existing rig)
  - `TestHandle_KillProposes`:
    - a revshell kill with sha and remote → two `Propose` calls;
    - a baseline exe → only the remote;
    - a listener alert → none.
  - `TestSetRules_RefusesProtected`:
    - a set containing a remote in `jump` and a baseline hash → two `rules-refused` incidents;
    - `pol.Rules` holds only the valid rule.
  - `TestRun_CachedRulesBeforeEtcd`:
    - the fake's `Cached` returns a set with the hash of a fixture proc, and the fake's `Run` blocks forever;
    - the first sweep kills it (`would-kill` with `kill: false`).
  - `TestRecord_Reports`: every logged incident goes to `Report`.
- [ ] **Step 2: Run** `go test ./internal/agent/`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test -count=1 -race ./...` and `make test-root`. Expected: PASS.
- [ ] **Step 5: Commit** `feat: agents propose rules from kills and enforce the signed fleet set`

### Task 10: Fleet on the 24.04 VM

**Files:**
- Create: `test/vm/e2e-fleet.sh`, `test/vm/beacon/main.go` (a `package main` the script builds with `CGO_ENABLED=0 go build`; `go vet ./...` covers it)
- Modify: `Makefile` (`e2e-fleet` target, `.PHONY`), the spec §4/§7.1 (builder's-call bullets for this plan), the roadmap (row 3 split into 3a/3b)

**Interfaces:**
- Consumes: everything above; the helpers of `test/vm/e2e-net.sh`, copied or sourced from a shared `test/vm/lib.sh` if the copy grows past ~40 lines.
- Produces:
  - `beacon HOST:PORT` dials and holds the connection; `beacon idle` only sleeps. It is a non-baseline binary by construction.
  - The controller runs on the dev host, bound to the LXD bridge address. The VM agent's `jump` is that address, and `xdr_ports` includes 2379.

- [ ] **Step 1: Write the script.** Its cases, each `ok <name>` or `FAIL <name>: <why>`:
  - `enrolled`: the agent starts, and the controller's stdout shows no `agent-silent` for the VM 20 s after the controller started.
  - `beacon-killed`: `beacon HOST:4444` is killed for egress, and within 3 s the controller prints `rule-promoted` twice, once for the hash and once for the remote.
  - `rule-hash-kills`: a copy of the beacon at another path, run as `idle`, is killed and the incident has kind `rule-hash`.
  - `baseline-not-promoted`: `python3 -c` dialling HOST:4444 is killed for egress; the controller rejects its hash ("baseline hash") or the agent never proposes it, and the remote rule is a duplicate.
  - `controller-down-cached`: stop the controller and restart the agent; `beacon idle` is still killed by `rule-hash`.
  - `agent-silent`: start the controller again, then stop the agent → the controller prints `agent-silent` for the VM within 20 s.
  - `revoke`: `xdr rules revoke` the hash rule, then `beacon idle` lives for 3 s.
- [ ] **Step 2: Run** `sg lxd -c "make e2e-fleet"` in the background. Expected: every case `ok`, then `E2E-FLEET PASS`, exit 0. Also rerun `sg lxd -c "make e2e-net"`. Expected: `E2E-NET PASS`, since an agent without a fleet section is unchanged.
- [ ] **Step 3: Update the spec and roadmap** as listed under Files.
- [ ] **Step 4: Commit** `test: fleet rules end to end on the 24.04 VM`
