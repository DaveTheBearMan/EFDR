# XDR Plan 4: SSH Gate, Accounts, Break-glass Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every SSH session to a target box is pending until approved and is terminated after a grace window if it isn't, and this holds with the jump box, etcd or the agent down. Gray-team and recovery accounts stay reachable. New accounts are disabled. Break-glass tokens minted in advance are the way back in. T-0 credential and key rotation sends agents hashes only.

**Architecture:**
- **Agent:** owns sshd and PAM. It renders sshd_config and `/etc/pam.d/sshd` from signed config plus the baseline's copies, and re-asserts them on drift. It judges logind sessions each sweep, and terminates or alerts on them.
- **Gate:** `xdr gate` is the `pam_exec` hook. It registers a session with the agent over a unix socket. If the agent is unreachable it refuses the session (fail-closed), unless a valid pause token is spooled.
- **Controller:** orders reach a host under a new per-host etcd prefix: session verdicts, user approvals and credential sets (hashes only). Break-glass tokens and the agent config are ed25519-signed by the jump box's rule key, each under its own purpose string.

**Tech Stack:** Go 1.27, CGO_ENABLED=0, etcd v3.7.3 clientv3, ed25519, `golang.org/x/crypto/md4` (NT hash for Samba), logind session files under `/run/systemd/sessions`, `loginctl`, `sshd -t`/`-T`, `systemctl`, `usermod`, `chpasswd -e`, `pdbedit`, `ssh-keygen`.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md`: §7.3 SSH gate, §7.4 (new users, sessions), §8 SSH hardening and password rotation, §10 break-glass, §6.2 Samba (passdb rotation), §3a gray-team accounts.

## Global Constraints

- One static binary, `CGO_ENABLED=0`; no new runtime dependency on the box beyond stock Ubuntu 24.04 tools named above.
- Gray team accounts (config `gray_users`; packet: `grayteam`, `othergrayteam`, `violetgray`) are never touched: "No credential or key rotation, no disable, no session kill, no home-directory cleanup. Activity on them is alert-only". "T-0 tooling refuses to act on a protected account even if asked." A reverse shell from a gray session is still killed (existing detections, unchanged).
- Never take a scored service offline by our own action: no account disable, password change or session kill may stop a scored-service process (`guard_exes`, or a listener on a scored port).
- Recovery account: "accepted only from the jump box/operator IPs", "key-only, with the key held off-box", "excluded from the 'new user' and 'non-baseline session' rules", "alerted on every login", enforced at sshd (`Match`) and nftables as well as the agent.
- "The gate reads the protected-account list from signed config, not from `/etc/passwd`"; "a protected name with a changed UID or a UID of 0 is a critical alert".
- Break-glass: tokens "minted in advance on the jump box, each scoped to one host and one action (approve-session or pause), short-lived (e.g. 2h)"; "the signing key never leaves the jump box". Must work with "jump box down, etcd down, agent dead, and the gate closed on the operator's own session".
- Rotation: "the controller generates each new password on the jump box and sends the agent only its hash (`chpasswd -e`)"; "cleartext lives in the controller's local store on the jump box, never in etcd". Samba passwords go as NT hashes (`pdbedit --set-nt-hash`), so no cleartext leaves the jump box (spec §6.2 note, builder's call recorded here).
- SSH: "keys-only, password auth disabled, for the ten blue-team accounts and root"; "`AllowUsers` pins blue-team and recovery accounts to the jump box address and leaves gray accounts reachable from the gray subnet"; gray accounts keep "the authentication methods sshd offered them at T-0 (a `Match User` block preserves those while the global default tightens)".
- Nothing from the packet in code or tests: test names `alice`/`bob` (blue), `gray1` (gray), `xdrrecover` (recovery), `xdrops` (platform), addresses from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24. No packet password anywhere.

## Review Focus

1. **The operator's own session is pending and the gate is closing on it.** Expected: `xdr breakglass <approve-token>` run in that session within the grace approves that session, with no `--session` flag. → Task 7 `TestBreakglass_ApprovesCallersSession`.
2. **The agent is stopped or dead.** Expected: blue logins are refused at PAM (fail-closed); recovery and gray logins still open, because the PAM skip line comes before `pam_exec`. A spooled pause token for this host lets blue logins through. → Task 6 `TestGate_FailClosed`, `TestGate_PauseTokenWhenAgentDown`; Task 3 `TestRenderPAM_ExemptSkipsGate`; Task 12 e2e `agent-dead`.
3. **A rendered sshd_config that sshd rejects, or one that would lock the jump box out.** Expected: `sshd -t` fails, so the file on disk is put back, there is no reload, and a Critical alert fires. Render never produces a config without `root@<jump>` and the recovery account in `AllowUsers`. → Task 4 `TestAssert_SSHDRejectedRestores`, Task 3 `TestRenderSSHD_KeepsWayIn`.
4. **A "new" account that is a package or system user, or that runs a scored service** (mysql, postfix, a Samba service account). Expected: an alert only, never disabled. Only accounts with a login shell and a UID ≥ 1000 that run nothing guarded are locked. → Task 9 `TestUsers_SystemAndServiceAccountsNotDisabled`.
5. **A hostile or stale token:** another host's, expired, not yet valid, signed by another key, tampered, an approve token reused for a second session, or a 1 MiB file in the spool. Expected: refused with a reason, nothing approved or paused, spool reads bounded. → Task 7 `TestToken_Refusals`, `TestBreakglass_ApproveOnce`, Task 6 `TestSpool_Bounded`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/sign/sign.go` | purpose-scoped ed25519 sign/verify of byte strings |
| `internal/config/config.go`, `config/sign.go` | `ssh` section; signed config (`agent.json.sig`) |
| `internal/sshgate/render.go` | pure rendering of sshd_config and pam.d/sshd |
| `internal/sshgate/assert.go` | write, `sshd -t`, reload, restore; drop-in quarantine; T-0 gray capture |
| `internal/sshgate/sessions.go` | read logind session files; terminate |
| `internal/sshgate/judge.go` | pure verdict per session |
| `internal/sshgate/gate.go` | the `pam_exec` hook client; the agent-side socket server |
| `internal/breakglass/token.go` | token format, mint, verify; spool read/write |
| `internal/fleet/keys.go`, `fleet/client.go` | `To(host)` orders prefix; `Order` callback |
| `internal/controller/etcd.go`, `controller/orders.go` | RBAC read on `To(h)`; put session/user verdicts and credential sets |
| `internal/creds/` | sha512-crypt, NT hash, password generation, the jump box's local store |
| `internal/agent/gate.go`, `agent/users.go`, `agent/creds.go` | agent wiring: sessions, accounts, rotation |
| `internal/cli/` | `gate`, `breakglass`, `controller sign-config|approve-session|kill-session|approve-user|mint-breakglass|rotate|creds` |
| `test/vm/e2e-gate.sh`, `Makefile` | one-VM end-to-end gate test |

---

### Task 1: Purpose-scoped signing and signed agent config

**Files:**
- Create: `internal/sign/sign.go`, `internal/sign/sign_test.go`, `internal/config/sign.go`, `internal/config/sign_test.go`
- Modify: `internal/config/config.go` (the `SSH` section and its validation), `internal/cli/controller.go` (`sign-config`), `internal/cli/agent.go` (load verifies)

**Interfaces:**
- Produces: `sign.Sign(purpose string, msg []byte, key ed25519.PrivateKey) []byte`; `sign.Verify(purpose string, msg, sig []byte, pub ed25519.PublicKey) bool`. The signed bytes are `"xdr/" + purpose + "\x00" + msg`. Purposes are `"config"` and `"breakglass"`; the rule set keeps its own format.
- Produces: `config.SSH{Blue []string "blue_users"; Recovery string "recovery"; RecoveryKey string "recovery_key"; Auto []string "auto"; Grace Duration "grace"}` and `Config.SSH *SSH "ssh"`. `nil` means no gate. `Grace` defaults to 90s.
- Produces: `config.LoadSigned(path string, pub ed25519.PublicKey) (*Config, error)`. It reads `path` and `path+".sig"` (raw 64-byte signature, base64 text) and refuses a missing or bad signature with `config: unsigned or tampered (path.sig)`.
- Produces: `xdr controller sign-config --dir D CONFIG` writes `CONFIG.sig` with `rules.key`.

- [ ] **Step 1: Failing tests**
  - `TestSign_PurposeScoped`: a signature for `"config"` does not verify as `"breakglass"`, for a flipped message byte, or for another key.
  - `TestValidate_SSH`, table of config → error substring:
    - recovery set without `recovery_key` → `ssh.recovery_key`;
    - a name in both `blue_users` and `gray_users` → `ssh: gray1 is both`;
    - recovery or auto in `gray_users` → `ssh: gray1 is both`;
    - empty `jump` with `ssh` set → `ssh: needs jump`;
    - `grace` < 10s → `ssh.grace`;
    - a user name failing `^[a-z_][a-z0-9_-]{0,31}$` → `ssh: bad user`.
  - `TestLoadSigned`: a signed file loads; one changed byte, a missing `.sig`, or a `.sig` from another key all give the error above; an agent whose config has `fleet` set and no valid `.sig` does not start (`cli` test via `agentCmd` returning the error).
- [ ] **Step 2: Run** `go test ./internal/sign ./internal/config ./internal/cli`. Expected: FAIL (undefined).
- [ ] **Step 3: Implement**
  - The agent loads with `LoadSigned` when the unsigned parse shows `fleet` set; `rules.pub` comes from `fleet.dir`.
  - A standalone agent (no fleet) loads unsigned as today.
  - SIGHUP reload uses the same path.
- [ ] **Step 4: Run** the same tests. Expected: PASS.
- [ ] **Step 5: Commit** `feat: signed agent config and the ssh section`.

### Task 2: Logind sessions

**Files:** Create `internal/sshgate/sessions.go`, `internal/sshgate/sessions_test.go`

**Interfaces:**
- Produces: `type Session struct{ ID, User, Service, Class, State, RemoteHost, Scope string; UID uint32; Leader int; RemoteAddr netip.Addr }`.
- Produces: `Sessions(root string) ([]Session, error)`, which reads `root/run/systemd/sessions/*` (key=value: `USER`, `UID`, `SERVICE`, `CLASS`, `STATE`, `REMOTE_HOST`, `LEADER`, `SCOPE`). `RemoteAddr` is parsed from `REMOTE_HOST` when it is an address. Each file is read with `collect.ReadFile` ≤ 64 KiB; names that are not decimal are skipped (`*.ref` and the rest).
- Produces: `type Runner func(name string, args ...string) error` and `Terminate(run Runner, id string) error`, which runs `loginctl terminate-session ID`.

- [ ] **Step 1: Failing tests**
  - `TestSessions_Parse`: three files: an sshd user session with `REMOTE_HOST=192.0.2.7`, a `tty` session, and a `.ref` file. Expect two sessions with the fields above; the bad file is skipped without error.
  - `TestTerminate_RunsLoginctl`: a recording runner sees `loginctl terminate-session 7`.
- [ ] **Step 2: Run** `go test ./internal/sshgate`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(sshgate): read and end logind sessions`.

### Task 3: Rendering sshd_config and pam.d/sshd

**Files:** Create `internal/sshgate/render.go`, `internal/sshgate/render_test.go`

**Interfaces:**
- Consumes: `config.SSH`, `cfg.Jump`, `cfg.GrayUsers`, `cfg.SSHFrom`.
- Produces: `type T0 struct{ Password, KbdInteractive, Pubkey, Methods string }`: the gray accounts' auth settings as `sshd -T` printed them at T-0.
- Produces: `RenderSSHD(base []byte, cfg *config.Config, t0 T0) []byte`, built as `header + base + trailer`, in that order:
  - `header`:
    - `PasswordAuthentication no`
    - `KbdInteractiveAuthentication no`
    - `PermitRootLogin prohibit-password`
    - `PubkeyAuthentication yes`
    - `UsePAM yes`
    - one `AllowUsers` line: `<u>@<jump>` for every blue, `root`, recovery and auto user and each jump net; bare `<gray>` for each gray user.

    First-obtained-wins makes the header override `base` and any drop-in.
  - `base`: the baseline copy, unchanged, with its `Include` line.
  - `trailer`:
    - `Match User <gray,...>` restoring `t0` (`PasswordAuthentication`, `KbdInteractiveAuthentication`, `PubkeyAuthentication`, and `AuthenticationMethods` when not `any`);
    - `Match User <recovery>` with `AuthenticationMethods publickey`.

  The trailer starts with a `Match all` line, so base content can't capture it.
- Produces: `RenderPAM(base []byte, cfg *config.Config, gateExe string) []byte`, the baseline `/etc/pam.d/sshd` with these lines inserted right after its `@include common-session` line:
  ```
  session [success=1 default=ignore] pam_succeed_if.so quiet user in <gray...:recovery>
  session required pam_exec.so quiet <gateExe> gate
  ```
  The `in` list is gray plus recovery (not auto: auto sessions go through the gate and the agent approves them). It returns an error if base has no `@include common-session`.

- [ ] **Step 1: Failing tests**
  - `TestRenderSSHD_Order`: header lines come before base; the trailer's `Match` lines are after base; `AllowUsers` holds `alice@192.0.2.7`, `root@192.0.2.7`, `xdrrecover@192.0.2.7` and bare `gray1`.
  - `TestRenderSSHD_KeepsWayIn`: for every valid config in a small table, output contains `root@` + each jump net and the recovery user.
  - `TestRenderSSHD_GrayKeepsT0`: `t0.Password = "yes"` gives `PasswordAuthentication yes` inside the gray `Match` only.
  - `TestRenderPAM_ExemptSkipsGate`: the skip line comes directly before the `pam_exec` line, after `@include common-session`; its user list is exactly `gray1:xdrrecover`; base without the include gives an error.
- [ ] **Step 2: Run** `go test ./internal/sshgate -run Render`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(sshgate): render sshd and PAM config from signed config`.

### Task 4: Re-asserting sshd and PAM, with drop-in quarantine and the T-0 capture

**Files:** Create `internal/sshgate/assert.go`, `internal/sshgate/assert_test.go`; Modify `internal/agent/agent.go` (guard tick calls it)

**Interfaces:**
- Consumes: `RenderSSHD`, `RenderPAM`, `Runner`, `baseline.Baseline.Files[pathenc.Encode(p)].Content`.
- Produces: `type Asserter struct{ Root, State string; Run Runner; Output func(name string, args ...string) ([]byte, error) }`.
- Produces: `(a *Asserter) Assert(cfg *config.Config, base *baseline.Baseline, gateExe string) (changed []string, err error)`:
  - It writes `etc/ssh/sshd_config` and `etc/pam.d/sshd` when they differ from the render, using temp file plus rename, mode 0644 root.
  - It moves every file in `etc/ssh/sshd_config.d/` not in the baseline into `State/quarantine/<unix-nanos>-<name>`.
  - It runs `sshd -t`. On failure it puts the previous contents back and returns an error naming `sshd -t`. On success, if anything changed, it runs `systemctl try-reload-or-restart ssh.service`.
- Produces: `(a *Asserter) T0(cfg *config.Config) (T0, error)`. On first call it runs `sshd -T -C user=<first gray>,host=x,addr=<first ssh_from address>` and keeps `passwordauthentication`, `kbdinteractiveauthentication`, `pubkeyauthentication` and `authenticationmethods` in `State/sshd-t0.json`. Later calls read that file. With no gray users it returns sshd's defaults.
- Agent:
  - The guard tick calls `Assert` when `cfg.SSH != nil`.
  - Each changed path is an `ssh-drift` High incident (`Detail`: path, and "restored").
  - An error is `ssh-config` Critical.
  - A baseline missing either file gives one `ssh-config` Critical "gate off: baseline has no …", and the gate stays off (no PAM edit).

- [ ] **Step 1: Failing tests** (root dir under `testfs.Root`, fake `Run`/`Output`):
  - `TestAssert_WritesAndReloads`: the first call writes both files and reloads once; a second call changes nothing and doesn't reload.
  - `TestAssert_SSHDRejectedRestores`: an `Output`/`Run` that fails for `sshd -t` leaves both files byte-identical to before, makes no reload, and returns an error naming `sshd -t`.
  - `TestAssert_QuarantinesDropIn`: `sshd_config.d/00-evil.conf` (not in baseline) moves to quarantine; `60-cloudimg-settings.conf` (in baseline) stays.
  - `TestT0_CapturedOnce`: `Output` is called once across two `T0` calls; the values come from its `-T` text.
  - `TestAgent_GateOffWithoutBaselinePAM` in `internal/agent`: one Critical and no PAM write.
- [ ] **Step 2: Run** `go test ./internal/sshgate ./internal/agent -run 'Assert|T0|GateOff'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(sshgate): keep sshd and PAM at their signed render`.

### Task 5: Judging sessions

**Files:** Create `internal/sshgate/judge.go`, `internal/sshgate/judge_test.go`, `internal/agent/gate.go`, `internal/agent/gate_test.go`

**Interfaces:**
- Produces: `type Verdict int` with `Keep, Alert, Pending, Terminate`. Also `type Policy struct{ Cfg *config.Config; BaseUsers map[string]uint32; Approved map[string]bool; Killed map[string]bool; Paused bool; Now time.Time }`.
- Produces: `Judge(s Session, first time.Time, p Policy) (Verdict, string)`. `first` is when the agent first saw the session. The string is a reason. Rules, first match wins (only `Service == "sshd"` sessions are judged; others give `Keep`):
  1. gray user → `Alert` (once per session: "gray login from ADDR")
  2. recovery user → `Alert` ("recovery login from ADDR", High)
  3. `Killed[id]` → `Terminate`
  4. auto user from a jump address → `Keep`
  5. user not in `BaseUsers` and not recovery/auto → `Terminate` ("user not in baseline"), or `Alert` if paused
  6. `Approved[id]` → `Keep`
  7. `Paused` → `Keep` ("paused")
  8. `Now - first < grace` → `Pending`
  9. otherwise → `Terminate` ("not approved within GRACE")
- Agent: `(a *agent) sessions()` runs each sweep when the gate is on.
  - It keeps `first` per session id and acts on verdicts. `Pending` gives one `session-pending` Medium incident with id, user and remote. `Terminate` calls `Terminate`, falling back to `respond.KillTree` on the leader, and records `session-terminated` High. `Alert` records once per session.
  - It forgets ids no longer listed.
  - A gray name whose UID differs from the baseline's, or is 0, gives `account-uid` Critical once per sweep set (this check runs here because it reads the same baseline).

- [ ] **Step 1: Failing tests**
  - `TestJudge_Table`: one row per rule above, plus:
    - a gray user whose session is also `Killed` → `Alert` (gray is never terminated);
    - auto user from a non-jump address → `Pending`;
    - a `tty` session → `Keep`.
  - `TestAgentSessions_TerminateAfterGrace`: fake clock and session files. A pending incident at t0, no terminate at t0+grace−1s, `loginctl terminate-session` at t0+grace, one `session-terminated` incident.
  - `TestAgentSessions_GrayUIDChanged`: baseline `gray1` uid 2001, passwd shows 0 → one `account-uid` Critical.
- [ ] **Step 2: Run** `go test ./internal/sshgate ./internal/agent -run 'Judge|AgentSessions'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: judge SSH sessions and end unapproved ones after the grace`.

### Task 6: The pam_exec gate and its socket

**Files:** Create `internal/sshgate/gate.go`, `internal/sshgate/gate_test.go`, `internal/breakglass/spool.go`, `internal/breakglass/spool_test.go`; Modify `internal/cli/cli.go` (`gate` subcommand), `internal/agent/gate.go` (serve)

**Interfaces:**
- Produces: `const Socket = "/run/xdr/gate.sock"` (dir 0755, socket 0666: messages are either harmless lookups or signed tokens).
- Produces: `type Msg struct{ Session, User, RHost, Token string; PPID int }` (JSON, one line, ≤ 8 KiB) and `type Reply struct{ OK bool; Why string }`.
- Produces: `Serve(ctx context.Context, l net.Listener, handle func(Msg) Reply)`. One goroutine per connection, 2 s deadline, 64 concurrent max.
- Produces: `Check(env map[string]string, sock string, paused func() bool) error`, the body of `xdr gate`:
  - It returns nil for a non-`open_session` `PAM_TYPE`.
  - It sends `Msg{Session: XDG_SESSION_ID, User: PAM_USER, RHost: PAM_RHOST, PPID: getppid}` and returns nil on `OK`.
  - If the agent is unreachable, it returns nil only when `paused()` is true (Task 7 supplies it: a valid pause token for this host in the spool), otherwise `gate: agent unreachable`.
  - An agent reply `OK:false` is an error.
- Produces: `xdr gate` reads env from `os.Environ()`; until Task 7 its `paused` is `func() bool { return false }`. It exits 1 with the message on stderr when `Check` errs.
- Agent: listens on `Socket` at start when the gate is on. The handler looks the session up (by id, else by the PPID's cgroup `session-N.scope`), marks `first` now, and replies OK. Token messages are Task 7's.
- Produces: `internal/breakglass/spool.go`: `Spool = "/var/lib/xdr/breakglass"` (mode 01733) and `ReadSpool(dir string) []string`, the contents of at most the 64 newest files, each ≤ 4 KiB; larger ones are skipped.

- [ ] **Step 1: Failing tests**
  - `TestGate_RegistersSession`: a test server receives `Session:"7", User:"alice"` and `Check` returns nil.
  - `TestGate_FailClosed`: no socket and an empty spool → `gate: agent unreachable`.
  - `TestGate_PauseTokenWhenAgentDown`: no socket and `paused` true → nil; `paused` false → error.
  - `TestGate_IgnoresCloseSession`: `PAM_TYPE=close_session` → nil with no socket.
  - `TestSpool_Bounded`: 70 files plus one 1 MiB file → at most 64 read, the large one skipped.
- [ ] **Step 2: Run** `go test ./internal/sshgate ./internal/breakglass -run 'Gate|Spool'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: pam_exec gate, fail-closed without the agent`.

### Task 7: Break-glass tokens

**Files:** Create `internal/breakglass/token.go`, `internal/breakglass/token_test.go`; Modify `internal/cli/` (`breakglass`, `controller mint-breakglass`), `internal/agent/gate.go`

**Interfaces:**
- Consumes: `sign.Sign/Verify` purpose `"breakglass"`.
- Produces: `type Token struct{ V int; ID, Host, Action string; NotBefore, Expires time.Time }`, where `Action` is `"approve-session"` or `"pause"`.
  - Wire form: `base64url(json) + "." + base64url(sig)`, one line.
  - `Mint(t Token, key) string`.
  - `Parse(s string, pub) (Token, error)`.
  - `(t Token) Valid(host string, now time.Time) error`, allowing 5 min clock skew either side. Errors name the reason: `another host`, `expired`, `not yet valid`, `bad signature`, `malformed`.
- Produces: `xdr controller mint-breakglass --dir D --hosts a,b --action pause|approve-session --from RFC3339 --every 2h --count N --out DIR`, which writes one file per host per window, `<host>-<action>-<from>.tok`. The ID is 16 random hex characters.
- Produces: `xdr breakglass TOKEN|-` with `[--session ID]`:
  - It sends `Msg{Token, Session}` to the agent socket. `Session` defaults to the caller's own: `XDG_SESSION_ID`, else the `session-N.scope` in `/proc/self/cgroup`.
  - It always also writes the token to `Spool` as `<id>.tok`, so a dead agent and the gate still see it.
  - It prints the agent's reply, or "agent down: token spooled".
- `xdr gate`'s `paused` becomes: some `ReadSpool(Spool)` entry parses with the config's `rules.pub` and is a `pause` token `Valid` for this host now.
- Agent:
  - A valid `approve-session` token approves exactly one session. Used IDs are kept in `State/breakglass-used.json`, and a reused ID is refused with `used`.
  - A valid `pause` token sets paused until its `Expires`. While paused, the gate keeps sessions (Task 5 rule 7) and `Decide` kills become `would-kill` (the effective `Kill` is false).
  - The agent scans `Spool` each sweep, so tokens spooled while it was down take effect.
  - Every token use is a `breakglass` High incident: action, host, ID, session.

- [ ] **Step 1: Failing tests**
  - `TestToken_RoundTrip`.
  - `TestToken_Refusals`: another host, expired by 6 min, not before +6 min, another key, one flipped payload byte, a `.`-less string; each gives its named error.
  - `TestToken_Skew`: expired 4 min ago → still valid.
  - `TestBreakglass_ApprovesCallersSession`: with `XDG_SESSION_ID=9` set and no `--session`, the agent marks 9 approved and the Task 5 judge keeps it past the grace.
  - `TestBreakglass_ApproveOnce`: the same token for session 10 after 9 → `used`, and 10 is not approved.
  - `TestBreakglass_PauseStopsKills`: while paused, a reverse-shell detection gives `would-kill`; after `Expires`, `killed`.
  - `TestMint_Windows`: `--count 3 --every 2h` gives three tokens per host with consecutive windows.
  - `TestGate_SpooledPauseToken`: the real `paused` is true for this host's valid pause token in a temp spool, and false for another host's token or an approve token.
- [ ] **Step 2: Run** `go test ./internal/breakglass ./internal/agent ./internal/cli -run 'Token|Breakglass|Mint'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: pre-minted break-glass tokens`.

### Task 8: Controller orders: session verdicts and user approvals

**Files:**
- Create: `internal/controller/orders.go`, `internal/controller/orders_test.go`
- Modify:
  - `internal/fleet/keys.go`, `internal/fleet/client.go`
  - `internal/controller/etcd.go` (host read on `To(h)`)
  - `internal/agent/agent.go` (`fleetLink.Run` signature, fake)
  - `internal/cli/controller.go`

**Interfaces:**
- Produces:
  - `fleet.ToAll = "/xdr/to/"` and `fleet.To(host) = ToAll + host + "/"`.
  - Keys: `To(h)+"session/"+id` with value `{"verdict":"approve"|"kill"}`; `To(h)+"user/"+name` with `{"verdict":"approve"}`; `To(h)+"creds"` (Task 10).
- Produces: `type Order struct{ Kind, Name string; Value []byte; Deleted bool }`. `Client.Run(ctx, onRules, onIncident, onHunt, onOrder func(Order))`. The session watches `To(host)`, replays current keys on (re)connect, and drops values > 64 KiB.
- Produces: `controller.PutOrder(ctx, c *clientv3.Client, host, kind, name string, v any) error`. CLI commands:
  - `xdr controller approve-session|kill-session --dir D --host H ID`
  - `xdr controller approve-user --dir D --host H NAME`

  Each refuses a host that isn't enrolled. `approve-user` and `kill-session` refuse a gray name, read from the controller config's `gray_users`: `refused: gray1 is a protected account`.
- RBAC: host role gets read on `To(h)` prefix, even when disabled (it must still obey).
- Agent: `onOrder` feeds `Approved`/`Killed` (sessions) and the approved-users set (Task 9), and keeps both in `State/orders.json` so they survive a restart with etcd down.

- [ ] **Step 1: Failing tests**
  - `TestOrders_ReachHost` (fleettest): a put by root reaches `onOrder` with the right kind and name; another host's client never sees it and gets permission denied on reading `To(other)`.
  - `TestOrders_GrayRefused`.
  - `TestAgentOrders_ApproveKeepsSession`: approve within grace → kept past it.
  - `TestAgentOrders_KillEndsApproved`.
  - `TestAgentOrders_SurviveRestart`.
- [ ] **Step 2: Run** `go test ./internal/fleet ./internal/controller ./internal/agent -run 'Orders'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: controller orders for sessions and users`.

### Task 9: Accounts: new users disabled, recovery account kept locked down

**Files:** Create `internal/agent/users.go`, `internal/agent/users_test.go`

**Interfaces:**
- Consumes: baseline `Accounts`, `collect.ParsePasswd`, `a.pol.Guarded`, the Task 8 approved-users set, `Runner`.
- Produces: `(a *agent) accounts(s *proc.Snapshot)`, run each sweep when `cfg.SSH != nil`. For each passwd account not in the baseline, not gray, not recovery or auto, and not approved:
  - UID ≥ 1000, a shell not ending in `nologin`/`false`, and no guarded process → `usermod --lock --expiredate 1 NAME`. Its sessions go to Task 5 (rule 5 already terminates them). Record `user-disabled` High once.
  - otherwise → `user-new` Medium alert once, no action.
  - Approving later runs `usermod --unlock --expiredate '' NAME` and records `user-enabled`.
- Produces: the recovery account check, each sweep:
  - `~recovery/.ssh/authorized_keys` must hold exactly `RecoveryKey` + "\n". If not, it is rewritten (0600, owned by the account) and `recovery-drift` High is recorded.
  - A missing recovery account is `recovery-missing` Critical once.

- [ ] **Step 1: Failing tests**
  - `TestUsers_NewLoginUserDisabled`: `evil` uid 1500 `/bin/bash` → usermod lock call and one incident; the next sweep makes no second call.
  - `TestUsers_SystemAndServiceAccountsNotDisabled`: `mysql` uid 110 `/bin/false`; `svc` uid 1600 `/bin/bash` running `/usr/sbin/apache2` (guarded); gray `gray1` absent from baseline. Each gets an alert or nothing, with no usermod call.
  - `TestUsers_ApprovedReenabled`.
  - `TestRecovery_KeyReasserted`: an added second key line is removed and recorded.
  - `TestRecovery_Missing`.
- [ ] **Step 2: Run** `go test ./internal/agent -run 'Users|Recovery'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): disable new login accounts; hold the recovery key`.

### Task 10: Credentials on the jump box: hashes, store, rotate command

**Files:** Create `internal/creds/crypt.go`, `internal/creds/nt.go`, `internal/creds/store.go`, and their tests; Modify `internal/cli/controller.go`

**Interfaces:**
- Produces:
  - `creds.SHA512Crypt(password, salt string, rounds int) string`: `$6$` per the SHA-crypt spec; `rounds` 5000 omits the `rounds=` field.
  - `creds.NTHash(password string) string`: hex MD4 of UTF-16LE.
  - `creds.Password() string`: 20 characters from `[A-Za-z0-9]` via `crypto/rand`, scorer-paste-safe.
- Produces: `type Set struct{ ID string; Users map[string]User; HostKeys bool }` and `type User struct{ Hash, NT string; Keys []string }` (the etcd value at `To(h)+"creds"`, JSON). `NT` is set only for `--samba` users. `Keys` replaces `authorized_keys` when non-nil.
- Produces: `Store` at `D/creds.json` (0600), holding per host and account `{Password, Service, Rotated}`. It provides `Load`, `Put` and `Save` (temp file plus rename), and `Block() string`: one `host\tservice\taccount\tpassword` line per entry, sorted.
- Produces: `xdr controller rotate --dir D --host H --users a,b [--samba a] [--keys FILE] [--hostkeys]`:
  - It refuses gray users (`refused: gray1 is a protected account`), the recovery and auto accounts, and hosts that aren't enrolled.
  - It generates passwords and saves the store before writing the etcd `Set` (a crash leaves cleartext that may not have been applied, never a hash nobody knows).
  - It prints the new `Block` lines.
- Produces: `xdr controller creds --dir D [--host H]`, which prints `Block()`.

- [ ] **Step 1: Failing tests**
  - `TestSHA512Crypt_Vectors`: the SHA-crypt reference vectors, `"Hello world!"` with salt `saltstring` → `$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1`, and the `rounds=10000` vector.
  - `TestNTHash`: `"password"` → `8846f7eaee8fb117ad06bdd830b7586c`.
  - `TestRotate_RefusesGray`: no store write and no etcd put.
  - `TestRotate_StoreBeforePut`: an etcd failure leaves the store entry.
  - `TestRotate_SambaGetsNTOnly`: the etcd value holds `NT` for the samba user, no field holds the cleartext, and the value's bytes don't contain the password.
- [ ] **Step 2: Run** `go test ./internal/creds ./internal/cli -run 'SHA512|NTHash|Rotate'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: T-0 rotation on the jump box, hashes only to agents`.

### Task 11: Agent applies credential sets

**Files:** Create `internal/agent/creds.go`, `internal/agent/creds_test.go`

**Interfaces:**
- Consumes: Task 8's `onOrder` with `Kind:"creds"`, `creds.Set`, `Runner`.
- Produces: `(a *agent) applyCreds(s creds.Set)`, which applies a set whose `ID` differs from `State/creds-applied` and then stores the ID:
  - `chpasswd -e` with `user:hash` lines on stdin, through a new agent hook `runIn func(stdin []byte, name string, args ...string) error` (the real one is `exec.Command` with `Stdin`).
  - `pdbedit -u USER --set-nt-hash NT` for each NT user.
  - `authorized_keys` rewritten for `Keys != nil`.
  - With `HostKeys`: remove `etc/ssh/ssh_host_*`, run `ssh-keygen -A`, reload ssh, and put the new public keys' SHA256 fingerprints in the incident.
  - Gray users are refused again agent-side (`creds-refused` High), and so is an account carrying a guarded process when the set changes its password with no `--samba` (a service account's password belongs to the service: refuse, `creds-refused`).
  - One `creds-applied` Medium incident per set lists the accounts done and refused. No hash is put in any incident.

- [ ] **Step 1: Failing tests**
  - `TestApplyCreds_Chpasswd`: stdin is exactly `alice:$6$…\n`.
  - `TestApplyCreds_GrayRefusedAgentSide`.
  - `TestApplyCreds_Idempotent`: the same ID twice → one run.
  - `TestApplyCreds_SambaNT`.
  - `TestApplyCreds_HostKeys`.
  - `TestApplyCreds_NoHashInIncident`.
- [ ] **Step 2: Run** `go test ./internal/agent -run ApplyCreds`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): apply rotated credentials from the jump box`.

### Task 12: End-to-end gate test in one VM

**Files:** Create `test/vm/e2e-gate.sh`; Modify `Makefile` (`e2e-gate`), `deploy/agent.example.json` (`ssh` section), spec §14-style "Builder's calls, plan 4" list in the spec, roadmap row 4 "(done)"

**Interfaces:**
- Consumes: `test/vm/lib.sh` (`on`, launch, `VM_MEM`), and the controller run on the host as in `e2e-fleet.sh`.
- Setup:
  - VM `xdr-e2e-gate` with users `alice` (blue), `gray1` (gray) and `xdrrecover`, each with a test key from the host.
  - Config `ssh.grace` "15s", jump = the host's lxdbr0 address, signed with `controller sign-config`.
  - Tokens minted for this VM.
- Cases. Each prints `ok <name>`; the script ends `E2E-GATE PASS`.
  1. `render`: `sshd -T` on the VM shows `passwordauthentication no` and the `AllowUsers` list; `/etc/pam.d/sshd` has the gate lines.
  2. `pending-terminated`: `ssh alice@VM sleep 60` is cut within grace+5s; the controller sees `session-terminated`.
  3. `approved`: ssh alice, `xdr controller approve-session` with the id from the `session-pending` incident → still alive at grace+10s.
  4. `own-session-breakglass`: ssh alice; inside it run `xdr breakglass <approve token>` → alive at grace+10s.
  5. `gray-untouched`: `ssh gray1@VM sleep 40` survives; a `session` alert names it.
  6. `new-user-disabled`: `useradd -m -s /bin/bash evil` on the VM → within 5 s `passwd -S evil` shows `L`.
  7. `agent-dead`: stop the agent → `ssh alice` is refused; `ssh xdrrecover` works; `xdr breakglass <pause token>` from the recovery session → `ssh alice` now works.
  8. `rotate`: `xdr controller rotate --host e2e --users alice` → the VM's shadow line for alice changes to `$6$`; `xdr controller creds` prints `e2e`, `alice` and a 20-character password; `rotate --users gray1` exits non-zero.
- [ ] **Step 1: Write the script and Makefile target.**
- [ ] **Step 2: Run** `sg lxd -c "make e2e-gate"`. Expected: all 8 `ok`, `E2E-GATE PASS`.
- [ ] **Step 3: Run** `sg lxd -c "make e2e-fleet"` and `make e2e-net`. Expected: PASS (no regression).
- [ ] **Step 4: Commit** `test: SSH gate, break-glass and rotation in a VM`.

---

## Builder's calls in this plan (recorded for the spec)

- The whole agent config is signed (`agent.json.sig`, rule key, purpose `config`). The spec asks only for the protected-account list to come from signed config; signing all of it covers that and stops a root edit from widening `allow_out` or `gray_users`.
- Platform-launched sessions = `ssh.auto` accounts connecting from a jump address. They go through the gate and are auto-approved. Recovery and gray skip the gate at PAM, so they log in with the agent dead.
- Pause = gate terminations and auto-kills both become alerts until the token expires.
- Samba rotation sends the NT hash (`pdbedit --set-nt-hash`), so cleartext never leaves the jump box. MySQL credentials stay out of this plan (service inspectors, plan 6).
- No new controller listener. Orders and credential sets ride etcd under `/xdr/to/<host>/`, and hold hashes only.
- nftables already limits SSH to jump ∪ `ssh_from`. Per-account pinning is sshd's `AllowUsers`; nftables cannot see users.
