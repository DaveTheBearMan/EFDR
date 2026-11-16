# XDR Plan 6: Self-protection and Self-healing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The agent comes back when it is killed, its files are put back when they are changed, whoever touches them is killed, the controller can reinstall a box over SSH, a box cut off from the fleet takes down what is cutting it off, and a signed token removes it all cleanly.

**Architecture:**
- **install:** `xdr install|ensure|uninstall` over one layout (three binary copies, a pinned hash, a manifest, immutable files, six kinds of launch point that all pick a good copy and run `xdr ensure`).
- **guard:** two guard units that watch each other and the agent.
- **tamper:** fanotify on the installed files names the writer; the agent kills it by the same rules as every other kill.
- **heal:** an isolation detector and the reconnect ladder.
- **controller:** `reinstall` over SSH, by hand or after a silence.

**Tech Stack:** Go 1.27, CGO_ENABLED=0, `golang.org/x/sys/unix` (fanotify, ioctl), `chattr`, `systemctl`, `ssh`, `nft`, `iptables-legacy`, `ip`.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md`: §9 and its "Builder's calls, plan 6", §9a, §7.4 (tamper), §10 (tokens).

## Global Constraints

- One static binary, `CGO_ENABLED=0`; no new dependency.
- Never take a scored service offline by our own action: tamper kills hold a scored service; the ladder never touches scored ports or rules, never reboots; `ensure` restarts only XDR's own units.
- Gray accounts are alert-only (reverse shells still killed); the harness's and operator's own `auto`/recovery sessions are never terminated.
- Response stays on-box; the controller's SSH key never goes to a target.
- Nothing from the packet in code or tests; test addresses from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (real-box tests use the boxes' own private addresses, never committed).

## Review Focus

1. **A box that cannot be brought back, or that is bricked by the install.** Expected: `install` run twice changes nothing; `ensure` with every copy bad exits non-zero and says so, and never deletes the last copy; a failed `install` leaves the previous install running; `uninstall` removes every launch point and clears `+i` so nothing is left running or immutable. → Task 1 tests.
2. **The box's own work read as tamper.** Expected: the agent, a guard, `ensure`, `install` and `apt` hooks never get killed; only a writer that is not running a pinned binary is. A pause token turns kills into alerts. → Task 3 `TestTamper_IgnoresOwnBinaries`, `TestTamper_PausedAlertsOnly`.
3. **Tamper kills aimed at the wrong thing.** Expected: pid reuse, a gray account, a scored service, the agent itself, and the operator's auto session are not killed or terminated. → Task 3.
4. **The ladder making things worse.** Expected: it removes only rules that name a fleet address or port, never ones for scored ports; it does nothing when not isolated; it backs off; every removal is an incident. → Task 5.
5. **The reinstall path as an attack surface.** Expected: host names and paths are checked before they reach a command line; the key stays on the jump box; a reinstall is rate-limited and never run for a host that is not enrolled. → Task 4.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/install/layout.go`, `render.go`, `install.go`, `ensure.go` | layout, rendering of units and hooks, install, ensure, uninstall |
| `internal/guard/guard.go` | the watcher loop |
| `internal/tamper/fanotify.go` | the fanotify watcher |
| `internal/agent/tamper.go`, `heal.go` | tamper response; isolation and the ladder |
| `internal/heal/*.go` | the ladder's pure parts: what blocks the fleet in nft, iptables, ip output |
| `internal/controller/reinstall.go`, `config.go` | reinstall, its trigger |
| `internal/breakglass/token.go`, `internal/cli/*.go` | `uninstall` action; `install`, `ensure`, `guard`, `uninstall`, `controller reinstall` |
| `test/vm/e2e-protect.sh`, `Makefile` | the real-box test |

---

### Task 1: install, ensure, uninstall

**Files:** Create `internal/install/layout.go`, `render.go`, `install.go`, `ensure.go` and tests; Modify `internal/cli/cli.go`

**Interfaces:**
- Produces: `type Layout struct{ Root string; Copies []string; Pinned, Manifest, Backup string; Config string }` and `DefaultLayout()` with the paths of the spec; `Root` is `""` on a box and a temp dir in tests.
- Produces: `type Runner func(name string, args ...string) ([]byte, error)`.
- Produces: `Chooser(l Layout) string`: the shell command every launch point starts with: it runs the first copy whose `sha256sum` equals the pinned hash, with the arguments given after it (`"$@"`), and exits 127 when none matches.
- Produces: `Render(l Layout) []File` (`File{Path string; Content []byte; Mode fs.FileMode}`), pure: `xdr-agent.service` (`Restart=always`, `RestartSec=1`), `xdr-guard-a.service` and `xdr-guard-b.service` (each running `guard --watch` the other), `xdr-ensure.service` and `xdr-ensure.timer` (`OnUnitActiveSec=30s`), `/etc/cron.d/xdr-ensure` (`@reboot` and `* * * * *`), `/usr/lib/systemd/system-generators/xdr-generator`, `/etc/apt/apt.conf.d/99xdr`; every one uses `Chooser`.
- Produces: `Install(l Layout, run Runner, binary string) (Report, error)`: writes the three copies (equal to `binary`), the pinned hash, the manifest, the backup of the config, its signature and the fleet bundle, then the files of `Render`, `systemctl daemon-reload`, `enable --now` the agent, guards and timer, and `chattr +i` on everything; idempotent (the second run changes nothing); a copy is written to a temp name and renamed, so a failed install leaves the old one.
- Produces: `Ensure(l Layout, run Runner) (Report, error)`: for each manifest entry whose file is missing or differs, restore it from a good copy (binary copies from each other, other files from the backup or `Render`), clearing and setting `+i` around the write; then start any of the agent, guard and timer units that `systemctl is-active` says is not active. `Report{Restored []string; Started []string}`; with no good copy it returns an error naming the copies and restores nothing.
- Produces: `Uninstall(l Layout, run Runner) error`: stops and disables the units, clears `+i`, removes every file of the manifest and the manifest itself, and `nft delete table inet xdr`.
- CLI: `xdr install [--config FILE]` (copies its own binary), `xdr ensure`, `xdr uninstall --token T` is Task 6.

- [ ] **Step 1: Failing tests** (`testfs.Root`, a recording fake `Runner`):
  - `TestChooser_PicksTheGoodCopy`: run for real with three small scripts as copies, one corrupted: the good one runs with the arguments; all bad: exit 127.
  - `TestRender_LaunchPoints`: each of the seven kinds is present; each contains the chooser and `ensure` (or `agent`/`guard`); the two guard units have different names and each names the other; the agent unit has `Restart=always`; the generator links the agent unit into `multi-user.target.wants`.
  - `TestInstall_WritesEverythingOnceAndIsIdempotent`: three equal copies, pinned hash, manifest listing them, backup of config, `chattr +i` called for each; the second run reports nothing changed and runs no `enable`.
  - `TestInstall_FailureKeepsTheOldInstall`: a failing write of the third copy leaves the first two as they were.
  - `TestEnsure_RestoresAndStarts`: a corrupted copy is restored from a good one, a deleted unit file is rewritten, a deleted backup file is restored, an inactive agent unit is started; the report names each; with everything fine it does nothing.
  - `TestEnsure_NoGoodCopy`: every copy bad: an error, nothing deleted, nothing written.
  - `TestUninstall_RemovesAllAndClearsImmutable`: after install then uninstall no manifest file remains, `chattr -i` ran first, the units were stopped and disabled, the table was deleted.
- [ ] **Step 2: Run** `go test ./internal/install`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(install): install, ensure and uninstall with six kinds of launch point`.

### Task 2: the guards

**Files:** Create `internal/guard/guard.go`, `guard_test.go`; Modify `internal/cli/cli.go` (`guard`)

**Interfaces:**
- Produces: `guard.Run(ctx, l install.Layout, run install.Runner, watch string, every time.Duration, report func(string))`: each tick it runs `install.Ensure`, and if `systemctl is-active watch` is not active it starts it and reports it. `xdr guard --watch UNIT [--every 1s]` runs it.
- Produces: `xdr ensure` prints its report and exits 0 when it restored nothing, 3 when it restored something, 1 on error.

- [ ] **Step 1: Failing tests**: `TestGuard_StartsTheOtherGuard` (fake runner: `is-active xdr-guard-b` is inactive: `start` is called once per tick until it is active), `TestGuard_RestoresADeletedUnitFile` (the other's unit file is gone: ensure restores it, then starts it), `TestGuard_StopsWithTheContext`, `TestEnsureCLI_ExitCodes`.
- [ ] **Step 2: Run** `go test ./internal/guard ./internal/cli -run 'Guard|Ensure'`. Expected: FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(guard): two guards that watch each other and the agent`.

### Task 3: tamper detection and response

**Files:** Create `internal/tamper/fanotify.go`, `fanotify_test.go`, `internal/agent/tamper.go`, `tamper_test.go`; Modify `internal/agent/agent.go` (start it), `internal/config/config.go` (`Self{Off bool "off"}` as `Config.Self "self"`)

**Interfaces:**
- Produces: `tamper.Watch(paths, dirs []string) (*Watcher, error)`: a fanotify group (`FAN_CLASS_NOTIF|FAN_REPORT_DFID_NAME|FAN_NONBLOCK`) with an inode mark on each path (`FAN_MODIFY|FAN_CLOSE_WRITE|FAN_ATTRIB|FAN_DELETE_SELF|FAN_MOVE_SELF`) and each directory (`FAN_CREATE|FAN_DELETE|FAN_MOVED_FROM|FAN_MOVED_TO|FAN_ONDIR`); `Events() <-chan Event` with `Event{Path string; Name string; PID int; Op string}`; `Close()`. A path that is missing is skipped and named in the error text of `Watch`, not fatal.
- Produces: `(a *agent) onTamper(ev tamper.Event)` (a.mu not held on entry): decides in this order:
  1. the actor is the agent, a guard, or runs a pinned binary (exe hash equals `/etc/xdr/pinned.sha256`, read from the process's `/proc/PID/exe`): ignored;
  2. a `tamper` incident Critical names path, op, actor pid and exe, whatever follows;
  3. paused: `Action "alert"`; the actor gray: alert; the actor guarded (a scored service): `held`; pid gone: alert `(exited)`; otherwise `a.kill(pid, start, protect)` (protect: the agent and guards) and `Action "killed"`;
  4. when killed, the actor's logind session (from its `/proc/PID/cgroup` `session-N.scope`, read before the kill) is terminated unless its user is in `ssh.auto`, the recovery account or gray.
- Agent: when `/var/lib/xdr/manifest.json` exists and `self.off` is false, `Run` watches the manifest's files and their directories and passes events to `onTamper` (a burst of events from one pid within a second is one incident).

- [ ] **Step 1: Failing tests**
  - `TestWatch_NamesTheWriter` (root only; skips otherwise): a temp file and directory; this process writes, renames, creates and deletes; each gives an `Event` whose PID is this process's and whose Op names it; a missing path is skipped.
  - `TestTamper_KillsActor`: a non-pinned process named in the event is killed, session terminated, one Critical `tamper`/`killed` incident.
  - `TestTamper_IgnoresOwnBinaries`: an actor whose exe hash equals the pinned one, and the agent's own pid, raise nothing.
  - `TestTamper_GrayAlertOnly`, `TestTamper_PausedAlertsOnly`, `TestTamper_GuardedHeld`, `TestTamper_PidGone`.
  - `TestTamper_AutoSessionNotTerminated`: an `auto` user's actor process is killed, its session is not.
  - `TestTamper_BurstIsOneIncident`.
- [ ] **Step 2: Run** `go test ./internal/tamper ./internal/agent -run 'Watch|Tamper'`. Expected: FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run** (also `sudo` for the fanotify test). Expected: PASS.
- [ ] **Step 5: Commit** `feat: tamper detection names the writer and kills it`.

### Task 4: controller reinstall

**Files:** Create `internal/controller/reinstall.go`, `reinstall_test.go`; Modify `internal/controller/config.go` (`Reinstall`), `internal/controller/controller.go` (the trigger), `internal/cli/controller.go` (`reinstall`)

**Interfaces:**
- Produces: `controller.Config.Reinstall *Reinstall{Key string; User string; After Duration; Hosts map[string]ReinstallHost{Addr, Config string}}`; `After` defaults 60 s; `Key` and each `Config` must be absolute paths.
- Produces: `type SSH interface{ Run(ctx, addr, command string, stdin io.Reader) error }` and `controller.Reinstall(ctx, dir string, cfg *Config, host string, ssh SSH, binary string) error`: refuses a host not enrolled or not in `cfg.Reinstall.Hosts`, and a host name or address failing `config.Hostname`/`netip.ParseAddr`; then over SSH: a temp directory (`mktemp -d`, name read back and validated), the binary, a fresh enrolment bundle (`pki.Enroll` to a temp dir, tarred), the host's agent config with a signature made on the spot, and `<binary> install --config <file>` run with the bundle in place. The key is only ever a `-i` argument of the local `ssh`; nothing of it is sent.
- Produces: `ExecSSH` (the real one, `ssh -i KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new USER@ADDR`) and the controller's trigger: when `agent-silent` is recorded for a host in `cfg.Reinstall.Hosts` and it stays silent for `After`, run `Reinstall` once per episode and at most every 5 min per host; incidents `reinstall` (alert, then repaired or failed).
- CLI: `xdr controller reinstall --dir D --host H [--binary FILE]` (default: this binary).

- [ ] **Step 1: Failing tests** (a fake `SSH` recording commands and stdin):
  - `TestReinstall_Steps`: the order and content: a mktemp, the binary pushed (hash equals the source), a bundle containing `ca.pem host.pem host-key.pem rules.pub`, a config whose `.sig` verifies with the rule key, then `install`; the fake sees no part of the key file.
  - `TestReinstall_Refusals`: unenrolled host, a host not in `reinstall.hosts`, `addr` of `1.2.3.4; reboot`, a relative `key`: each an error and no command run.
  - `TestTrigger_AfterSilenceOncePerEpisode`: a fake clock: silent for less than `After` runs nothing; at `After` one reinstall; still silent: no second until 5 min; back then silent again: a new episode.
  - `TestConfig_Reinstall`: defaults, bad paths refused.
- [ ] **Step 2: Run** `go test ./internal/controller ./internal/cli -run 'Reinstall|Trigger'`. Expected: FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(controller): reinstall a box over SSH, by hand or after a silence`.

### Task 5: isolation and the ladder

**Files:** Create `internal/heal/parse.go`, `parse_test.go`, `internal/agent/heal.go`, `heal_test.go`; Modify `internal/agent/agent.go`, `internal/mesh/mesh.go` (a `Reachable() int`)

**Interfaces:**
- Produces: `heal.NftBlockers(ruleset string, fleet []netip.Prefix, ports []uint16, scored []config.Port) []Table` (tables other than ours with a `drop` or `reject` rule naming a fleet address or one of the agent ports; never one whose only matches are scored ports), `heal.IptablesBlockers(save string, ...) [][]string` (rules, as `-D` argument lists), `heal.RouteBlockers(rules, routes string, fleet) []string` (the `ip rule del …` / `ip route del …` argument lines for blackhole, unreachable and prohibit entries naming a fleet address), `heal.DenyLines(hostsDeny string, fleet) []string`.
- Produces: `(a *agent) isolated() bool`: etcd not connected and `mesh.Reachable() == 0` (or no mesh peers) for 10 s (an injected clock).
- Produces: `(a *agent) ladder(run Runner)`: when isolated, at most once per backoff step (2 s doubling to 30 s, reset when not isolated): (1) `syncTable`; (2) run the blocker finders over `nft list ruleset`, `iptables-legacy-save`, `ip6tables-legacy-save`, `ip rule`, `ip route`, `/etc/hosts.deny` and remove what they name, one `tamper` Critical incident each; (3) from the snapshot taken at start (link, address, default route) bring back what is missing; (4) `systemctl restart ssh.service` when nothing listens on `ssh_port`. Incidents `isolation` (when it starts) and `isolation-over` (when it ends, listing what was removed).
- Guardrails (tests): a drop rule for a scored port is not removed; nothing runs when not isolated; steps are in order; the rules removed are exactly those named.

- [ ] **Step 1: Failing tests**
  - `TestNftBlockers`: a foreign table with `ip daddr 192.0.2.7 drop` is found; one with only `tcp dport 80 drop` (scored) is not; our table and Docker's `nat` are not; a table with `reject` and the etcd port is.
  - `TestIptablesBlockers`, `TestRouteBlockers` (`blackhole 192.0.2.7`, `unreachable 192.0.2.0/24`, a `from all to 192.0.2.7 prohibit` rule), `TestDenyLines`, each with a harmless line that is left.
  - `TestIsolated_NeedsBothAndTenSeconds`.
  - `TestLadder_StepsInOrderAndBacksOff`: fake runner; not isolated: nothing runs; isolated: table re-applied, then the removals, one incident each, then the link and sshd steps; the next call before the backoff runs nothing; after it, the next step of the ladder; `isolation-over` lists what was removed.
  - `TestLadder_RestoresLinkAndRoute`: the snapshot has `eth0 up 10.0.0.5/24 via 10.0.0.1`; the box lost the address and route: both are re-added.
- [ ] **Step 2: Run** `go test ./internal/heal ./internal/agent -run 'Blockers|Isolated|Ladder'`. Expected: FAIL.
- [ ] **Step 3: Implement.** **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: isolation detection and the reconnect ladder`.

### Task 6: the signed uninstall

**Files:** Modify `internal/breakglass/token.go`, `internal/agent/breakglass.go`, `internal/cli/*.go`, `internal/console/actions.go`

**Interfaces:**
- Produces: break-glass action `uninstall` accepted by `Parse` and `controller mint-breakglass` (and the console's mint), 5 min to 24 h as the others.
- Produces: the agent, on a valid `uninstall` token for this host (once, via the socket or the spool), records an `uninstall` Critical incident and runs `install.Uninstall`, then exits; `xdr uninstall --token T` verifies the token itself with the fleet bundle's `rules.pub` and the host name in its certificate and runs `install.Uninstall` (for a dead agent).

- [ ] **Step 1: Failing tests**: `TestToken_UninstallAction` (parse, mint, another host's refused), `TestBreakglass_UninstallRemovesTheInstall` (fake runner and layout: uninstall ran, incident recorded, a second use refused), `TestUninstallCLI` (a valid token uninstalls; an expired, another host's or an `approve-session` token does not).
- [ ] **Step 2: Run.** Expected: FAIL. **Step 3: Implement.** **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat: a signed token removes the install`.

### Task 7: protection on the real boxes

**Files:** Create `test/vm/e2e-protect.sh`; Modify `Makefile` (`remote-protect`)

**Interfaces:**
- Consumes: the ssh backend with the controller (and a reinstall key: the deploy key, `reinstall.key`), one target (`BOXES[0]`) with `xdr install` run on it and the agent started by its unit, a second target (`BOXES[1]`) as the reinstall target without an install.
- Cases (each `ok <name>`; ends `E2E-PROTECT PASS`):
  1. `install`: the three copies, pinned hash, manifest, units active, files immutable (`lsattr`); a second install changes nothing.
  2. `restart-agent`: `kill -9` the agent: back within 5 s, by the unit.
  3. `stop-all-units`: stop the agent and both guards and the timer: back within 90 s (cron and timer).
  4. `delete-unit-files`: delete the agent unit and a guard unit (after clearing `+i` as an attacker would): `ensure` puts them back and the agent runs.
  5. `corrupt-a-copy`: overwrite one binary copy: restored from a good one, the agent still runs, a `tamper` incident from `ensure` is reported.
  6. `tamper-kills-actor`: a non-pinned process (a copy of `/bin/sleep` run from `/tmp`) that rewrites the manifest is killed within 2 s and a Critical `tamper` is reported with its pid; the harness's own root session lives.
  7. `tamper-by-gray`: a gray user cannot write the files (permission): nothing to kill; a gray *root-owned* case is not testable and is covered by unit tests.
  8. `reinstall`: delete the second box's install (or never install it), `xdr controller reinstall` brings its agent up and it appears in the console/controller as up.
  9. `isolation-ladder`: on the first box add an nft foreign table dropping the jump box's etcd port and an `ip route blackhole` for the jump box: the agent reports `isolation`, removes both (one `tamper` incident each), the fleet reconnects, `isolation-over` is reported; nothing of the scored ports is touched.
  10. `uninstall-token`: a minted `uninstall` token through `xdr breakglass` removes every launch point, the files, the table: nothing left running or immutable.
- [ ] **Step 1: Write the script and the Makefile target.**
- [ ] **Step 2: Run** `make remote-protect`. Expected: all 10 `ok`, `E2E-PROTECT PASS`. Run it twice.
- [ ] **Step 3: Run** `remote-console`, `remote-gate`, `remote-block`, `remote-detect`, `remote-fleet`. Expected: PASS.
- [ ] **Step 4: Commit** `test: self-protection and self-healing on the real boxes`.

---

## Builder's calls in this plan (recorded for the spec)

See the spec's "Builder's calls, plan 6" (written with the plan).
