# XDR Plan 5: Console and Approvals Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The operator opens one page on the jump box, from a desktop or a phone, and sees what the fleet detected and did, approves or refuses what needs a person (SSH sessions, new users, files to remove, held processes), sees each host's state, and copies the rotated credentials. The agents report file drift against the baseline so there is something to approve.

**Architecture:**
- **Agent:** a drift scanner reports new or changed findings as `file-drift` incidents carrying the path; two new orders (`file`, `proc`) act on approved ones, with the same refusals the plan's tests pin.
- **Controller:** `internal/console` keeps a bounded view built from the incidents the controller already records, the heartbeats and the signed rules; it serves an authenticated JSON API and one embedded page over HTTPS, and turns operator actions into etcd orders.
- **Page:** one static HTML file with no external resources, polling the API.

**Tech Stack:** Go 1.27, CGO_ENABLED=0, `net/http`, `go:embed`, existing etcd orders (`/xdr/to/<host>/`), `creds` store, `breakglass` tokens.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md` §11 and its "Builder's calls, plan 5"; §7.4 (approvals), §5 and §6.2 (baseline and drift).

## Global Constraints

- One static binary, `CGO_ENABLED=0`; no new dependency, no external resource (the boxes are air-gapped): no web fonts, no CDN, no framework.
- Response stays on-box; gray accounts are alert-only; never take a scored service offline by our own action: the console may only kill a held scored process after the operator's explicit click, and the agent re-checks it.
- Nothing from the competition packet in code or tests; test addresses from 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24; no real password.
- Cleartext passwords never enter etcd, an incident, a log line or an error message; they are served only to the logged-in operator.
- Everything an agent sends is untrusted text.

## Review Focus

1. **Anyone but the operator reaching the API or the credentials.** Expected: every `/api/*` route answers 401 without a valid session cookie; a wrong password is refused and rate-limited; a cookie from before a restart, a logout, or 12 h ago is refused; a state-changing request without the custom header is refused. → Task 6 `TestAuth_*`, `TestAPI_RequiresSession`.
2. **Hostile text in the page.** Expected: a process, path or detail containing markup is displayed as text, and the page's CSP forbids inline script from any other source. → Task 7 `TestPage_NoInnerHTMLOfData`, `TestHeaders_CSP`; Task 8 e2e `hostile-text`.
3. **An approval that acts on more than it names.** Expected: `file` removes only a path the agent itself reported as a new persistence file, refuses a symlink swapped in, a base-image path, a guarded binary and a path outside its reports; `proc` kills only the pid whose exe hash matches the order, and refuses a gray process. → Task 2 `TestFileOrder_*`, Task 3 `TestProcOrder_*`.
4. **Hostile or heavy incident volume.** Expected: the console's memory and state file are bounded whatever the agents send (2000 incidents, 500 handled-approval ids, 256 hosts); a flood does not slow the API. → Task 4 `TestState_Bounded`.
5. **A controller restart or a double click.** Expected: a handled approval stays handled; the same approval acted on twice puts one order; credentials are never lost between a rotate and the store write (store first, then etcd). → Task 4 `TestState_HandledSurvivesRestart`, Task 5 `TestActions_Idempotent`.

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/collect/walk.go` | `WalkDirs(root, dirs)`: the walk limited to some directories |
| `internal/agent/scan.go` | fast and full drift scans, `file-drift` incidents |
| `internal/agent/fileorder.go`, `procorder.go` | the `file` and `proc` orders |
| `internal/incident/incident.go` | `Incident.Path` |
| `internal/console/state.go` | the bounded view, approvals derived from incidents |
| `internal/console/actions.go` | operator actions as orders; rotate; break-glass |
| `internal/console/server.go`, `auth.go` | HTTPS, login, sessions, API routes |
| `internal/console/web/index.html` | the page (embedded) |
| `internal/controller/config.go`, `internal/cli/controller.go` | `console` config, `console-password`, wiring |
| `test/vm/e2e-console.sh`, `Makefile` | the real-box test |

---

### Task 1: The agent reports drift

**Files:** Modify `internal/collect/walk.go`, `internal/incident/incident.go`, `internal/config/config.go`; Create `internal/agent/scan.go`, `internal/agent/scan_test.go`

**Interfaces:**
- Produces: `collect.WalkDirs(root string, dirs []string) (map[string]baseline.FileEntry, []string)`: `Walk` for the given directories only (those that exist), with the same skip, seal and keep rules; paths are relative to root as in `Walk`.
- Produces: `incident.Incident.Path string "path,omitempty"`.
- Produces: `config.Scan{Interval, Full Duration; Off bool}` as `Config.Scan "scan"`; defaults 30s and 10m; `off` disables both.
- Produces: `scanRoots = []string{"/etc", "/usr/lib/systemd", "/usr/local", "/opt", "/root", "/home", "/var/spool", "/tmp", "/var/tmp", "/dev/shm", "/srv"}`.
- Produces: `(a *agent) scan(full bool)` (no lock held while walking): walk (`WalkDirs(a.root, scanRoots)`, or `Snapshot` when full), compare with `diff.Diff` against the baseline restricted to the walked directories (a partial walk never makes anything outside them "removed"; accounts, groups and modules are copied from the baseline so only files differ), and record one `file-drift` incident per finding **not already reported with the same content**: `Action "alert"`, severity the finding's, `Path` its subject, `Detail` `<category> <kind>: <detail>`, plus `Size` and `SHA256` for a regular file. The agent keeps `a.drift map[path]sha256` of what it reported, forgets a path that no longer differs, and caps it at 4096.
- `Run` starts one scan goroutine on the intervals; a scan that is still running skips the next tick.

- [ ] **Step 1: Failing tests**
  - `TestWalkDirs_OnlyThoseDirs`: files under `/etc/cron.d` and `/home/bob`, and one under `/usr/bin`; `WalkDirs(root, ["/etc", "/home"])` has the first two and not the third; a missing directory is not an error.
  - `TestScan_ReportsNewFileOnce`: baseline without `/etc/cron.d/evil`; the file appears: one `file-drift` with `Path "/etc/cron.d/evil"`, severity High, its `SHA256`; a second scan adds none; the file changes: a second incident; it is deleted and comes back: reported again.
  - `TestScan_PartialDoesNotReadRemoved`: a baseline file under `/usr/bin` is absent from a fast scan's walk: no incident; a baseline file under `/etc` that is gone: a `removed` incident.
  - `TestScan_Bounded`: 5000 new files give at most 4096 remembered and no panic.
  - `TestConfig_Scan`: defaults, `off`, and a bad duration refused.
- [ ] **Step 2: Run** `go test ./internal/collect ./internal/agent ./internal/config -run 'WalkDirs|Scan'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): report baseline drift`.

### Task 2: The `file` order

**Files:** Create `internal/agent/fileorder.go`, `internal/agent/fileorder_test.go`; Modify `internal/agent/orders.go`

**Interfaces:**
- Consumes: `a.drift` from Task 1 (now also `a.driftNew map[id]path`: the *added* regular files and symlinks in persistence categories it reported), `onOrder`.
- Produces: order kind `file`, name = `FileID(path)` (the first 16 hex of sha256 of the path), value `{"verdict":"remove"|"undo","at":N}`.
  - `remove`: only a path in `a.driftNew` under that id. The file is opened `O_NOFOLLOW` at remove time and must still be a regular file or a symlink with the content or target the agent reported, not a base-image path, not a guarded binary (`a.pol.Guarded`), not under `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/lib`, `/usr/lib` except `/usr/lib/systemd`. It is moved to `State/quarantine-files/<id>/<name>` with `meta.json` (path, mode, uid, gid, link, time). Incident `file-removed` High, or `file-refused` with the reason.
  - `undo`: moves it back when the path is free and the meta matches; incident `file-restored`.
  - A quarantined entry older than 24 h is purged each sweep.
- Produces: `func FileID(path string) string` (also used by the console).

- [ ] **Step 1: Failing tests**
  - `TestFileOrder_RemovesReportedNewFile`: report `/etc/cron.d/evil`; the order moves it to quarantine, `file-removed` is recorded, the path is gone; `undo` puts it back byte for byte with its mode.
  - `TestFileOrder_Refusals`, rows: an id the agent never reported; a path now replaced by a symlink to `/etc/shadow`; a base-image path (reported as altered); a guarded binary; `/usr/bin/x` added; each gives `file-refused` and leaves the file.
  - `TestFileOrder_PurgesOld`: an entry 25 h old is gone after a sweep, a 1 h one stays.
- [ ] **Step 2: Run** `go test ./internal/agent -run FileOrder`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): remove a reported file with undo`.

### Task 3: The `proc` order and the pending session's deadline

**Files:** Create `internal/agent/procorder.go`, `internal/agent/procorder_test.go`; Modify `internal/agent/gate.go`, `internal/agent/orders.go`

**Interfaces:**
- Produces: order kind `proc`, name `<pid>`, value `{"verdict":"kill","sha256":"<exe hash>","at":N}`. The agent finds the pid in its last snapshot, requires its exe hash to equal `sha256`, refuses a gray process (`proc-refused`), and otherwise kills the tree with `a.kill(pid, start, protect)` where `protect` names only the agent itself (the operator has said yes to a held scored process; nothing else is spared). Incident `proc-killed` High, or `proc-refused` with the reason.
- Produces: the `session-pending` incident's detail ends `(ends in 1m30s)` (the grace left when it is recorded).

- [ ] **Step 1: Failing tests**
  - `TestProcOrder_KillsHeldProcessOnHash`: a guarded process held by an earlier detection; the order with its hash kills it (`proc-killed`); a wrong hash, a pid that is not there, a pid reused with another exe, and a gray user's process each give `proc-refused` and no kill.
  - `TestAgentSessions_PendingSaysWhenItEnds` (adapt the existing pending test): the detail contains `ends in 1m30s`.
- [ ] **Step 2: Run** `go test ./internal/agent -run 'ProcOrder|AgentSessions'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(agent): kill a held process on the operator's order`.

### Task 4: The console's view

**Files:** Create `internal/console/state.go`, `internal/console/state_test.go`; Modify `internal/controller/controller.go` (read-only accessors)

**Interfaces:**
- Consumes: `incident.Incident` as `ctl.record` writes them (the controller hands them to `State.Feed` through the log's `OnWrite`), `Controller.Hosts()`, `Controller.Current()`.
- Produces on `Controller`: `Hosts() []HostStatus{Name string; Seen bool; Silent bool; Disabled bool; Last time.Time}` (all enrolled hosts) and `Current()` as today.
- Produces: `type State`, `NewState(dir string, now func() time.Time) (*State, error)`, `(*State) Feed(in incident.Incident)`, `(*State) View(hosts []HostStatus, set *rules.Set) View`, and the persistence of `console-state.json` (handled approval ids, written on change, 0600).
- Produces: `type View struct{ Now time.Time; Summary Summary; Alerts []Alert; Approvals []Approval; Sessions []SessionRow; Hosts []HostRow; Rules int }`, with:
  - `Summary{Need, Killed, AgentsUp, AgentsTotal, Blocks int}`;
  - `Alert{ID, Host, Kind, Action, Severity, Title, Detail, Exe, SHA256, Path string; Remote string; Chain []string; Steps []string; Time time.Time}`: `Steps` lists what happened (the action; `rule <id> written` when a `rule-promoted` for the same hash or endpoint followed within 60 s; `block applied` for an `fw-block`);
  - `Approval{ID, Host, Kind ("session"|"user"|"file"|"proc"), Title, Why string; Deadline time.Time; Actions []string; Params map[string]string; Time time.Time}`.
- Approvals are derived and removed when handled or no longer true:
  - `session-pending` (session id from its detail) until a `session-terminated`, a `breakglass` for it, or the console handled it; actions `approve`, `kill`; `Deadline` from `ends in`.
  - `user-disabled` and `user-new` until `user-enabled` or handled; actions `approve`, `ignore`.
  - `file-drift` of kind added in a persistence category with a path, until `file-removed` or handled; actions `remove`, `keep`; after a removal an `undo` entry for 24 h.
  - an incident with `Action "held"` and a PID; actions `kill`, `ignore`; `Params` carries pid and sha256.
- Bounds: 2000 incidents, 500 handled ids (oldest dropped), 256 hosts, each text field cut to 2 KiB.

- [ ] **Step 1: Failing tests**
  - `TestState_ApprovalsFromIncidents`: a `session-pending` for session 7 (ends in 1m30s) appears with a deadline; a later `session-terminated` for 7 removes it; a `user-disabled` appears; a held `service-shell` appears with pid and sha256; a `file-drift` added `/etc/cron.d/evil` appears; a `file-removed` replaces it with an undo entry.
  - `TestState_AlertSteps`: an egress `killed` with hash H followed within 60 s by `rule-promoted` for H lists both steps.
  - `TestState_Summary`: killed count, agents up/total from hosts, blocks from `fw-block` minus `fw-unblock`.
  - `TestState_HandledSurvivesRestart`: handle an approval, build a new `State` on the same dir: it is still handled.
  - `TestState_Bounded`: 10000 incidents, 2000 handled ids and a 1 MiB detail keep the view and the state file within the bounds.
- [ ] **Step 2: Run** `go test ./internal/console ./internal/controller -run 'State|Hosts'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(console): the operator's view of the fleet`.

### Task 5: Operator actions

**Files:** Create `internal/console/actions.go`, `internal/console/actions_test.go`; Modify `internal/cli/rotate.go` (use the shared core)

**Interfaces:**
- Produces: `type Actions struct{ Dir string; Client *clientv3.Client; Cfg *controller.Config; Key ed25519.PrivateKey; State *State; Now func() time.Time }`.
- Produces: `(a *Actions) Decide(ctx, approvalID, action string) error`: session `approve`/`kill` and user `approve` put the order (as the CLI does, with `at`); file `remove`/`undo` put a `file` order; proc `kill` puts a `proc` order with the pid and hash; `ignore`/`keep` only mark handled. The same approval decided twice puts one order and the second returns `already handled`. A gray name is refused as the CLI refuses it.
- Produces: `(a *Actions) Rotate(ctx, host string, users, samba []string) ([]creds.Entry-lines, error)`: the core moved out of `cli/rotate.go` into `controller.Rotate(...)` and used by both; store first, then etcd.
- Produces: `(a *Actions) Creds() string` (the `Block("")`) and `Entries()` (host, service, account, password, rotated).
- Produces: `(a *Actions) Breakglass(host, action string, minutes int) (token string, err error)`: mints one token for an enrolled host, 5 min to 24 h long, starting now.

- [ ] **Step 1: Failing tests** (fleettest etcd):
  - `TestActions_DecideSession`: approving a pending session puts `session/<id>` with `approve` and `at`; killing puts `kill`; a second call returns `already handled` and puts nothing.
  - `TestActions_GrayRefused`: approving a gray user is refused, no order.
  - `TestActions_FileAndProc`: remove puts a `file` order with the id; proc kill puts the pid and hash from the approval.
  - `TestActions_RotateStoreBeforePut`: etcd down leaves the store entry (as `TestRotate_StoreBeforePut`); the CLI test still passes on the shared core.
  - `TestActions_Breakglass`: a token parses with the rule key, for the host, window as asked; an unenrolled host and `minutes` 0 or 2000 are refused.
- [ ] **Step 2: Run** `go test ./internal/console ./internal/controller ./internal/cli -run 'Actions|Rotate'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(console): approvals, rotation and break-glass as actions`.

### Task 6: The server and its login

**Files:** Create `internal/console/server.go`, `internal/console/auth.go`, tests; Modify `internal/controller/config.go` (`Console *struct{Listen string "listen"}`), `internal/cli/controller.go` (`console-password`, start the console in `controllerRun`)

**Interfaces:**
- Produces: `xdr controller console-password --dir D`: reads a password from stdin (not an argument), refuses under 12 characters, stores `console.json` (0600) `{hash: sha512-crypt $6$ with 100000 rounds}`.
- Produces: `console.Serve(ctx, cfg Config, view func() View, act *Actions) error`: HTTPS on `Console.Listen` with `DIR/server.pem` and `server-key.pem`, TLS 1.3 only.
- Routes: `POST /login` {password} sets cookie `xdr` (random 32 bytes, `HttpOnly; Secure; SameSite=Strict; Max-Age=43200`), `POST /logout`, `GET /` the page, `GET /api/state`, `POST /api/decide` {id, action}, `GET /api/creds`, `POST /api/rotate` {host, users, samba}, `POST /api/breakglass` {host, action, minutes}.
- Rules: every `/api/*` needs a live session (401 otherwise); every `POST /api/*` also needs header `X-XDR: 1` (403 otherwise); sessions live in memory only (a restart logs everyone out), 12 h; at most 5 failed logins a minute per source address and 20 a minute in all, then 429; request bodies limited to 64 KiB; every response carries `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`; the page, script and style are three embedded files so `'unsafe-inline'` is never needed.
- No password or cookie is ever logged.

- [ ] **Step 1: Failing tests** (`httptest`, self-signed or the fleettest server cert):
  - `TestAPI_RequiresSession`: each `/api/*` route without a cookie → 401; with a bad or expired cookie → 401.
  - `TestAuth_LoginLogout`: right password → cookie with the four attributes; the cookie opens `/api/state`; after `/logout` it does not.
  - `TestAuth_RateLimited`: 6 wrong passwords from one address → the 6th is 429, even a right one then; after the window it works; the 21st failure from many addresses is 429 for all.
  - `TestAuth_CSRF`: a `POST /api/decide` with the cookie but no `X-XDR` → 403, no order put.
  - `TestHeaders_CSP`: every route, 401s included, carries the header values above.
  - `TestAuth_PasswordNeverLogged`: the server's log output after logins holds neither the password nor the cookie value.
  - `TestConsolePasswordCLI`: stdin password under 12 characters refused; a good one writes `console.json` 0600 with a `$6$` hash that verifies.
  - `TestServe_TLS13Only`.
- [ ] **Step 2: Run** `go test ./internal/console ./internal/cli -run 'API|Auth|Headers|Serve|ConsolePassword'`. Expected: FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(console): HTTPS server with a login`.

### Task 7: The page

**Files:** Create `internal/console/web/index.html`, `app.js`, `app.css`, `internal/console/web_test.go`

**Interfaces:**
- Consumes: the API of Task 6; mockup `https://claude.ai/artifact/EYEaRd2sYnpqMRyRJSoywX` for layout and tone (status strip, tabs Alerts / Approvals / SSH sessions / Hosts / Credentials, left-bordered cards, pills), phone first, light and dark by `prefers-color-scheme`, system fonts only.
- The page: a login form; the header clock and etcd line; the summary strip; the tabs with counts; Alerts as cards with chain, steps and details; Approvals with their action buttons; Sessions with a live countdown to `Deadline`; Hosts as a table with agent, last beat, drift count, a break-glass control (mints and shows a token to copy); Credentials with each entry masked until revealed, a copy button each, "copy all" (the `Block` text), rotate-again beside each. Copy uses the clipboard API with a `select()`/`execCommand` fallback so it works over plain phone browsers. Polls `/api/state` every 2 s, pausing while hidden.
- All data is put in the DOM with `textContent` or `createElement`; `innerHTML`, `outerHTML`, `insertAdjacentHTML` and `document.write` are never used.

- [ ] **Step 1: Failing tests** (Go, on the embedded files):
  - `TestPage_NoInnerHTMLOfData`: `app.js` contains none of `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`.
  - `TestPage_NoExternalResources`: no `http://` or `https://` URL and no `<link href=`/`<script src=` outside the page's own paths.
  - `TestPage_Served`: `GET /`, `/app.js`, `/app.css` are served without a session (the login form is the page) with the right types; no data is in them.
  - `TestPage_Phone`: the page has a viewport meta and `app.css` has a media query under 520 px.
- [ ] **Step 2: Run** `go test ./internal/console -run Page`. Expected: FAIL.
- [ ] **Step 3: Write the page.** Check it by running the controller locally against a fleettest etcd and loading it in a browser pane or `curl`; it is also exercised by Task 8.
- [ ] **Step 4: Run.** Expected: PASS.
- [ ] **Step 5: Commit** `feat(console): the operator's page`.

### Task 8: The console on the real boxes

**Files:** Create `test/vm/e2e-console.sh`; Modify `Makefile` (`remote-console`), `deploy/` (a `controller.example.json` with `console`)

**Interfaces:**
- Consumes: the ssh backend; the controller runs on the jump box with `console.listen` on its private address; the API is driven with `curl -k` from the jump box itself. One agent target (`BOXES[0]`) as in `e2e-gate.sh`, plus `alice`, a gray user and a test key.
- Cases, each `ok <name>`; ends `E2E-CONSOLE PASS`:
  1. `auth`: `/api/state` without login is 401; wrong password 401/429; the right one gives a cookie that opens it; `POST` without `X-XDR` is 403.
  2. `state`: the host is up in `Hosts`; the summary counts agents.
  3. `session-approve`: `ssh alice` is pending: it appears under Approvals with a deadline; `decide approve` keeps it alive past the grace.
  4. `session-kill`: the same, `decide kill` ends it.
  5. `drift-and-remove`: planting `/etc/cron.d/xdr-e2e-evil` on the box makes a `file-drift` approval appear within 60 s (fast scan); `decide remove` quarantines it (gone from the box, `file-removed` alert); `undo` restores it byte for byte.
  6. `held-kill`: a copy of the box's scored-service binary run from `/tmp` is not held (non-baseline: killed); a guarded process is made to show a held detection (a `service-shell` child of the test scored service as `svc.py` does) and `decide kill` kills the shell, never the service without an approval.
  7. `creds`: `rotate` through the API shows the new password in `/api/creds`, 20 characters, and the box's shadow hash changed; `copy all` text lists host, service, account, password.
  8. `breakglass`: minting a pause token through the API gives a token that `xdr breakglass` accepts on the box.
  9. `hostile-text`: a process named `<script>alert(1)</script>` (`exec -a`) making an outbound connection appears in `/api/state` as the literal string, and the served page still carries the CSP; (a browser pane check of the rendered page is done by hand once and noted in the ledger).
- [ ] **Step 1: Write the script and the Makefile target.**
- [ ] **Step 2: Run** `make remote-console`. Expected: all 9 `ok`, `E2E-CONSOLE PASS`. Run it twice.
- [ ] **Step 3: Run** `make remote-gate`, `remote-block`, `remote-detect`, `remote-fleet` (the agent changed). Expected: PASS.
- [ ] **Step 4: Commit** `test: console on the real boxes`.

---

## Builder's calls in this plan (recorded for the spec)

- Drift is reported by a persistence-directories walk every 30 s and a whole-disk walk every 10 min (configurable, `scan.off` disables); a partial walk never reports anything outside its directories as removed.
- Only *new* files in persistence locations can be removed from the console; changed or removed base-image files are alerts only (nothing to restore them from on an air-gapped box).
- A removed file is quarantined, not deleted, and can be restored for 24 hours.
- Killing a held scored process needs the operator's click and the pid's exe hash; nothing else spares it.
- The console is HTTPS with the controller's server certificate and one operator password; sessions are in memory, so a controller restart logs the operator out.
- The page and its script and style are three embedded files so the CSP never needs `unsafe-inline`.
- Service inspectors and a DNS switch are not part of this plan.
