# XDR Plan 1: Foundation & Baseline Engine — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single static `xdr` binary that captures a host snapshot (files, privilege bits, accounts, kernel modules) and reports every added/altered/removed persistence item against an embedded clean baseline, plus off-box package-hash verification from `.deb` files.

**Architecture:** Every collector reads from a `root` directory (`/` in production, a temp fixture tree in tests), so almost everything is unit-tested unprivileged. The snapshot is one `baseline.Baseline` value: a path-keyed file map (with content kept for small persistence-relevant files), accounts and modules. Layers (base image → scored-service packages → triage approvals) compose by overlay. A path classifier assigns each file a persistence category and severity. The diff engine turns baseline-vs-live differences into `model.Finding`s.

**Tech Stack:** Go 1.27 (toolchain on dev box), `CGO_ENABLED=0`; `golang.org/x/sys/unix` (xattrs, mkfifo in tests); `github.com/klauspost/compress/zstd`; `github.com/ulikunitz/xz`; `github.com/pmezard/go-difflib`; LXD (`lxc`) for the Ubuntu 24.04 VM harness.

**Spec:** `docs/superpowers/specs/2026-11-10-xdr-design.md` (roadmap: `docs/superpowers/plans/2026-11-10-xdr-roadmap.md`)

## Global Constraints

- Linux only; target Ubuntu 24.04 (exact base image provided by operator). Dev box is Ubuntu 26.04: anything kernel/OS-specific is verified in the 24.04 VM (Task 9).
- One static binary: `CGO_ENABLED=0 go build -trimpath`. No runtime dependence on host tools (`debsums`, `dpkg`, `getcap`, …).
- Trusted hashes never come from the target box (never read `/var/lib/dpkg/info/*.md5sums` as truth). Hash algorithm: SHA-256, lowercase hex.
- Clean baseline is embedded with `go:embed`.
- Collectors never follow symlinks and only open regular files.
- Module path: `xdr`. Binary: `bin/xdr`.
- Every path stored in a `Baseline` is `pathenc`-encoded (Task 2). Paths are absolute as seen from `root` (e.g. `/etc/crontab`).

## Review Focus

1. **Symlink in a persistence directory pointing outside the root or at a device** (`/etc/cron.d/x -> /dev/zero`): the collector records the link and target without following it or hanging. Test: `TestWalk_SymlinkNotFollowed` (Task 3).
2. **Non-UTF-8 or newline-containing filenames**: they must survive save/load with no phantom findings. Test: `TestCodec_RoundTripOddPaths` (Task 2).
3. **FIFOs, unreadable files and files vanishing mid-walk** (e.g. a FIFO in `/tmp`): no hang, no crash, an error recorded, the walk continues. Test: `TestWalk_FifoAndUnreadable` (Task 3).
4. **Malformed `/etc/passwd` lines and a second UID-0 account** (`toor:x:0:0`): the parser tolerates junk and the diff raises Critical. Tests: `TestParsePasswd_Malformed` (Task 4), `TestDiffAccounts_SecondUID0` (Task 6).
5. **A clean rescan of a real 24.04 box must yield zero findings** (volatile paths excluded), and package `/bin/x` paths must match the walker's `/usr/bin/x`. Tests: the VM `clean-rescan` check (Task 9) and `TestParseDeb_UsrMerge` (Task 7).

---

## File Structure

```
go.mod, Makefile, .gitignore
cmd/xdr/main.go                    entry: os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
internal/cli/cli.go                subcommand dispatch, flag parsing, exit codes
internal/cli/cli_test.go
internal/model/finding.go          Finding, Kind, Severity
internal/pathenc/pathenc.go        safe path encoding
internal/baseline/baseline.go      Baseline, FileEntry, Account, Group, Layer, Compose
internal/baseline/codec.go         Save/Load (gzip JSON)
internal/baseline/embedded.go      go:embed data/base.json.gz → Embedded()
internal/baseline/data/base.json.gz
internal/testfs/testfs.go          fixture-tree helpers for tests
internal/collect/walk.go           filesystem walk → Files
internal/collect/exclude.go        volatile/ignored path lists
internal/collect/accounts.go       passwd/shadow/group parsing
internal/collect/modules.go        /proc/modules
internal/collect/snapshot.go       Snapshot(root) → *Baseline
internal/classify/classify.go      path → Category, severity, keep-content
internal/diff/diff.go              Diff(base, live) → []Finding
internal/diff/accounts.go          account/group/module semantics
internal/debhash/deb.go            .deb → per-file hashes
internal/debhash/status.go         dpkg status parsing
internal/debhash/layer.go          FromPackages → package-layer Baseline
test/vm/e2e.sh, test/vm/plant.sh   Ubuntu 24.04 LXD harness
```

---

### Task 1: Repo, binary skeleton, static build

**Files:**
- Create: `go.mod`, `Makefile`, `.gitignore`, `cmd/xdr/main.go`, `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Produces: `cli.Run(args []string, stdout, stderr io.Writer) int`. Exit codes: `0` = ok/no findings, `1` = findings present, `2` = usage or runtime error. Subcommand `version` prints `xdr <version>` where `var Version = "dev"` lives in `internal/cli` and is set with `-ldflags "-X xdr/internal/cli.Version=..."`.

- [ ] **Step 1:** `git init` in `/home/davethebearman/XDR`, `go mod init xdr`, add `.gitignore` containing `bin/`.
- [ ] **Step 2: Write failing tests** in `internal/cli/cli_test.go`:
  - `TestRun_Version`: `Run([]string{"version"}, &out, &errb)` returns `0`, and `out` starts with `"xdr "`.
  - `TestRun_Unknown`: `Run([]string{"bogus"}, ...)` returns `2`, and `errb` contains `unknown command "bogus"`.
  - `TestRun_NoArgs`: returns `2`, and `errb` contains `usage:`.
- [ ] **Step 3:** Run `go test ./internal/cli/`. Expected: FAIL (`Run` undefined).
- [ ] **Step 4:** Implement `Run` with a `switch` on `args[0]`, and `cmd/xdr/main.go`.
- [ ] **Step 5:** Run `go test ./internal/cli/`. Expected: PASS.
- [ ] **Step 6:** Add a `Makefile` with targets `build` (`CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X xdr/internal/cli.Version=$(git describe --always --dirty)" -o bin/xdr ./cmd/xdr`) and `test` (`go test ./...`). Run `make build && file bin/xdr`. Expected: output contains `statically linked`.
- [ ] **Step 7:** Commit the existing `XDR_INITIAL.md` and `docs/` along with the skeleton: `git add -A && git commit -m "feat: xdr binary skeleton"`.

---

### Task 2: Core types, path encoding, baseline codec

**Files:**
- Create: `internal/model/finding.go`, `internal/pathenc/pathenc.go`, `internal/pathenc/pathenc_test.go`, `internal/baseline/baseline.go`, `internal/baseline/codec.go`, `internal/baseline/baseline_test.go`, `internal/testfs/testfs.go`

**Interfaces:**
- Produces, in `model`:
  ```go
  type Kind string      // KindAdded="added", KindAltered="altered", KindRemoved="removed"
  type Severity int     // SevInfo, SevLow, SevMedium, SevHigh, SevCritical (ordered); String() → "info".."critical"
  type Finding struct {
      Kind     Kind
      Category string   // classify category, or "account", "group", "module"
      Severity Severity
      Subject  string   // encoded path, account/group name, or module name
      Detail   string   // one human-readable line
      Before   string   // e.g. old sha256 / old value; "" if added
      After    string   // e.g. new sha256 / new value; "" if removed
      Diff     string   // unified diff when both contents are known, else ""
  }
  ```
- Produces, in `pathenc`: `Encode(p string) string` and `Decode(s string) (string, error)`. A valid-UTF-8 path with no `\n` and no `b64:` prefix is returned unchanged. Anything else becomes `"b64:" + base64.StdEncoding(p)`.
- Produces, in `baseline`:
  ```go
  type Layer uint8 // LayerBase=0, LayerPackage=1, LayerTriage=2
  type FileType byte // 'f' regular, 'd' dir, 'l' symlink, 'o' other (fifo/socket/device)
  type FileEntry struct {
      Type FileType; Mode uint32 /* os.FileMode bits incl. setuid/setgid */
      UID, GID uint32; Size int64
      SHA256 string; Link string; Caps string // hex of security.capability xattr, "" if none
      Content []byte // only when classify says keep-content and Size <= 65536
      HashOnly bool  // compare only Type/SHA256/Link (package layer)
      Layer Layer
      Err string     // read error, if any
  }
  type Account struct { Name string; UID, GID uint32; Home, Shell string; PwState string /* "locked","none","set" */; PwDigest string /* sha256 of shadow field */ }
  type Group struct { Name string; GID uint32; Members []string }
  type Baseline struct {
      Schema int // = 1
      Host, OSRelease string
      CapturedAt time.Time
      Files map[string]FileEntry // key: pathenc-encoded absolute path
      Accounts []Account
      Groups []Group
      Modules []string // nil = not captured (offline image); diff skips modules when either side is nil
      Errors []string
  }
  func Compose(layers ...*Baseline) *Baseline // later layer wins per path; Accounts/Groups/Modules: the last non-nil wins
  func Save(w io.Writer, b *Baseline) error   // gzip(JSON)
  func Load(r io.Reader) (*Baseline, error)
  ```
- Produces, in `testfs`, test-only helpers that take `t *testing.T` and `t.Fatal` on error:
  - `Root(t) string` returns a temp dir.
  - `File(t, root, rel, content string, mode os.FileMode)` creates parent dirs.
  - `Symlink(t, root, rel, target string)`.
  - `Fifo(t, root, rel string)`.
  - `Remove(t, root, rel string)`.

- [ ] **Step 1: Write failing tests.**
  - `TestEncode_Plain`: `Encode("/etc/crontab") == "/etc/crontab"`.
  - `TestEncode_Odd`: for `"/tmp/a\nb"`, `"/tmp/\xff"` and `"b64:x"`, the output has the prefix `b64:` and `Decode(Encode(p)) == p`.
  - `TestCodec_RoundTripOddPaths`: a Baseline whose Files are keyed by `Encode("/tmp/\xff\n")` with `Content: []byte{0,1,2}` survives `Save`→`Load`, compared with `reflect.DeepEqual` (with `CapturedAt` truncated to seconds, in UTC).
  - `TestCompose_LaterWins`: base has `/a` sha `"1"` and `/b`. The overlay has `/a` sha `"2"` with `Layer: LayerTriage`. The result has `/a`=`"2"` and still has `/b`.
- [ ] **Step 2:** Run `go test ./internal/...`. Expected: FAIL (undefined symbols).
- [ ] **Step 3:** Implement the types, `Encode`/`Decode`, `Compose`, `Save`/`Load`, and the `testfs` helpers.
- [ ] **Step 4:** Run `go test ./internal/...`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: core types, path encoding, baseline codec`.

---

### Task 3: Path classifier and filesystem walker

**Files:**
- Create: `internal/classify/classify.go`, `internal/classify/classify_test.go`, `internal/collect/exclude.go`, `internal/collect/walk.go`, `internal/collect/walk_test.go`

**Interfaces:**
- Produces, in `classify`:
  ```go
  type Class struct { Category string; Severity model.Severity; KeepContent bool }
  func Path(p string) Class // p is a decoded absolute path
  ```
  The table is pinned below. The first match wins, globs use `path.Match` semantics extended so that `**` matches any depth, and `*` stands in for any home dir (`/root` or `/home/*`) in the user patterns:

  | Category | Severity | Patterns |
  |---|---|---|
  | `preload` | Critical | `/etc/ld.so.preload` |
  | `systemd-generator` | Critical | `/{etc,run,usr/lib,usr/local/lib}/systemd/{system,user}-generators/**` |
  | `systemd-unit` | High | `/{etc,run,usr/lib,usr/local/lib}/systemd/{system,user}/**`, `{home}/.config/systemd/user/**` |
  | `cron` | High | `/etc/crontab`, `/etc/cron.d/**`, `/etc/cron.{hourly,daily,weekly,monthly}/**`, `/var/spool/cron/crontabs/**` |
  | `at` | High | `/var/spool/cron/atjobs/**`, `/var/spool/at/**` |
  | `pkg-hook` | High | `/etc/apt/apt.conf.d/**`, `/etc/dpkg/dpkg.cfg.d/**`, `/var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm}` |
  | `ssh-key` | High | `{home}/.ssh/authorized_keys*`, `/etc/ssh/authorized_keys/**` |
  | `sudo` | Critical | `/etc/sudoers`, `/etc/sudoers.d/**` |
  | `sshd` | Critical | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/**` |
  | `pam` | Critical | `/etc/pam.d/**`, `/etc/security/**`, `/usr/lib/x86_64-linux-gnu/security/**` (KeepContent false for this last `.so` dir) |
  | `kmod-config` | Critical | `/etc/modules`, `/etc/modules-load.d/**`, `/etc/modprobe.d/**`, `/usr/lib/modules-load.d/**` |
  | `login-hook` | High | `/etc/update-motd.d/**`, `/etc/rc.local`, `/etc/profile`, `/etc/profile.d/**`, `/etc/bash.bashrc`, `/etc/environment`, `{home}/.{bashrc,profile,bash_profile,bash_login,bash_logout,zshrc}` |
  | `resolver` | High | `/etc/nsswitch.conf`, `/etc/hosts`, `/etc/resolv.conf`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/**` |
  | `udev` | High | `/etc/udev/rules.d/**`, `/usr/lib/udev/rules.d/**` |
  | `mail` | High | `/etc/aliases`, `/etc/postfix/**`, `{home}/.forward` |
  | `account-db` | Medium | `/etc/{passwd,shadow,group,gshadow}` |
  | `system-binary` | High | `/usr/{bin,sbin,lib,lib64,libexec,local/bin,local/sbin}/**`, `/opt/**` (KeepContent false) |
  | `file` | Medium | everything else (KeepContent false) |

  KeepContent is true for every row except those marked false.
- Produces, in `collect`:
  - `func Walk(root string) (files map[string]baseline.FileEntry, errs []string)`. It covers the whole tree under `root` except `Excluded`. It uses `filepath.WalkDir` and `os.Lstat`, never follows symlinks, and reads `Link` with `os.Readlink`. It opens a file (`O_RDONLY|O_NOFOLLOW|O_NONBLOCK`) only if `Lstat` reports a regular file. It hashes with a streaming SHA-256, reads `Caps` with `unix.Lgetxattr(..., "security.capability")`, and keeps `Content` only when `classify.Path(p).KeepContent && size <= 65536`. A file that vanishes (`ENOENT`) is skipped silently. Any other error sets `FileEntry.Err` and appends to `errs`.
  - `var Excluded []string` holds pinned prefixes relative to root, skipped entirely: `/proc`, `/sys`, `/dev` (but `/dev/shm` is walked), `/run/user`, `/run/udev`, `/run/systemd/journal`, `/var/log`, `/var/cache`, `/var/tmp/systemd-private-*`, `/tmp/systemd-private-*`, `/var/lib/apt/lists`, `/var/lib/docker`, `/var/lib/containerd`, `/var/lib/snapd`, `/snap`, `/var/lib/systemd`, `/var/lib/dhcp`, `/var/lib/cloud`, `/var/lib/mysql`, `/var/spool/postfix`, `/var/backups`, `/lost+found`.
  - `var Ignored []string` holds per-instance files that are walked but dropped from the result: `/etc/machine-id`, `/var/lib/dbus/machine-id`, `/etc/hostname`, `/etc/ssh/ssh_host_*`, `/etc/netplan/**`, `/etc/cloud/**`, `/etc/ld.so.cache`, `/etc/mtab`, `/etc/adjtime`, `/etc/.pwd.lock`. (The VM clean-rescan in Task 9 is the authority here. Extend these lists only with paths it proves volatile, and record why in a comment.)

- [ ] **Step 1: Write failing tests.**
  - `TestPath_Table`: table-driven, asserting the category for `/etc/ld.so.preload`→`preload`, `/usr/lib/systemd/system-generators/x`→`systemd-generator`, `/home/bob/.config/systemd/user/a.timer`→`systemd-unit`, `/root/.ssh/authorized_keys2`→`ssh-key`, `/var/lib/dpkg/info/foo.postinst`→`pkg-hook`, `/home/bob/.forward`→`mail`, `/usr/bin/ls`→`system-binary` (KeepContent false), `/srv/x`→`file`.
  - `TestWalk_Basic`: a fixture with `/etc/crontab` (`"* * * * * root x\n"`, 0644) and `/usr/bin/tool` (0755 plus setuid). Assert the crontab entry has the right SHA256 and non-nil `Content`, the tool entry has `Mode&os.ModeSetuid != 0` and nil `Content`, and the map key is `/etc/crontab` (root prefix stripped).
  - `TestWalk_SymlinkNotFollowed`: `/etc/cron.d/x -> /dev/zero`. The entry has `Type=='l'`, `Link=="/dev/zero"`, empty SHA256, and the walk returns within 2s.
  - `TestWalk_FifoAndUnreadable`: a fifo at `/tmp/f` gets `Type=='o'` with no hang. A file with mode 0000 at `/etc/secret`: when the test runs as non-root, `Err != ""` and `len(errs)==1`. Skip the unreadable half when `os.Geteuid()==0`.
  - `TestWalk_Excluded`: files under `/proc/1/x`, `/var/log/a` and `/etc/machine-id` are absent, and `/dev/shm/evil` is present.
- [ ] **Step 2:** Run `go test ./internal/classify/ ./internal/collect/`. Expected: FAIL.
- [ ] **Step 3:** Implement `classify.Path` (brace expansion is done when the table is built, and a small `**` matcher splits on `/`) and `collect.Walk`.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: path classifier and filesystem walker`.

---

### Task 4: Accounts and modules collectors, Snapshot

**Files:**
- Create: `internal/collect/accounts.go`, `internal/collect/modules.go`, `internal/collect/snapshot.go`, `internal/collect/accounts_test.go`, `internal/collect/snapshot_test.go`

**Interfaces:**
- Produces:
  - `func ParsePasswd(r io.Reader) []baseline.Account` fills Name/UID/GID/Home/Shell and skips malformed lines (wrong field count, non-numeric uid).
  - `func ApplyShadow(accts []baseline.Account, r io.Reader)` sets PwState: `""`→`"none"`, a leading `!` or `*`→`"locked"`, otherwise `"set"`. It also sets `PwDigest` = sha256 hex of the password field.
  - `func ParseGroup(r io.Reader) []baseline.Group`.
  - `func Modules(root string) []string` reads `root/proc/modules`, returning the first field of each line, sorted, or nil if the file is absent.
  - `func Snapshot(root string) (*baseline.Baseline, error)` combines Walk, accounts (from `root/etc/{passwd,shadow,group}`), Modules, Host (from `root/etc/hostname`, trimmed), OSRelease (the `VERSION` value from `root/etc/os-release`), `CapturedAt=time.Now().UTC()` and `Schema=1`.
  - Note for Task 9: in the VM, `root` is `/`, so `/proc/modules` is the live one.

- [ ] **Step 1: Write failing tests.**
  - `TestParsePasswd_Malformed`: given the input `"root:x:0:0:root:/root:/bin/bash\ngarbage\nbob:x:abc:1::/h:/bin/sh\ntoor:x:0:0::/root:/bin/bash\n"`, the result is exactly `root` and `toor`, both with UID 0.
  - `TestApplyShadow_States`: `a:!:…`→locked, `b::…`→none, `c:$6$x:…`→set with a 64-char digest.
  - `TestModules_AbsentIsNil`: an empty root gives `nil`. A root with `/proc/modules` containing `"nf_tables 1 0 - Live 0x0\nbpf 2 0 - Live 0x0\n"` gives `["bpf","nf_tables"]`.
  - `TestSnapshot_Fixture`: a fixture with passwd, shadow, group, hostname, os-release (`VERSION="24.04.3 LTS (Noble Numbat)"`) and one cron file. Assert Host, OSRelease, `len(Accounts)`, the cron file present in Files, and `Schema==1`.
- [ ] **Step 2:** Run `go test ./internal/collect/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: accounts/modules collectors and snapshot`.

---

### Task 5: File diff

**Files:**
- Create: `internal/diff/diff.go`, `internal/diff/diff_test.go`

**Interfaces:**
- Consumes: `baseline.Baseline`, `classify.Path`, `pathenc.Decode`, `model.Finding`.
- Produces: `func Diff(base, live *baseline.Baseline) []model.Finding`, sorted by Severity descending, then Subject. File rules:
  - **Added:** in live but not base. Category and severity come from `classify.Path`. If the new file has setuid, setgid or non-empty `Caps`, the category becomes `privilege` and the severity Critical.
  - **Altered:** in both, with any compared field different. Compared fields: Type, SHA256, Link, Caps, `Mode`, UID, GID. When the base entry is `HashOnly`, compare only Type/SHA256/Link. Severity comes from classify, but gaining setuid/setgid/caps forces `privilege`/Critical. `Detail` names the changed fields, e.g. `"sha256, mode 0755→4755"`. `Diff` is a unified diff (`difflib.UnifiedDiff`, 3 context lines, `FromFile`/`ToFile` = `baseline`/`live`) when both sides have `Content`.
  - **Removed:** in base but not live. Severity is Medium for `system-binary`/`file`, otherwise the classify severity lowered one step.
  - Before/After hold the sha256 for regular files and the link target for symlinks.
  - Entries with `Err != ""` on either side produce no finding.

- [ ] **Step 1: Write failing tests.**
  - `TestDiff_AddedCron`: live adds `/etc/cron.d/evil`. Expect one finding: added, `cron`, High.
  - `TestDiff_AlteredSshdHasUnifiedDiff`: `/etc/ssh/sshd_config` content changes from `"PasswordAuthentication no\n"` to `"PasswordAuthentication yes\n"`. Expect altered, `sshd`, Critical, and `Diff` containing `-PasswordAuthentication no` and `+PasswordAuthentication yes`.
  - `TestDiff_SuidGainedIsPrivilege`: `/usr/bin/find` Mode goes from 0755 to 0755|setuid. Expect `privilege`, Critical, and Detail containing `mode`.
  - `TestDiff_NewSuidInTmp`: `/var/tmp/.x` added with setuid. Expect `privilege`, Critical.
  - `TestDiff_HashOnlyIgnoresMode`: base `HashOnly` with the same sha, live with a different mode/uid. Expect no findings.
  - `TestDiff_Removed`: base has `/etc/sudoers.d/ok` and live doesn't. Expect removed, `sudo`, High (Critical lowered one step).
  - `TestDiff_Identical`: `Diff(b, b)` is empty.
- [ ] **Step 2:** Run `go test ./internal/diff/`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run the tests. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: file diff engine`.

---

### Task 6: Account, group and module diff

**Files:**
- Create: `internal/diff/accounts.go`, `internal/diff/accounts_test.go`
- Modify: `internal/diff/diff.go` so that `Diff` also appends these findings

**Interfaces:**
- Produces (unexported, called from `Diff`): account, group and module findings with these pinned rules:
  - New account: `account`, High. If the UID is 0 and the name is not `root`: Critical, with Detail `"uid 0"`.
  - Existing account whose UID changes to 0: Critical.
  - Account removed: Medium.
  - Shell changes from `nologin`/`false` to anything else: High.
  - PwState or PwDigest changed: High, with Detail `"password changed"`. Digests are never put in Before/After.
  - Home or GID changed: Medium.
  - New member in a privileged group (`root`, `sudo`, `adm`, `docker`, `shadow`, `disk`, `lxd`): `group`, Critical. A new member in another group: Low. A new group: Medium.
  - New loaded module (only when both Modules are non-nil): `module`, Critical. Module unloaded: Low.

- [ ] **Step 1: Write failing tests.**
  - `TestDiffAccounts_SecondUID0`: `toor` UID 0 added gives Critical, Detail containing `uid 0`.
  - `TestDiffAccounts_NologinToBash`: `www-data` shell goes from `/usr/sbin/nologin` to `/bin/bash`. Expect High.
  - `TestDiffAccounts_PasswordChanged`: the digest differs. Expect High, with Before and After empty.
  - `TestDiffGroups_SudoMember`: `sudo` gains `mallory`. Expect Critical.
  - `TestDiffModules_NilSkips`: base Modules nil, live `["diamorphine"]`. Expect no module finding. With base `["bpf"]` and live `["bpf","diamorphine"]`: Critical.
- [ ] **Step 2:** Run. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `go test ./internal/diff/`. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: account, group and module diff`.

---

### Task 7: Package layer from .deb files

**Files:**
- Create: `internal/debhash/deb.go`, `internal/debhash/status.go`, `internal/debhash/layer.go`, `internal/debhash/debhash_test.go`

**Interfaces:**
- Produces:
  ```go
  type DebFile struct { Path string /* normalized absolute */; Type baseline.FileType; Mode uint32; SHA256, Link string }
  type Deb struct { Package, Version, Arch string; Files []DebFile }
  func ParseDeb(r io.Reader) (*Deb, error)
  type Installed struct { Package, Version, Arch string }
  func ParseStatus(r io.Reader) []Installed // only stanzas with "Status: install ok installed"
  func Layer(debs []*Deb) *baseline.Baseline // LayerPackage, HashOnly=true, keys pathenc-encoded
  ```
  - `ParseDeb` reads the `ar` format directly: the `!<arch>\n` magic, then 60-byte member headers, with data padded to even length. In `control.tar.{gz,xz,zst}` it parses the `control` file for Package/Version/Architecture. In `data.tar.{gz,xz,zst}` it records each entry. Uncompressed `.tar` is also accepted.
  - Path normalization: strip a leading `./`, make the path absolute, and rewrite the `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64` and `/libx32` prefixes to `/usr/...` (usr-merge on 24.04).
  - Hardlink tar entries take the target's hash.
  - Mode is the tar mode bits converted to `os.FileMode` bits.

- [ ] **Step 1: Write failing tests.** A test helper `buildDeb(t, pkg, ver string, files map[string]string, comp string) []byte` writes the ar container and a tar per member using `archive/tar` plus the chosen compressor.
  - `TestParseDeb_Gzip`, `TestParseDeb_Xz`, `TestParseDeb_Zstd`: Package/Version are parsed, and the file `./usr/sbin/postfix` with content `"bin"` gets Path `/usr/sbin/postfix` and the SHA256 of `"bin"`.
  - `TestParseDeb_UsrMerge`: the entry `./bin/foo` gets Path `/usr/bin/foo`, and `./lib/x/y` gets `/usr/lib/x/y`.
  - `TestParseStatus`: a two-stanza fixture where one stanza has `Status: deinstall ok config-files`. Only the installed one is returned.
  - `TestLayer_HashOnly`: every entry has `HashOnly==true` and `Layer==baseline.LayerPackage`.
  - `TestParseDeb_Garbage`: random bytes return an error, not a panic.
- [ ] **Step 2:** Run `go test ./internal/debhash/`. Expected: FAIL.
- [ ] **Step 3:** Implement, using `go get github.com/klauspost/compress github.com/ulikunitz/xz`.
- [ ] **Step 4:** Run. Expected: PASS.
- [ ] **Step 5:** Commit: `feat: package layer from .deb files`.

---

### Task 8: CLI commands and embedded baseline

**Files:**
- Create: `internal/baseline/embedded.go`, `internal/baseline/data/base.json.gz`
- Modify: `internal/cli/cli.go`, `internal/cli/cli_test.go`

**Interfaces:**
- Consumes: `collect.Snapshot`, `diff.Diff`, `baseline.{Save,Load,Compose}`, `debhash.{ParseDeb,ParseStatus,Layer}`.
- Produces:
  - `func Embedded() (*baseline.Baseline, error)` decodes the `//go:embed data/base.json.gz` bytes.
  - Subcommands:
    - `capture --root DIR --out FILE [--layer base|triage]` writes `Snapshot(root)` with every entry's Layer set. Exit 0.
    - `pkglist --root DIR` prints `package=version arch` per installed package, sorted, from `root/var/lib/dpkg/status`. This is what the agent reports at T-0.
    - `pkghash --debs DIR --out FILE` parses every `*.deb` in DIR into a package-layer baseline. It runs on the jump box.
    - `scan --root DIR [--baseline FILE]... [--json]` builds the base from the `--baseline` files composed in order, or `Embedded()` when none is given, diffs it against `Snapshot(root)` and prints the findings. Exit 1 if there are any findings, 0 if none, 2 on error.
      - Text output: one line per finding, `SEVERITY<TAB>KIND<TAB>CATEGORY<TAB>SUBJECT<TAB>DETAIL` (severity upper-case). When `Diff` is non-empty, the diff follows, indented 4 spaces.
      - `--json`: a JSON array of `model.Finding` with lower-case keys (add json tags: `kind, category, severity, subject, detail, before, after, diff`; severity as its string).

- [ ] **Step 1:** Generate the placeholder embedded baseline: write a one-off test `TestWriteEmptyEmbedded` guarded by `if os.Getenv("XDR_GEN_EMBED") == ""` { t.Skip() }. It writes an empty Schema 1 baseline to `internal/baseline/data/base.json.gz`. Run `XDR_GEN_EMBED=1 go test ./internal/baseline/ -run TestWriteEmptyEmbedded`.
- [ ] **Step 2: Write failing tests** in `cli_test.go`, using testfs fixtures and temp files:
  - `TestCaptureThenScan_Clean`: capture the fixture, then scan with `--baseline` set to that file. Exit 0 and empty output.
  - `TestCaptureThenScan_Planted`: capture, then add `/etc/cron.d/evil`, append `toor:x:0:0::/root:/bin/bash` to passwd, and change `/etc/ssh/sshd_config`, then scan. Exit 1. The output contains the lines for `CRITICAL\tadded\taccount\ttoor`, `CRITICAL\taltered\tsshd\t/etc/ssh/sshd_config` and `HIGH\tadded\tcron\t/etc/cron.d/evil`.
  - `TestScan_JSON`: the same planted fixture with `--json` unmarshals into `[]map[string]any` with `len==4` (the three planted items plus `altered account-db /etc/passwd`) and `severity=="critical"` on the first entry.
  - `TestScan_LayerCompose`: base capture, then a triage capture after planting the cron file, then scan with `--baseline base --baseline triage`. Exit 0.
  - `TestPkglist`: fixture `var/lib/dpkg/status` with two installed packages. Output `"a=1.0 amd64\nb=2.0 all\n"`.
  - `TestScan_BadBaseline`: `--baseline /nonexistent` gives exit 2.
- [ ] **Step 3:** Run `go test ./internal/cli/`. Expected: FAIL.
- [ ] **Step 4:** Implement with the `flag` package (one `FlagSet` per subcommand; a repeatable `--baseline` via a `flag.Value` string slice).
- [ ] **Step 5:** Run `make test`. Expected: all PASS. Run `make build`.
- [ ] **Step 6:** Commit: `feat: capture/scan/pkglist/pkghash commands and embedded baseline`.

---

### Task 9: Ubuntu 24.04 VM harness

**Files:**
- Create: `test/vm/e2e.sh`, `test/vm/plant.sh`, `test/vm/expected.txt`
- Modify: `Makefile` (target `e2e: build` → `test/vm/e2e.sh`), `internal/collect/exclude.go` (only if the clean rescan proves extra volatile paths)

**Interfaces:**
- Consumes: `bin/xdr` (Task 8).
- `e2e.sh`, with `set -euo pipefail`:
  1. `lxc launch ubuntu:24.04 xdr-e2e --vm`, then wait until `lxc exec xdr-e2e -- systemctl is-system-running --wait` returns.
  2. Push `bin/xdr` to `/usr/local/sbin/xdr`, then capture `/root/base.json.gz`.
  3. **clean-rescan:** sleep 60s, then run `xdr scan --root / --baseline /root/base.json.gz`. This must exit 0. Otherwise print the findings and fail.
  4. Push and run `plant.sh`, which as root creates:
     - `/etc/cron.d/updater`;
     - user `toor` with UID 0 (`useradd -o -u 0 -g 0 toor`);
     - `/etc/ld.so.preload` pointing at `/usr/lib/libz.so.1.bak` (it creates an empty file there first, so the box stays usable);
     - a new line in `/root/.ssh/authorized_keys`;
     - `cp /bin/bash /var/tmp/.b && chmod u+s /var/tmp/.b`;
     - `/etc/systemd/system/snapd-refresh-helper.{service,timer}`;
     - `/etc/apt/apt.conf.d/99update` containing `APT::Update::Pre-Invoke {"/var/tmp/.b -p";};`;
     - `echo 'support: "|/var/tmp/.b"' >> /etc/aliases`;
     - `sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config`;
     - `setcap cap_setuid+ep /usr/bin/python3.12`.
  5. Scan again. It must exit 1, and every line of `expected.txt` must appear as a substring (`grep -F -f`). `expected.txt` holds one `KIND\tCATEGORY\tSUBJECT` fragment per planted item, for example `added\tcron\t/etc/cron.d/updater`, `added\taccount\ttoor`, `added\tpreload\t/etc/ld.so.preload`, `added\tprivilege\t/var/tmp/.b` and `altered\tprivilege\t/usr/bin/python3.12`.
  6. `lxc delete --force xdr-e2e` runs in a `trap` on EXIT.

- [ ] **Step 1:** Write `plant.sh` and `expected.txt`.
- [ ] **Step 2:** Write `e2e.sh`.
- [ ] **Step 3:** Run `make e2e`. Expected on the first run: the clean-rescan step may FAIL and list volatile paths.
- [ ] **Step 4:** For each path the clean rescan flags, add it to `Excluded` or `Ignored` with a one-line comment saying why it changes on a clean box. Never add a path that a persistence category in Task 3 covers; if one shows up, report it instead of excluding it. Re-run `make test` and then `make e2e`.
- [ ] **Step 5:** Run `make e2e`. Expected: clean-rescan exits 0, the planted scan exits 1, all expected fragments are present, and the script prints `E2E PASS`.
- [ ] **Step 6:** Commit: `test: ubuntu 24.04 VM harness for baseline engine`.

---

## Done when

- `make test` and `make e2e` both pass.
- `bin/xdr` is statically linked.
- `xdr scan` on a clean 24.04 VM reports nothing.
- `xdr scan` on the same VM after `plant.sh` reports every planted item.
