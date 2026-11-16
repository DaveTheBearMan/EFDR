package agent

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"xdr/internal/baseline"
	"xdr/internal/collect"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/proc"
)

// accounts acts on the accounts not in the baseline: one a person could
// log in to (a uid from 1000, a real shell) running nothing guarded is
// locked; any other is alerted on, once. The gray, recovery and platform
// accounts are left alone, and approved ones are unlocked. It also holds
// the recovery account's one key.
func (a *agent) accounts(s *proc.Snapshot) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cfg.SSH == nil {
		return
	}
	data, err := collect.ReadFile(filepath.Join(a.root, "etc/passwd"), 1<<20)
	if err != nil {
		return
	}
	a.initOrders()
	if a.userSaid == nil {
		a.userSaid = map[string]bool{}
	}
	base := a.baseUsers()
	ssh := a.cfg.SSH
	var recovery *baseline.Account
	for _, acc := range collect.ParsePasswd(bytes.NewReader(data)) {
		if acc.Bad {
			continue
		}
		if acc.Name == ssh.Recovery {
			recovery = &acc
			continue
		}
		if _, ok := base[acc.Name]; ok || slices.Contains(a.cfg.GrayUsers, acc.Name) || slices.Contains(ssh.Auto, acc.Name) {
			continue
		}
		if a.okUsers[acc.Name] {
			if a.disabled[acc.Name] {
				in := incident.Incident{Kind: "user-enabled", Action: "repaired", Severity: model.SevMedium, UID: acc.UID, User: acc.Name, Detail: "approved"}
				if err := a.run("usermod", "--unlock", "--expiredate", "", acc.Name); err != nil {
					in.Action, in.Detail = "alert", "approved, but unlocking failed: "+err.Error()
				} else {
					delete(a.disabled, acc.Name)
					a.saveOrders()
				}
				a.record(in)
			}
			continue
		}
		if a.disabled[acc.Name] || a.userSaid[acc.Name] {
			continue
		}
		a.userSaid[acc.Name] = true
		in := incident.Incident{UID: acc.UID, User: acc.Name, Detail: fmt.Sprintf("uid %d, shell %s", acc.UID, acc.Shell)}
		if acc.UID < firstUserUID || !loginShell(acc.Shell) || a.runsGuarded(s, acc.UID) {
			in.Kind, in.Action, in.Severity = "user-new", "alert", model.SevMedium
			a.record(in)
			continue
		}
		in.Kind, in.Action, in.Severity = "user-disabled", "repaired", model.SevHigh
		if err := a.run("usermod", "--lock", "--expiredate", "1", acc.Name); err != nil {
			in.Action, in.Detail = "kill-failed", in.Detail+"; usermod: "+err.Error()
		} else {
			a.disabled[acc.Name] = true
			a.saveOrders()
		}
		a.record(in)
	}
	a.holdRecovery(recovery)
}

// loginShell reports whether shell lets a person in.
func loginShell(shell string) bool {
	return shell != "" && !strings.HasSuffix(shell, "/nologin") && !strings.HasSuffix(shell, "/false") && shell != "/bin/sync"
}

// runsGuarded reports whether a scored service runs as uid.
func (a *agent) runsGuarded(s *proc.Snapshot, uid uint32) bool {
	if s == nil {
		return false
	}
	for _, p := range s.Procs {
		if p.UID == uid && a.pol.Guarded(s, p) {
			return true
		}
	}
	return false
}

// holdRecovery keeps the recovery account's authorized_keys at exactly
// its configured key.
func (a *agent) holdRecovery(acc *baseline.Account) {
	ssh := a.cfg.SSH
	if ssh.Recovery == "" {
		return
	}
	if acc == nil {
		if !a.recoverySaid {
			a.record(incident.Incident{Kind: "recovery-missing", Action: "alert", Severity: model.SevCritical, User: ssh.Recovery,
				Detail: "the recovery account is not in /etc/passwd"})
		}
		a.recoverySaid = true
		return
	}
	a.recoverySaid = false
	dir := filepath.Join(a.root, acc.Home, ".ssh")
	path := filepath.Join(dir, "authorized_keys")
	want := []byte(strings.TrimSpace(ssh.RecoveryKey) + "\n")
	got, err := collect.ReadFile(path, 1<<20)
	if st, serr := os.Lstat(path); err == nil && serr == nil && bytes.Equal(got, want) && st.Mode().Perm() == 0o600 {
		return
	}
	in := incident.Incident{Kind: "recovery-drift", Action: "repaired", Severity: model.SevHigh, UID: acc.UID, User: acc.Name, Detail: path + " restored"}
	if err := a.writeKeys(dir, path, want, acc.UID, acc.GID); err != nil {
		in.Action, in.Detail = "alert", path+": "+err.Error()
	}
	a.record(in)
}

// writeKeys replaces dir/authorized_keys (dir is a home's .ssh), owned by
// the account. The agent is root and the account owns what is written
// into, so nothing here follows a symlink: the home is opened, then .ssh
// beneath it, both O_NOFOLLOW, and the file is made fresh (O_EXCL, a
// random name) and renamed over the old one inside that directory.
func (a *agent) writeKeys(dir, path string, data []byte, uid, gid uint32) error {
	name := filepath.Base(path)
	if filepath.Dir(path) != dir {
		return fmt.Errorf("%s is not in %s", path, dir)
	}
	home, err := unix.Open(filepath.Dir(dir), unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("home %s: %w", filepath.Dir(dir), err)
	}
	defer unix.Close(home)
	if err := unix.Mkdirat(home, filepath.Base(dir), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	d, err := unix.Openat(home, filepath.Base(dir), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err) // a symlink, or not a directory
	}
	defer unix.Close(d)
	unix.Fchown(d, int(uid), int(gid))
	var tmp string
	var f int
	for range 8 {
		var rnd [6]byte
		rand.Read(rnd[:])
		tmp = "." + name + "." + hex.EncodeToString(rnd[:])
		f, err = unix.Openat(d, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
	}
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(f), tmp)
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		unix.Unlinkat(d, tmp, 0)
		return err
	}
	file.Chown(int(uid), int(gid))
	if err := unix.Renameat(d, tmp, d, name); err != nil {
		unix.Unlinkat(d, tmp, 0)
		return err
	}
	return nil
}
