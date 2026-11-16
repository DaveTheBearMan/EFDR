package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"xdr/internal/baseline"
	"xdr/internal/collect"
	"xdr/internal/creds"
	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/proc"
)

// runStdin runs a command with stdin; its error carries what it printed.
func runStdin(stdin []byte, name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdin = bytes.NewReader(stdin)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (a *agent) credsAppliedPath() string { return filepath.Join(a.state, "creds-applied") }

// onCreds takes in a credential set from the controller.
func (a *agent) onCreds(b []byte) {
	var s creds.Set
	if err := json.Unmarshal(b, &s); err != nil || s.ID == "" {
		a.record(incident.Incident{Kind: "creds-refused", Action: "alert", Severity: model.SevHigh, Detail: "credential set unreadable"})
		return
	}
	a.applyCreds(s)
}

// applyCreds applies a set not applied before: the system hashes through
// chpasswd -e, Samba's through pdbedit, authorized_keys, and new host
// keys. A gray account is refused, and so is one a scored service runs as
// unless its Samba hash comes too (its password is the service's). No
// hash goes into an incident.
func (a *agent) applyCreds(s creds.Set) {
	if b, err := collect.ReadFile(a.credsAppliedPath(), 256); err == nil && strings.TrimSpace(string(b)) == s.ID {
		return
	}
	accts := map[string]baseline.Account{}
	if data, err := collect.ReadFile(filepath.Join(a.root, "etc/passwd"), 1<<20); err == nil {
		for _, acc := range collect.ParsePasswd(bytes.NewReader(data)) {
			if !acc.Bad {
				accts[acc.Name] = acc
			}
		}
	}
	snap := a.snap
	if snap == nil {
		snap, _ = proc.Read(filepath.Join(a.root, "proc"))
	}
	var done, refused, failed []string
	refuse := func(name, why string) {
		refused = append(refused, name)
		a.record(incident.Incident{Kind: "creds-refused", Action: "alert", Severity: model.SevHigh, User: name, Detail: why})
	}
	names := make([]string, 0, len(s.Users))
	for n := range s.Users {
		names = append(names, n)
	}
	slices.Sort(names)
	var chpasswd bytes.Buffer
	var ok []string
	for _, n := range names {
		u := s.Users[n]
		acc, exists := accts[n]
		switch {
		case slices.Contains(a.cfg.GrayUsers, n):
			refuse(n, "a protected account")
		case !exists:
			refuse(n, "no such account")
		case u.NT == "" && a.runsGuarded(snap, acc.UID):
			refuse(n, "a scored service runs as it; its password belongs to the service")
		case strings.ContainsAny(u.Hash, ":\n") || !strings.HasPrefix(u.Hash, "$"):
			refuse(n, "not a crypt hash")
		default:
			fmt.Fprintf(&chpasswd, "%s:%s\n", n, u.Hash)
			ok = append(ok, n)
		}
	}
	if len(ok) > 0 {
		if err := a.runIn(chpasswd.Bytes(), "chpasswd", "-e"); err != nil {
			failed = append(failed, "chpasswd: "+err.Error())
			ok = nil
		}
	}
	for _, n := range ok {
		u, acc := s.Users[n], accts[n]
		if u.NT != "" {
			if err := a.run("pdbedit", "-u", n, "--set-nt-hash", u.NT); err != nil {
				failed = append(failed, n+" samba: "+err.Error())
			}
		}
		if u.Keys != nil {
			dir := filepath.Join(a.root, acc.Home, ".ssh")
			body := ""
			for _, k := range u.Keys {
				body += strings.TrimSpace(k) + "\n"
			}
			if err := a.writeKeys(dir, filepath.Join(dir, "authorized_keys"), []byte(body), acc.UID, acc.GID); err != nil {
				failed = append(failed, n+" keys: "+err.Error())
			}
		}
		done = append(done, n)
	}
	detail := fmt.Sprintf("set %s: done %s", s.ID, strings.Join(done, ","))
	if len(refused) > 0 {
		detail += "; refused " + strings.Join(refused, ",")
	}
	if s.HostKeys {
		fps, err := a.newHostKeys()
		if err != nil {
			failed = append(failed, "host keys: "+err.Error())
		} else {
			detail += "; host keys " + strings.Join(fps, " ")
		}
	}
	in := incident.Incident{Kind: "creds-applied", Action: "repaired", Severity: model.SevMedium, Detail: detail}
	if len(failed) > 0 {
		in.Action, in.Severity = "alert", model.SevHigh
		in.Detail += "; failed: " + strings.Join(failed, "; ")
	}
	a.record(in)
	if len(failed) == 0 {
		os.MkdirAll(a.state, 0o700)
		os.WriteFile(a.credsAppliedPath(), []byte(s.ID+"\n"), 0o600)
	}
}

// newHostKeys replaces the SSH host keys: the old ones are set aside, new
// ones made, and the old ones put back if that fails. It returns the new
// public keys' fingerprints.
func (a *agent) newHostKeys() ([]string, error) {
	sshDir := filepath.Join(a.root, "etc/ssh")
	old, _ := filepath.Glob(filepath.Join(sshDir, "ssh_host_*"))
	aside := filepath.Join(a.state, "hostkeys-old")
	os.RemoveAll(aside)
	if err := os.MkdirAll(aside, 0o700); err != nil {
		return nil, err
	}
	for _, p := range old {
		if err := moveAside(p, filepath.Join(aside, filepath.Base(p))); err != nil {
			return nil, err
		}
	}
	restore := func() {
		for _, p := range old {
			moveAside(filepath.Join(aside, filepath.Base(p)), p)
		}
	}
	if err := a.run("ssh-keygen", "-A", "-f", a.root); err != nil {
		restore()
		return nil, err
	}
	pubs, _ := filepath.Glob(filepath.Join(sshDir, "ssh_host_*_key.pub"))
	if len(pubs) == 0 {
		restore()
		return nil, fmt.Errorf("ssh-keygen made no keys")
	}
	var fps []string
	for _, p := range pubs {
		b, _ := collect.ReadFile(p, 16<<10)
		f := strings.Fields(string(b))
		if len(f) < 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		fps = append(fps, f[0]+"="+"SHA256:"+base64.RawStdEncoding.EncodeToString(sum[:]))
	}
	if err := a.run("systemctl", "try-reload-or-restart", "ssh.service"); err != nil {
		return fps, err
	}
	return fps, nil
}

func moveAside(from, to string) error {
	if err := os.Rename(from, to); err == nil {
		return nil
	}
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	st, err := os.Lstat(from)
	if err != nil {
		return err
	}
	if err := os.WriteFile(to, b, st.Mode().Perm()); err != nil {
		return err
	}
	return os.Remove(from)
}
