package sshgate

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"xdr/internal/config"
)

// T0 is the gray accounts' authentication settings as sshd -T printed
// them at T-0: the gate tightens the global defaults and keeps these for
// them alone.
type T0 struct {
	Password, KbdInteractive, Pubkey, Methods string
}

// netString is n as sshd's USER@HOST takes it: a single host bare.
func netString(n config.Net) string {
	if n.Bits() == n.Addr().BitLen() {
		return n.Addr().String()
	}
	return n.Prefix.String()
}

// RenderSSHD is sshd_config: a header, the baseline's file unchanged, a
// trailer. sshd keeps the first value it reads for a keyword, so the
// header overrides the base and every drop-in it includes. The trailer
// starts with "Match all" so that no Match block left open in the base
// captures it.
func RenderSSHD(base []byte, cfg *config.Config, t0 T0) []byte {
	s := cfg.SSH
	var b bytes.Buffer
	b.WriteString("# Written by xdr from the signed config and the baseline; edits are undone.\n")
	b.WriteString("PasswordAuthentication no\nKbdInteractiveAuthentication no\nPermitRootLogin prohibit-password\nPubkeyAuthentication yes\nUsePAM yes\n")
	pinned := append(append([]string{"root"}, s.Blue...), s.Auto...)
	if s.Recovery != "" {
		pinned = append(pinned, s.Recovery)
	}
	b.WriteString("AllowUsers")
	for _, u := range pinned {
		for _, j := range cfg.Jump {
			fmt.Fprintf(&b, " %s@%s", u, netString(j))
		}
	}
	for _, u := range cfg.GrayUsers {
		fmt.Fprintf(&b, " %s", u)
	}
	b.WriteString("\n\n")
	b.Write(base)
	if len(base) > 0 && base[len(base)-1] != '\n' {
		b.WriteByte('\n')
	}
	b.WriteString("\n# xdr: per-account rules.\nMatch all\n")
	if len(cfg.GrayUsers) > 0 {
		fmt.Fprintf(&b, "Match User %s\n", strings.Join(cfg.GrayUsers, ","))
		for _, kv := range [][2]string{{"PasswordAuthentication", t0.Password}, {"KbdInteractiveAuthentication", t0.KbdInteractive}, {"PubkeyAuthentication", t0.Pubkey}} {
			if kv[1] != "" {
				fmt.Fprintf(&b, "\t%s %s\n", kv[0], kv[1])
			}
		}
		if t0.Methods != "" && t0.Methods != "any" {
			fmt.Fprintf(&b, "\tAuthenticationMethods %s\n", t0.Methods)
		}
	}
	if s.Recovery != "" {
		fmt.Fprintf(&b, "Match User %s\n\tAuthenticationMethods publickey\n", s.Recovery)
	}
	return b.Bytes()
}

// RenderPAM is the baseline's /etc/pam.d/sshd with the gate after its
// "@include common-session": the gray and recovery accounts skip it, so
// they log in with the agent dead; for everyone else a refusal by
// `xdr gate` fails the session.
func RenderPAM(base []byte, cfg *config.Config, gateExe string) ([]byte, error) {
	lines := strings.SplitAfter(string(base), "\n")
	at := -1
	for i, l := range lines {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "@include" && f[1] == "common-session" {
			at = i
			break
		}
	}
	if at < 0 {
		return nil, fmt.Errorf("sshgate: the baseline pam.d/sshd has no @include common-session")
	}
	exempt := append([]string(nil), cfg.GrayUsers...)
	if cfg.SSH.Recovery != "" {
		exempt = append(exempt, cfg.SSH.Recovery)
	}
	var gate strings.Builder
	if !strings.HasSuffix(lines[at], "\n") {
		gate.WriteString("\n")
	}
	if len(exempt) > 0 {
		fmt.Fprintf(&gate, "session [success=1 default=ignore] pam_succeed_if.so quiet user in %s\n", strings.Join(exempt, ":"))
	}
	fmt.Fprintf(&gate, "session required pam_exec.so quiet %s gate\n", gateExe)
	out := strings.Join(lines[:at+1], "") + gate.String() + strings.Join(lines[at+1:], "")
	return []byte(out), nil
}

// ReleasePAM takes the gate RenderPAM added out of root's pam.d/sshd: the
// pam_exec line and the exemption line just before it. The off switch
// does this before the binary goes, since a gate that cannot run refuses
// every session but the gray and recovery accounts'. changed is false
// when there was no gate (or no file).
func ReleasePAM(root string) (changed bool, err error) {
	path := filepath.Join(root, pamSSHD)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	lines := strings.SplitAfter(string(b), "\n")
	isGate := func(l string) bool {
		f := strings.Fields(l)
		return len(f) == 6 && f[0] == "session" && f[1] == "required" && f[2] == "pam_exec.so" && f[3] == "quiet" && f[5] == "gate"
	}
	isExempt := func(l string) bool {
		return strings.HasPrefix(strings.TrimSpace(l), "session [success=1 default=ignore] pam_succeed_if.so quiet user in ")
	}
	var keep []string
	for i, l := range lines {
		if isGate(l) {
			changed = true
			continue
		}
		if isExempt(l) && i+1 < len(lines) && isGate(lines[i+1]) {
			continue
		}
		keep = append(keep, l)
	}
	if !changed {
		return false, nil
	}
	mode := fs.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	if err := writeFile(path, []byte(strings.Join(keep, "")), mode); err != nil {
		return false, err
	}
	return true, nil
}
