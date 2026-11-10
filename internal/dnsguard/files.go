// Package dnsguard keeps name resolution on the box under the agent's
// control: the resolver files are pinned, and the only resolver is a stub
// that answers for an allow-list.
package dnsguard

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"xdr/internal/collect"
	"xdr/internal/config"
)

const (
	hostsPath    = "/etc/hosts"
	nsswitchPath = "/etc/nsswitch.conf"
	resolvPath   = "/etc/resolv.conf"

	fileMode = 0o644
	maxFile  = 1 << 20
)

// Assert brings /etc/hosts, /etc/nsswitch.conf and /etc/resolv.conf under
// root to the content the config calls for, and returns the paths it had to
// rewrite. Each file is replaced by rename, so whatever sits at the path —
// a symlink, a fifo — is replaced, never followed or opened.
func Assert(root string, c *config.Config, now time.Time) (changed []string, err error) {
	want := []struct {
		path    string
		content func(old []byte) []byte
	}{
		{hostsPath, func([]byte) []byte { return hosts(c) }},
		{nsswitchPath, func(old []byte) []byte { return nsswitch(old, c.DNSOn(now)) }},
		{resolvPath, func([]byte) []byte { return resolv(c) }},
	}
	var errs []string
	for _, w := range want {
		full := filepath.Join(root, w.path)
		old, ok := current(full)
		content := w.content(old)
		if ok && bytes.Equal(old, content) {
			continue
		}
		if err := replace(full, content); err != nil {
			errs = append(errs, err.Error())
			continue
		}
		changed = append(changed, w.path)
	}
	if errs != nil {
		return changed, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return changed, nil
}

// current returns the file's content. ok is false when the path is not a
// regular file of the right mode, whatever its content.
func current(full string) (content []byte, ok bool) {
	st, err := os.Lstat(full)
	if err != nil || !st.Mode().IsRegular() {
		return nil, false
	}
	content, err = collect.ReadFile(full, maxFile)
	if err != nil {
		return nil, false
	}
	return content, st.Mode().Perm() == fileMode
}

func replace(full string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(full), ".xdr-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	_, err = tmp.Write(content)
	if err == nil {
		err = tmp.Chmod(fileMode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), full)
}

// hosts is the whole of /etc/hosts: nothing in it but what the config names.
func hosts(c *config.Config) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "127.0.0.1 localhost\n127.0.1.1 %s\n::1 localhost ip6-localhost ip6-loopback\n", c.Host)
	names := make([]string, 0, len(c.DNS.Hosts))
	for name := range c.DNS.Hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "%s %s\n", c.DNS.Hosts[name], name)
	}
	return []byte(b.String())
}

// nsswitch is old with its hosts line set: files only, or files then dns.
func nsswitch(old []byte, dnsOn bool) []byte {
	line := "hosts:          files"
	if dnsOn {
		line += " dns"
	}
	var out []string
	done := false
	for _, l := range strings.Split(strings.TrimSuffix(string(old), "\n"), "\n") {
		if isHostsLine(l) {
			if !done {
				out = append(out, line)
				done = true
			}
			continue
		}
		out = append(out, l)
	}
	if len(old) == 0 {
		out = nil
	}
	if !done {
		out = append(out, line)
	}
	return []byte(strings.Join(out, "\n") + "\n")
}

// isHostsLine reports whether l sets the hosts database, as glibc reads it.
func isHostsLine(l string) bool {
	rest, ok := strings.CutPrefix(strings.TrimLeft(l, " \t"), "hosts")
	return ok && strings.HasPrefix(strings.TrimLeft(rest, " \t"), ":")
}

func resolv(c *config.Config) []byte {
	addr := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if ap, err := netip.ParseAddrPort(c.DNS.Listen); err == nil {
		addr = ap.Addr()
	}
	return []byte(fmt.Sprintf("nameserver %s\noptions timeout:1 attempts:1\n", addr))
}
