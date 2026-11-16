package dnsguard

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"xdr/internal/collect"
)

// The three files the pin replaces, by the name each keeps in the backup.
var pinned = []struct{ name, path string }{
	{"hosts", hostsPath}, {"nsswitch", nsswitchPath}, {"resolv", resolvPath},
}

// LooksPinned reports whether /etc/resolv.conf under root is the one the
// pin writes: a stub address and the stub's timeouts.
func LooksPinned(root string) bool {
	b, ok := current(filepath.Join(root, resolvPath))
	return ok && bytes.Contains(b, []byte("options timeout:1 attempts:1\n")) && bytes.HasPrefix(b, []byte("nameserver 127."))
}

// Save keeps the three files as they are in backup, to put them back when
// the pin is turned off. It does nothing when a backup is already there, or
// when the box is already pinned (those are not the originals).
func Save(root, backup string) error {
	if _, err := os.Lstat(backup); err == nil || LooksPinned(root) {
		return nil
	}
	tmp := backup + ".tmp"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return err
	}
	for _, f := range pinned {
		full := filepath.Join(root, f.path)
		st, err := os.Lstat(full)
		switch {
		case err != nil:
			err = os.WriteFile(filepath.Join(tmp, f.name+".absent"), nil, 0o600)
			if err != nil {
				return err
			}
		case st.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(full)
			if err == nil {
				err = os.WriteFile(filepath.Join(tmp, f.name+".link"), []byte(target), 0o600)
			}
			if err != nil {
				return err
			}
		case st.Mode().IsRegular():
			b, err := collect.ReadFile(full, maxFile)
			if err == nil {
				err = os.WriteFile(filepath.Join(tmp, f.name+".file"), b, 0o600)
			}
			if err == nil {
				err = os.WriteFile(filepath.Join(tmp, f.name+".mode"), []byte(strconv.FormatUint(uint64(st.Mode().Perm()), 8)), 0o600)
			}
			if err != nil {
				return err
			}
		}
	}
	return os.Rename(tmp, backup)
}

// Restore puts the files Save kept back, returns the paths it restored and
// removes the backup. With no backup it does nothing.
func Restore(root, backup string) (restored []string, err error) {
	if _, serr := os.Lstat(backup); serr != nil {
		return nil, nil
	}
	var errs []string
	for _, f := range pinned {
		full := filepath.Join(root, f.path)
		var rerr error
		switch {
		case exists(filepath.Join(backup, f.name+".absent")):
			rerr = os.Remove(full)
			if os.IsNotExist(rerr) {
				rerr = nil
			}
		case exists(filepath.Join(backup, f.name+".link")):
			var target []byte
			if target, rerr = os.ReadFile(filepath.Join(backup, f.name+".link")); rerr == nil {
				rerr = replaceLink(full, string(target))
			}
		case exists(filepath.Join(backup, f.name+".file")):
			var b, m []byte
			if b, rerr = os.ReadFile(filepath.Join(backup, f.name+".file")); rerr == nil {
				m, _ = os.ReadFile(filepath.Join(backup, f.name+".mode"))
				mode, perr := strconv.ParseUint(strings.TrimSpace(string(m)), 8, 32)
				if perr != nil {
					mode = fileMode
				}
				rerr = replaceMode(full, b, os.FileMode(mode))
			}
		default:
			continue
		}
		if rerr != nil {
			errs = append(errs, rerr.Error())
			continue
		}
		restored = append(restored, f.path)
	}
	if errs != nil {
		return restored, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return restored, os.RemoveAll(backup)
}

func exists(p string) bool { _, err := os.Lstat(p); return err == nil }

func replaceLink(full, target string) error {
	tmp := filepath.Join(filepath.Dir(full), ".xdr-link")
	os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}
