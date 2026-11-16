// Package sshgate is the SSH gate: it renders and holds sshd's and PAM's
// config, judges each logind session, and ends those not approved in
// time.
package sshgate

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"xdr/internal/collect"
)

// Session is one logind session, as its file under /run/systemd/sessions
// describes it.
type Session struct {
	ID, User, Service, Class, State, RemoteHost, Scope string
	UID                                                uint32
	Leader                                             int
	RemoteAddr                                         netip.Addr // REMOTE_HOST, when it is an address
}

// sessionID is a logind session id: the audit session id, or "c" and a
// counter when there is none.
var sessionID = regexp.MustCompile(`^c?[0-9]{1,10}$`)

// Sessions reads root/run/systemd/sessions. Files that are not a session
// (the .ref files and the rest) are skipped, as are ones it cannot read:
// a session can end while it is being read.
func Sessions(root string) ([]Session, error) {
	dir := filepath.Join(root, "run/systemd/sessions")
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Session
	for _, e := range ents {
		if !e.Type().IsRegular() || !sessionID.MatchString(e.Name()) {
			continue
		}
		data, err := collect.ReadFile(filepath.Join(dir, e.Name()), 64<<10)
		if err != nil {
			continue
		}
		out = append(out, parseSession(e.Name(), data))
	}
	return out, nil
}

func parseSession(id string, data []byte) Session {
	s := Session{ID: id}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		k, v, ok := bytes.Cut(sc.Bytes(), []byte("="))
		if !ok {
			continue
		}
		val := string(v)
		switch string(k) {
		case "USER":
			s.User = val
		case "UID":
			if n, err := strconv.ParseUint(val, 10, 32); err == nil {
				s.UID = uint32(n)
			}
		case "SERVICE":
			s.Service = val
		case "CLASS":
			s.Class = val
		case "STATE":
			s.State = val
		case "REMOTE_HOST":
			s.RemoteHost = val
			if a, err := netip.ParseAddr(val); err == nil {
				s.RemoteAddr = a.Unmap()
			}
		case "LEADER":
			s.Leader, _ = strconv.Atoi(val)
		case "SCOPE":
			s.Scope = val
		}
	}
	return s
}

// Runner runs a command to completion.
type Runner func(name string, args ...string) error

// Terminate ends session id: logind kills every process in it.
func Terminate(run Runner, id string) error {
	if !sessionID.MatchString(id) {
		return fmt.Errorf("sshgate: %q is not a session id", id)
	}
	return run("loginctl", "terminate-session", id)
}
