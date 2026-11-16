package cli

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xdr/internal/breakglass"
	"xdr/internal/rules"
	"xdr/internal/sshgate"
)

func TestMint_Windows(t *testing.T) {
	dir, _ := fleetConfig(t)
	out := filepath.Join(t.TempDir(), "tokens")
	var so, se bytes.Buffer
	args := []string{"controller", "mint-breakglass", "--dir", dir, "--hosts", "web01", "--action", "pause", "--from", "2026-11-14T08:00:00Z", "--every", "2h", "--count", "3", "--out", out}
	if code := Run(args, &so, &se); code != 0 {
		t.Fatalf("mint: %d %s", code, se.String())
	}
	files, _ := filepath.Glob(filepath.Join(out, "web01-pause-*.tok"))
	if len(files) != 3 {
		t.Fatalf("files %v", files)
	}
	pub, _ := rules.LoadPublic(filepath.Join(dir, "rules.pub"))
	from := time.Date(2026, 11, 14, 8, 0, 0, 0, time.UTC)
	ids := map[string]bool{}
	for i, f := range files {
		b, _ := os.ReadFile(f)
		tk, err := breakglass.Parse(string(b), pub)
		if err != nil {
			t.Fatal(err)
		}
		want := from.Add(time.Duration(i) * 2 * time.Hour)
		if !tk.NotBefore.Equal(want) || !tk.Expires.Equal(want.Add(2*time.Hour)) || tk.Host != "web01" || tk.Action != "pause" {
			t.Fatalf("token %d: %+v", i, tk)
		}
		ids[tk.ID] = true
	}
	if len(ids) != 3 {
		t.Fatal("ids repeat")
	}
	if code := Run([]string{"controller", "mint-breakglass", "--dir", dir, "--hosts", "nope", "--action", "pause", "--from", "2026-11-14T08:00:00Z", "--count", "1", "--out", t.TempDir() + "/x"}, &so, &se); code == 0 {
		t.Fatal("minted for a host not enrolled")
	}
	if code := Run([]string{"controller", "mint-breakglass", "--dir", dir, "--hosts", "web01", "--action", "root", "--from", "2026-11-14T08:00:00Z", "--count", "1", "--out", t.TempDir() + "/y"}, &so, &se); code == 0 {
		t.Fatal("minted an unknown action")
	}
}

func TestBreakglassCmd_CallersSession(t *testing.T) {
	var got sshgate.Msg
	sock := serveGate(t, func(m sshgate.Msg) sshgate.Reply { got = m; return sshgate.Reply{OK: true, Why: "approve-session"} })
	old, oldSpool := gateSocket, spoolDir
	gateSocket, spoolDir = sock, t.TempDir()
	t.Cleanup(func() { gateSocket, spoolDir = old, oldSpool })
	t.Setenv("XDG_SESSION_ID", "9")
	var so, se bytes.Buffer
	if code := Run([]string{"breakglass", "abc.def"}, &so, &se); code != 0 {
		t.Fatalf("exit %d %s", code, se.String())
	}
	if got.Token != "abc.def" || got.Session != "9" {
		t.Fatalf("sent %+v", got)
	}
	sp := breakglass.ReadSpool(spoolDir)
	if len(sp) != 1 || breakglass.ParseEntry(sp[0]) != (breakglass.Entry{Token: "abc.def", Session: "9"}) {
		t.Fatalf("spool %q", sp)
	}
	gateSocket = filepath.Join(t.TempDir(), "none.sock")
	so.Reset()
	if code := Run([]string{"breakglass", "--session", "12", "abc.xyz"}, &so, &se); code != 0 || !strings.Contains(so.String(), "agent down: token spooled") {
		t.Fatalf("agent down: %d %q %q", code, so.String(), se.String())
	}
	if len(breakglass.ReadSpool(spoolDir)) != 2 {
		t.Fatal("not spooled")
	}
}

// An uninstall token the agent acts on ends the agent: the connection
// closes with no reply. That is said as what it is, not as an agent down.
func TestBreakglassCmd_UninstallSent(t *testing.T) {
	_, key, _ := ed25519.GenerateKey(nil)
	mintTok := func(action string) string {
		return breakglass.Mint(breakglass.Token{V: 1, ID: "00000000000000f1", Host: "web01", Action: action,
			NotBefore: time.Now().Add(-time.Minute), Expires: time.Now().Add(time.Hour)}, key)
	}
	// agent is a gate socket whose agent, on a message, removes the spool
	// (as it does for a spent uninstall token) and exits without a reply.
	agent := func(t *testing.T, spool string) string {
		sock := filepath.Join(t.TempDir(), "gate.sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n')
			ents, _ := os.ReadDir(spool)
			for _, e := range ents {
				os.Remove(filepath.Join(spool, e.Name()))
			}
			c.Close()
			l.Close() // the socket goes with the agent
		}()
		return sock
	}
	old, oldSpool := gateSocket, spoolDir
	t.Cleanup(func() { gateSocket, spoolDir = old, oldSpool })
	spoolDir = t.TempDir()
	gateSocket = agent(t, spoolDir)
	var so, se bytes.Buffer
	if code := Run([]string{"breakglass", mintTok("uninstall")}, &so, &se); code != 0 || !strings.Contains(so.String(), "uninstall sent; the agent is removing the install") {
		t.Fatalf("uninstall: %d %q %q", code, so.String(), se.String())
	}
	// A pause token to the same kind of exit is still an agent down.
	spoolDir = t.TempDir()
	gateSocket = agent(t, spoolDir)
	so.Reset()
	if code := Run([]string{"breakglass", mintTok("pause")}, &so, &se); code != 0 || !strings.Contains(so.String(), "agent down: token spooled") {
		t.Fatalf("pause: %d %q %q", code, so.String(), se.String())
	}
	// No agent at all: an uninstall token is spooled, and said so.
	spoolDir = t.TempDir()
	gateSocket = filepath.Join(t.TempDir(), "none.sock")
	so.Reset()
	if code := Run([]string{"breakglass", mintTok("uninstall")}, &so, &se); code != 0 || !strings.Contains(so.String(), "agent down: token spooled") {
		t.Fatalf("no agent: %d %q %q", code, so.String(), se.String())
	}
}
