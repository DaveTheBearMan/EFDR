package agent

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"xdr/internal/incident"
	"xdr/internal/model"
	"xdr/internal/sshgate"
)

// assertSSH holds sshd's and PAM's config at their render. With report
// false, files it had to write are logged, not incidents. A baseline
// without either file keeps the gate off, said once.
func (a *agent) assertSSH(report bool) {
	changed, err := a.ssh.Assert(a.cfg, a.pol.Base, a.gateExe)
	for _, p := range changed {
		if report {
			a.record(incident.Incident{Kind: "ssh-drift", Action: "repaired", Severity: model.SevHigh, Detail: p + " restored"})
		} else {
			a.logf("ssh: wrote %s", p)
		}
	}
	if errors.Is(err, sshgate.ErrNoBase) {
		if !a.gateOffSaid {
			a.record(incident.Incident{Kind: "ssh-config", Action: "alert", Severity: model.SevCritical, Detail: err.Error()})
		}
		a.gateOffSaid = true
		return
	}
	a.gateOffSaid = false
	if err != nil {
		a.record(incident.Incident{Kind: "ssh-config", Action: "alert", Severity: model.SevCritical, Detail: err.Error()})
	}
}

// runCmd runs a command; its error carries what it printed.
func runCmd(name string, args ...string) error {
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %v: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func outputCmd(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}
