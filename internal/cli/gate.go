package cli

import (
	"io"
	"os"
	"strings"

	"xdr/internal/sshgate"
)

// gateSocket is where `xdr gate` finds the agent.
var gateSocket = sshgate.Socket

// gatePaused reports whether a pause token lets sessions through while
// the agent is down.
var gatePaused = func() bool { return false }

// gateCmd is `xdr gate`, pam_exec's hook as a session opens: it exits 0 to
// let the session open, and refuses it when the agent says no or cannot be
// reached.
func gateCmd(_ []string, _ io.Writer) error {
	env := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return sshgate.Check(env, gateSocket, gatePaused)
}
