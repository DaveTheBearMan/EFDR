#!/bin/bash
# prep-target.sh: the facts `xdr controller add-target` needs, gathered on
# the target before it is added. Run as root with the xdr binary beside it
# (or named); prints JSON on stdout and writes nothing:
#   ./prep-target.sh [XDR_BINARY] > HOST-facts.json
# "listeners" is `xdr listeners` (give the file to add-target --listeners);
# "accounts" are the login accounts with uid >= 1000 (pick --blue and
# --gray from them); "ports" is every listening socket, to pick --scored.
set -euo pipefail

BIN=${1:-$(cd "$(dirname "$0")" && pwd)/xdr}
[ "$(id -u)" = 0 ] || { echo "prep-target: run me as root (xdr listeners reads every process)" >&2; exit 1; }
[ -f "$BIN" ] && [ -x "$BIN" ] || { echo "prep-target: no xdr binary at $BIN (give its path)" >&2; exit 1; }

LISTENERS=$("$BIN" listeners)
{ ss -H -l -n -t -u 2>/dev/null || true; } | python3 -c '
import json, pwd, socket, sys

listeners = json.loads(sys.argv[1])
try:
    shells = {l.strip() for l in open("/etc/shells") if l.strip().startswith("/")}
except OSError:
    shells = set()

def login(sh):
    if sh.endswith(("/nologin", "/false", "/sync")):
        return False
    return sh in shells if shells else bool(sh)

accounts = [{"name": p.pw_name, "uid": p.pw_uid, "shell": p.pw_shell, "home": p.pw_dir}
            for p in sorted(pwd.getpwall(), key=lambda p: p.pw_uid)
            if p.pw_uid >= 1000 and p.pw_uid != 65534 and login(p.pw_shell)]
ports = []
for line in sys.stdin.read().splitlines():
    f = line.split()
    if len(f) < 5:
        continue
    local = f[4]
    addr, _, port = local.rpartition(":")
    if not port.isdigit():
        continue
    e = {"proto": f[0], "port": int(port), "local": local}
    if e not in ports:
        ports.append(e)
ports.sort(key=lambda e: (e["proto"], e["port"], e["local"]))
print(json.dumps({"host": socket.gethostname(), "listeners": listeners, "accounts": accounts, "ports": ports}, indent=2))
' "$LISTENERS"
