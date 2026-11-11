#!/bin/bash
# Fleet rules end to end: the controller runs on the host (the jump box),
# the agent in an Ubuntu 24.04 VM (LXD). A kill on the VM becomes a signed
# rule; the rule kills a copy of the same binary; it holds with the
# controller down; a silent agent is reported; a revoked rule stops
# killing. Prints "ok <case>" or "FAIL <case>: why" and ends with
# E2E-FLEET PASS.
#   XDR_E2E_KEEP=1      leaves the VM running afterwards
# grep -q on a pipe can SIGPIPE the writer: under pipefail, grep a captured
# string instead.
set -uo pipefail
cd "$(dirname "$0")/../.."

VM=${XDR_E2E_VM:-xdr-e2e-fleet}
IMAGE=${XDR_E2E_IMAGE:-ubuntu:24.04}
CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh

OUT=$(mktemp -d)
CTL=$OUT/ctl
CTLPID=""
cleanup() {
  [ -n "$CTLPID" ] && kill "$CTLPID" 2>/dev/null && wait "$CTLPID" 2>/dev/null
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then lxc delete --force "$VM" >/dev/null 2>&1; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

CGO_ENABLED=0 go build -trimpath -o "$OUT/beacon" ./test/vm/beacon || exit 1
# An LXD client can stall with no operation behind it; fail rather than wait.
timeout 600 lxc launch "$IMAGE" "$VM" --vm || exit 1
for _ in $(seq 120); do x true >/dev/null 2>&1 && break; sleep 2; done
x systemctl is-system-running --wait >/dev/null || true
HOST=$(lxc network get lxdbr0 ipv4.address | cut -d/ -f1)
echo "== host $HOST"

# The jump box side.
bin/xdr controller init --dir "$CTL" --name "$HOST" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e --out "$OUT/bundle" >/dev/null || exit 1
printf '{"listen": "%s:2379", "protect": ["%s"]}\n' "$HOST" "$HOST" > "$CTL/controller.json"
starts_ctl=0
start_ctl() {
  starts_ctl=$((starts_ctl + 1))
  CTLOUT=$OUT/ctl.$starts_ctl.out
  bin/xdr controller run --dir "$CTL" > "$CTLOUT" 2>&1 &
  CTLPID=$!
  for _ in $(seq 40); do grep -q '^controller: listening' "$CTLOUT" && return 0; sleep 0.25; done
  cat "$CTLOUT"
  return 1
}
stop_ctl() { kill "$CTLPID"; wait "$CTLPID" 2>/dev/null; CTLPID=""; }
# ctl_count PATTERN: lines of the controller's output matching PATTERN.
ctl_count() { grep -c -- "$1" "$CTLOUT"; }
# wait_ctl SECONDS N PATTERN: at least N lines match within SECONDS.
wait_ctl() {
  for _ in $(seq $(($1 * 4))); do [ "$(ctl_count "$3")" -ge "$2" ] && return 0; sleep 0.25; done
  return 1
}

# The box side.
lxc file push bin/xdr "$VM/usr/local/sbin/xdr" --mode 0755 || exit 1
x mkdir -p /etc/xdr/fleet /var/cache/xdr-e2e /opt/beacon
for f in ca.pem host.pem host-key.pem rules.pub; do
  lxc file push "$OUT/bundle/$f" "$VM/etc/xdr/fleet/$f" --mode 0600 || exit 1
done
python3 - "$HOST" > "$OUT/agent.json" <<'PY'
import json, sys
host = sys.argv[1]
print(json.dumps({
    "host": "e2e",
    "jump": [host],
    "xdr_ports": [7443, 2379],
    "listeners": [],
    "dhcp_server": [host],
    "kill": True,
    "dns": {"resolver": host},
    "fleet": {"endpoints": [host + ":2379"]},
}, indent=2))
PY
lxc file push "$OUT/agent.json" "$VM$CONF" --mode 0600 || exit 1
echo "== capture baseline"
x xdr capture --root / --out "$BASE" || exit 1
x xdr listeners --config "$CONF" > "$OUT/listeners.json" || exit 1
python3 - "$OUT/agent.json" "$OUT/listeners.json" <<'PY' || exit 1
import json, sys
c = json.load(open(sys.argv[1]))
c["listeners"] = json.load(open(sys.argv[2])) + [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}]
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
lxc file push "$OUT/agent.json" "$VM$CONF" --mode 0600 || exit 1
# After the capture: the beacon is in no baseline.
lxc file push "$OUT/beacon" "$VM/opt/beacon/beacon" --mode 0755 || exit 1
x cp /opt/beacon/beacon /usr/local/bin/helperd
BEACON_SUM=$(sha256sum "$OUT/beacon" | cut -d' ' -f1)
PY_SUM=$(x sh -c 'sha256sum "$(readlink -f /usr/bin/python3)"' | cut -d' ' -f1)
[ ${#PY_SUM} = 64 ] || { echo "no python3 hash: '$PY_SUM'"; exit 1; }

start_ctl || exit 1
CTL_STARTED=$(date +%s)
start_agent || { x cat "$ERR"; exit 1; }

echo "== enrolled"
sleep $((CTL_STARTED + 18 - $(date +%s)))
if [ "$(ctl_count 'agent-silent')" != 0 ]; then fail enrolled "controller: $(grep agent-silent "$CTLOUT")"
else ok enrolled; fi

echo "== beacon-killed"
mark
# Not the host: it is protected, so no rule may name it.
bg "/opt/beacon/beacon 203.0.113.9:4444"
if ! gone 5 '/opt/beacon/beacon'; then fail beacon-killed "the beacon still runs"
elif ! wait_inc 2 egress killed "i.get('exe') == '/opt/beacon/beacon'"; then fail beacon-killed "no egress/killed incident"
elif ! wait_ctl 3 2 'rule-promoted'; then fail beacon-killed "controller: $(cat "$CTLOUT")"
elif ! grep -q "hash $BEACON_SUM" <<<"$(bin/xdr rules list --dir "$CTL")"; then fail beacon-killed "no hash rule: $(bin/xdr rules list --dir "$CTL")"
else ok beacon-killed; fi

echo "== rule-hash-kills"
mark
bg "/usr/local/bin/helperd idle"
if ! gone 5 'helperd idle'; then fail rule-hash-kills "the copy still runs"
elif ! wait_inc 2 rule-hash killed "i.get('exe') == '/usr/local/bin/helperd'"; then fail rule-hash-kills "no rule-hash/killed incident"
else ok rule-hash-kills; fi

echo "== baseline-not-promoted"
mark
promoted=$(ctl_count 'rule-promoted')
# As with the beacon, not the protected host.
bg "python3 -c \"import socket; socket.create_connection(('203.0.113.9', 4445), 60)\""
if ! gone 5 "create_connection\\(\\('203.0.113.9', 4445"; then fail baseline-not-promoted "python still runs"
elif ! wait_inc 2 egress killed "i.get('remote', {}).get('port') == 4445"; then fail baseline-not-promoted "no egress/killed incident"
elif ! wait_ctl 3 $((promoted + 1)) 'rule-promoted'; then fail baseline-not-promoted "the remote rule was not promoted"
else
  sleep 1
  if grep -q "$PY_SUM" <<<"$(bin/xdr rules list --dir "$CTL")"; then
    fail baseline-not-promoted "python3's hash $PY_SUM became a rule: $(bin/xdr rules list --dir "$CTL"; grep rule- "$CTLOUT")"
  elif [ "$(ctl_count 'rule-promoted')" != $((promoted + 1)) ]; then fail baseline-not-promoted "more than the remote rule: $(tail -3 "$CTLOUT")"
  else ok baseline-not-promoted; fi
fi

echo "== controller-down-cached"
stop_ctl
stop_agent
start_agent || fail controller-down-cached "agent did not start: $(x cat "$ERR")"
mark
bg "/usr/local/bin/helperd idle"
if ! gone 5 'helperd idle'; then fail controller-down-cached "the copy still runs"
elif ! wait_inc 2 rule-hash killed; then fail controller-down-cached "no rule-hash/killed incident"
else ok controller-down-cached; fi

echo "== agent-silent"
start_ctl || exit 1
# The agent's reconnect backoff is at most 30 s.
sleep 35
before=$(ctl_count 'agent-silent')
stop_agent
if ! wait_ctl 20 $((before + 1)) 'agent-silent'; then fail agent-silent "controller: $(tail -5 "$CTLOUT")"
elif ! grep 'agent-silent' "$CTLOUT" | tail -1 | grep -q '^e2e '; then fail agent-silent "not for e2e: $(grep agent-silent "$CTLOUT")"
else ok agent-silent; fi

echo "== revoke"
start_agent || fail revoke "agent did not start"
id=$(bin/xdr rules list --dir "$CTL" | awk -v s="$BEACON_SUM" '$3 == s {print $1}')
if [ -z "$id" ]; then fail revoke "no hash rule to revoke"
else
  bin/xdr rules revoke --dir "$CTL" "$id" >/dev/null || fail revoke "revoke failed"
  sleep 3
  bg "/usr/local/bin/helperd idle"
  sleep 3
  if x pgrep -f 'helperd idle' >/dev/null; then ok revoke; else fail revoke "the copy was killed after the revoke"; fi
  x pkill -f 'helperd idle'
fi

stop_agent
if [ $fails = 0 ]; then echo "E2E-FLEET PASS"; else echo "E2E-FLEET FAIL ($fails)"; exit 1; fi
