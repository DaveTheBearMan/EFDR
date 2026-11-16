#!/bin/bash
# The day-1 deployment on real boxes, done as deploy/README.md says: the
# controller goes on the jump box with `xdr controller install` (a systemd
# unit), one target is installed only through prep-target.sh, `xdr
# controller add-target` and the bundle's install-target.sh. Then: the
# controller unit is active and comes back from a `systemctl kill`, the
# console takes the password, the target's agent unit is active and up in
# the console, a beacon is would-kill (kill is off by default) until the
# console turns kill on, and install-target.sh refuses a second run
# without --again; an uninstall token from the console removes it all
# again. Prints "ok <case>" or "FAIL <case>: why" and ends with
# E2E-DEPLOY PASS. Runs on the ssh backend.
#   XDR_E2E_KEEP=1      leaves the boxes as they are (until the dead-man timer)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-deploy runs on the ssh backend"; exit 1; }

CONF=/etc/xdr/agent.json
LOG=/var/lib/xdr/incidents.jsonl
PW='e2e deploy passphrase'
D=/root/xdr-day1
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh
VM=${XDR_E2E_VM:-${BOXES[0]}}

OUT=$(mktemp -d)
JCTL=$JROOT/ctl
JRESET=$JROOT/xdr-e2e-reset
ctl_reset() { jb sh "$JRESET" controller >/dev/null 2>&1; }
cleanup() {
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then
    ctl_reset
    x rm -rf "$D" /root/e2e.tgz
    boxes_down "$VM"
  fi
  rm -rf "$OUT"
}
trap cleanup EXIT

CGO_ENABLED=0 go build -trimpath -o "$OUT/beacon" ./test/vm/beacon || exit 1
boxes_up "$VM" || exit 1
VM=$JUMP push test/vm/remote-reset.sh "$JRESET" 0755 || exit 1
ctl_reset
HOST=$(jump_ip)
IP=$(ip_of "$VM")
echo "== jump box $HOST, $VM $IP"

BASEURL=https://$HOST:8443
CJ=$JROOT/cookies
capi() { jb curl -sk -m 15 -b "$CJ" -c "$CJ" -H 'X-XDR: 1' "$@"; }
code() { jb curl -sk -m 15 -o /dev/null -w '%{http_code}' "$@"; }
state_has() {
  capi "$BASEURL/api/state" | python3 -c 'import json, sys; v = json.load(sys.stdin); sys.exit(0 if eval(sys.argv[1]) else 1)' "$1" 2>/dev/null
}
wait_state() { for _ in $(seq $(($1 * 2))); do state_has "$2" && return 0; sleep 0.5; done; return 1; }
mode() { code -b "$CJ" -X POST -H 'X-XDR: 1' -H 'Content-Type: application/json' -d "{\"host\":\"$1\",\"kill\":$2}" "$BASEURL/api/mode"; }
# beacon_is PORT ACTION: a beacon to 203.0.113.9:PORT gets that action.
beacon_is() {
  mark
  bg "/opt/beacon/beacon 203.0.113.9:$1"
  wait_inc 25 egress "$2" "(i.get('remote') or {}).get('port') == $1"
}
ctl_pid() { jb systemctl show -p MainPID --value xdr-controller.service; }
INSTALL=(controller install --dir "$JCTL" --name "$HOST" --gray gray1 --auto root --recovery xdrrecover)

echo "== controller-install"
out=$(printf '%s\n' "$PW" | ssh -F "$SSHCFG" "$JUMP" "$(printf '%q ' "$JXDR" "${INSTALL[@]}")" 2>&1)
rc=$?
active=""
for _ in $(seq 20); do [ "$(jb systemctl is-active xdr-controller.service)" = active ] && { active=1; break; }; sleep 0.5; done
if [ $rc != 0 ]; then fail controller-install "exit $rc: $out"
elif grep -qF "$PW" <<<"$out"; then fail controller-install "the password was printed"
elif [ -z "$active" ]; then fail controller-install "xdr-controller.service is not active: $(jb journalctl -u xdr-controller -n 10 --no-pager)"
elif ! jb grep -q "ExecStart=/usr/local/sbin/xdr controller run --dir $JCTL" /etc/systemd/system/xdr-controller.service; then fail controller-install "the unit's ExecStart"
else ok controller-install; fi

echo "== controller-install-again"
pid=$(ctl_pid)
out=$(jb "$JXDR" "${INSTALL[@]}" 2>&1)
rc=$?
if [ $rc != 0 ] || ! grep -q 'nothing changed' <<<"$out"; then fail controller-install-again "exit $rc: $out"
elif [ "$(ctl_pid)" != "$pid" ]; then fail controller-install-again "the controller was restarted"
else ok controller-install-again; fi

echo "== controller-restarts"
pid=$(ctl_pid)
jb systemctl kill xdr-controller.service
back=""
for _ in $(seq 40); do
  now=$(ctl_pid)
  if [ "$(jb systemctl is-active xdr-controller.service)" = active ] && [ -n "$now" ] && [ "$now" != 0 ] && [ "$now" != "$pid" ]; then back=1; break; fi
  sleep 0.5
done
if [ -z "$back" ]; then fail controller-restarts "not back after systemctl kill (pid was $pid, is $(ctl_pid)): $(jb journalctl -u xdr-controller -n 10 --no-pager)"
else ok controller-restarts; fi

echo "== console-login"
up=""
for _ in $(seq 40); do [ "$(code "$BASEURL/api/state")" = 401 ] && { up=1; break; }; sleep 0.5; done
if [ -z "$up" ]; then fail console-login "the console does not answer at $BASEURL"
elif [ "$(code -X POST -H 'Content-Type: application/json' -d '{"password":"not the password at all"}' "$BASEURL/login")" != 401 ]; then fail console-login "a wrong password was not refused"
elif [ "$(code -c "$CJ" -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" "$BASEURL/login")" != 204 ]; then fail console-login "the password was refused"
elif [ "$(code -b "$CJ" "$BASEURL/api/state")" != 200 ]; then fail console-login "the session cookie does not work"
else ok console-login; fi

echo "== prep-target"
# The box's accounts first: they are in its baseline.
ssh-keygen -q -t ed25519 -N "" -C xdr-e2e -f "$OUT/key" || exit 1
PUB=$(cat "$OUT/key.pub")
for u in alice gray1 xdrrecover; do
  x useradd -m -s /bin/bash "$u" || exit 1
  x sh -c "mkdir -p /home/$u/.ssh && echo '$PUB' > /home/$u/.ssh/authorized_keys && chown -R $u: /home/$u/.ssh && chmod 700 /home/$u/.ssh && chmod 600 /home/$u/.ssh/authorized_keys" || exit 1
done
x mkdir -p "$D" || exit 1
push bin/xdr "$D/xdr" 0755 || exit 1
push deploy/prep-target.sh "$D/prep-target.sh" 0755 || exit 1
x "$D/prep-target.sh" > "$OUT/facts.json"
rc=$?
pt=$(python3 -c '
import json, sys
f = json.load(open(sys.argv[1]))
bad = []
if not isinstance(f.get("listeners"), list) or not f["listeners"]: bad.append("no listeners")
if "alice" not in [a["name"] for a in f.get("accounts", [])]: bad.append("alice is not among the accounts")
if not any(p["proto"] == "tcp" and p["port"] == 22 for p in f.get("ports", [])): bad.append("no tcp/22 among the ports")
print(" ".join(bad))' "$OUT/facts.json" 2>&1)
if [ $rc != 0 ]; then fail prep-target "exit $rc"
elif [ -n "$pt" ]; then fail prep-target "$pt: $(head -c 400 "$OUT/facts.json")"
elif [ "$(x ls -A "$D" | tr '\n' ' ')" != "prep-target.sh xdr " ] || x test -e /etc/xdr; then fail prep-target "it wrote something"
else ok prep-target; fi

echo "== add-target"
VM=$JUMP push "$OUT/facts.json" "$JROOT/facts.json" 0600 || exit 1
VM=$JUMP push "$OUT/key.pub" "$JROOT/recovery.pub" 0644 || exit 1
out=$(jb "$JXDR" controller add-target --dir "$JCTL" --host e2e --out "$JROOT/e2e.tgz" --listeners "$JROOT/facts.json" \
  --scored tcp/8081 --blue alice --gray gray1 --recovery xdrrecover --recovery-key "$JROOT/recovery.pub" --auto root 2>&1)
rc=$?
if [ $rc != 0 ]; then fail add-target "exit $rc: $out"
elif ! grep -q 'install-target.sh' <<<"$out"; then fail add-target "no next step: $out"
elif [ "$(jb stat -c %a "$JROOT/e2e.tgz")" != 600 ]; then fail add-target "the bundle is not 0600"
else ok add-target; fi

echo "== install-target"
jb cat "$JROOT/e2e.tgz" > "$OUT/e2e.tgz" && push "$OUT/e2e.tgz" /root/e2e.tgz 0600 || exit 1
x tar -C "$D" -xzf /root/e2e.tgz || exit 1
x "$D/install-target.sh" > "$OUT/install.out" 2>&1
rc=$?
if [ $rc != 0 ]; then fail install-target "exit $rc: $(tail -15 "$OUT/install.out")"
elif ! grep -q '^ok   xdr-agent.service is active' "$OUT/install.out" || ! grep -q '^ok   the controller answers' "$OUT/install.out"; then
  fail install-target "its checks: $(tail -8 "$OUT/install.out")"
elif ! grep -q 'capturing this box' "$OUT/install.out" || ! x test -s /var/lib/xdr/baseline.json.gz; then fail install-target "no baseline captured and installed"
elif [ "$(x stat -c %a /etc/xdr/fleet/host-key.pem)" != 600 ]; then fail install-target "the host key is not 0600"
else ok install-target; fi
# After the capture: the beacon is in no baseline.
x mkdir -p /opt/beacon && push "$OUT/beacon" /opt/beacon/beacon 0755 || exit 1

echo "== agent-up"
if [ "$(x systemctl is-active xdr-agent.service)" != active ]; then fail agent-up "xdr-agent.service: $(x systemctl is-active xdr-agent.service)"
elif ! wait_state 40 'any(h["Name"] == "e2e" and h["Status"] == "up" for h in v["Hosts"])'; then fail agent-up "not up in the console: $(capi "$BASEURL/api/state" | head -c 600)"
else ok agent-up; fi

echo "== kill-off-then-on"
kt=""
if ! beacon_is 4471 would-kill; then kt="kill off: the beacon was not would-kill: $(x tail -3 $LOG)"
elif ! x pgrep -f 'beacon 203.0.113.9:4471' >/dev/null; then kt="kill off: the beacon was killed"
fi
x pkill -f '^/opt/beacon/beacon 203.0.113.9:447'
if [ -z "$kt" ]; then
  if [ "$(mode e2e true)" != 204 ]; then kt="the console's kill-on order was refused"
  elif ! wait_state 20 'any(h["Name"] == "e2e" and h["Kill"] == "on" for h in v["Hosts"])'; then kt="the console never showed kill on"
  elif ! beacon_is 4472 killed; then kt="kill on: the beacon was not killed: $(x tail -3 $LOG)"
  elif ! gone 8 'beacon 203.0.113.9:4472'; then kt="kill on: the beacon still runs"
  fi
fi
x pkill -f '^/opt/beacon/beacon 203.0.113.9:447'
if [ -n "$kt" ]; then fail kill-off-then-on "$kt"; else ok kill-off-then-on; fi

echo "== install-target-again"
out=$(x "$D/install-target.sh" 2>&1)
rc=$?
if [ $rc = 0 ]; then fail install-target-again "a second run was not refused: $out"
elif ! grep -q -- '--again' <<<"$out" || ! grep -q 'pause' <<<"$out"; then fail install-target-again "no --again and pause advice: $out"
elif [ "$(x systemctl is-active xdr-agent.service)" != active ]; then fail install-target-again "the agent is not active after the refusal"
else ok install-target-again; fi

echo "== uninstall"
# As the README removes a target: an uninstall token from the console.
tok=$(capi -X POST -H 'Content-Type: application/json' -d '{"host": "e2e", "action": "uninstall", "minutes": 30}' "$BASEURL/api/breakglass" |
  python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
uout=$(printf '%s\n' "$tok" | xin /usr/local/sbin/xdr breakglass - 2>&1)
gone_all() { ! x test -e /usr/local/sbin/xdr && ! x test -e /etc/xdr/agent.json && ! x pgrep -f '[x]dr (agent|guard|ensure)' >/dev/null; }
removed=""
for _ in $(seq 60); do gone_all && { removed=1; break; }; sleep 0.5; done
if [ -z "$tok" ]; then fail uninstall "the console minted no token"
elif [ -z "$removed" ]; then fail uninstall "the install is still there 30 s on (breakglass said: $uout)"
elif ! ssh -F "$SSHCFG" -n -o ControlMaster=no -o ControlPath=none "$VM" true; then fail uninstall "a fresh root login is refused"
else ok uninstall; fi

if [ $fails = 0 ]; then echo "E2E-DEPLOY PASS"; else echo "E2E-DEPLOY FAIL ($fails)"; exit 1; fi
