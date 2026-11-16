#!/bin/bash
# The detect-first firewall on three real boxes: the controller on the jump
# box, agents on two targets that are each other's mesh peer, and a third
# target with no agent that runs two listeners to be blocked or not. The
# table is policy accept; a non-baseline binary's connection is killed and
# its endpoint becomes a fleet-wide block; a base-image interpreter's is an
# alert and nothing more; DNS is left alone. Prints "ok <case>" or
# "FAIL <case>: why" and ends with E2E-BLOCK PASS. Runs on the ssh backend.
#   XDR_E2E_KEEP=1      leaves the boxes as they are (until their dead-man timer)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-block runs on the ssh backend"; exit 1; }

CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh
[ ${#BOXES[@]} -ge 3 ] || { echo "e2e-block needs three [targets]"; exit 1; }
VM1=${BOXES[0]} VM2=${BOXES[1]} VM3=${BOXES[2]}
VM=$VM1

OUT=$(mktemp -d)
CTL=$OUT/ctl
cleanup() {
  jb systemctl stop xdr-e2e-jhttp >/dev/null 2>&1
  ctl_kill
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then boxes_down "$VM1" "$VM2" "$VM3"; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

CGO_ENABLED=0 go build -trimpath -o "$OUT/beacon" ./test/vm/beacon || exit 1
boxes_up "$VM1" "$VM2" "$VM3" || exit 1
HOST=$(jump_ip)
IP1=$(ip_of "$VM1")
IP2=$(ip_of "$VM2")
IP3=$(ip_of "$VM3")
echo "== jump box $HOST, agents $VM1 $IP1 and $VM2 $IP2, plain host $VM3 $IP3"
for v in "$VM1" "$VM2"; do
  on "$v" x command -v curl >/dev/null || { echo "$v has no curl"; exit 1; }
done

# The third host: two listeners (4444 gets blocked, 4445 does not).
for port in 4444 4445; do
  on "$VM3" x systemd-run --unit=xdr-e2e-http-$port python3 -m http.server $port --bind 0.0.0.0 --directory /tmp >/dev/null || exit 1
done
# And one on the jump box, which no rule may ever name.
jb systemd-run --unit=xdr-e2e-jhttp python3 -m http.server 4446 --bind 0.0.0.0 --directory /tmp >/dev/null || exit 1
sleep 1

# What name resolution looked like before any agent ran.
dns_state() {
  x sh -c 'sha256sum /etc/resolv.conf /etc/hosts /etc/nsswitch.conf; readlink -f /etc/resolv.conf; getent hosts ubuntu.com >/dev/null 2>&1 && echo resolves || echo no-resolve'
}
DNS1=$(on "$VM1" dns_state)

# The jump box side.
bin/xdr controller init --dir "$CTL" --name "$HOST" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e --out "$OUT/bundle" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e2 --out "$OUT/bundle2" >/dev/null || exit 1
printf '{"listen": "%s:2379", "protect": ["%s"]}\n' "$HOST" "$HOST" > "$CTL/controller.json"
jsync "$CTL" || exit 1
SIGN_DIR=$CTL
jx() { jb "$JXDR" "$@"; }
starts_ctl=0
start_ctl() {
  starts_ctl=$((starts_ctl + 1))
  ctl_run $starts_ctl
  for _ in $(seq 40); do grep -q '^controller: listening' <<<"$(ctl_log)" && return 0; sleep 0.25; done
  ctl_log
  return 1
}
ctl_count() { grep -c -- "$1" <<<"$(ctl_log)"; }
wait_ctl() {
  for _ in $(seq $(($1 * 4))); do [ "$(ctl_count "$3")" -ge "$2" ] && return 0; sleep 0.25; done
  return 1
}
rule_ids() { jx rules list --dir "$JCTL" | awk '$1 ~ /^[0-9a-f]{16}$/ {print $1}'; }

setup_box() {
  local name=$1 bundle=$2
  push bin/xdr /usr/local/sbin/xdr 0755 || return 1
  x mkdir -p /etc/xdr/fleet /var/cache/xdr-e2e /opt/beacon
  for f in ca.pem host.pem host-key.pem rules.pub; do
    push "$bundle/$f" /etc/xdr/fleet/$f 0600 || return 1
  done
  python3 - "$HOST" "$name" "$IP1" "$IP2" > "$OUT/$name.json" <<'PY'
import json, sys
host, name, ip1, ip2 = sys.argv[1:]
print(json.dumps({
    "host": name,
    "jump": [host],
    "peers": [ip1, ip2],
    "xdr_ports": [7443, 2379],
    "listeners": [],
    "kill": True,
    "dns": {"resolver": host},
    "fleet": {"endpoints": [host + ":2379"]},
    "mesh": {"port": 7443},
}, indent=2))
PY
  push_conf "$OUT/$name.json" || return 1
  echo "== capture baseline on $name"
  x xdr capture --root / --out "$BASE" || return 1
  x xdr listeners --config "$CONF" > "$OUT/$name.listeners.json" || return 1
  python3 - "$OUT/$name.json" "$OUT/$name.listeners.json" <<'PY' || return 1
import json, sys
c = json.load(open(sys.argv[1]))
c["listeners"] = json.load(open(sys.argv[2])) + [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}]
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
  push_conf "$OUT/$name.json" || return 1
  push "$OUT/beacon" /opt/beacon/beacon 0755 || return 1
}
on "$VM1" setup_box e2e "$OUT/bundle" || exit 1
on "$VM2" setup_box e2e2 "$OUT/bundle2" || exit 1

start_ctl || exit 1
start_agent || { x cat "$ERR"; exit 1; }
on "$VM2" start_agent || { on "$VM2" x cat "$ERR"; exit 1; }
# joined VM: its table is applied and its agent holds a session with etcd.
joined() { on "$1" x sh -c 'nft list table inet xdr >/dev/null 2>&1 && [ -n "$(ss -Htn state established "( dport = :2379 )")" ]'; }
for _ in $(seq 80); do joined "$VM1" && joined "$VM2" && break; sleep 0.25; done
joined "$VM1" && joined "$VM2" || { echo "the agents did not apply their table and join within 20 s"; exit 1; }

# fetch VM PORT: the http status of the third host's listener, 000 when
# nothing came back within 3 s.
fetch() { x curl -s -m 3 -o /dev/null -w '%{http_code}' "http://$IP3:$1/" 2>/dev/null; true; }
# out_has VM PATTERN: the output chain of VM's table has a line matching.
out_has() { grep -q -- "$2" <<<"$(on "$1" x nft list chain inet xdr output)"; }
# wait_out SECS VM PATTERN / wait_out_gone SECS VM PATTERN
wait_out() { for _ in $(seq $(($1 * 4))); do out_has "$2" "$3" && return 0; sleep 0.25; done; return 1; }
wait_out_gone() { for _ in $(seq $(($1 * 4))); do out_has "$2" "$3" || return 0; sleep 0.25; done; return 1; }
DROP="ip daddr $IP3 tcp dport 4444 drop"

echo "== policy-accept"
bad=""
for v in "$VM1" "$VM2"; do
  t=$(on "$v" x nft list table inet xdr)
  grep -q 'policy drop' <<<"$t" && bad="$bad $v:policy-drop"
  grep -Eq 'hook output priority [a-z ]*-? ?10; policy accept' <<<"$t" || bad="$bad $v:no-accept"
  grep -q 'daddr' <<<"$t" && bad="$bad $v:has-a-block"
  for port in 4444 4445; do
    [ "$(on "$v" fetch $port)" = 200 ] || bad="$bad $v:cannot-reach-$port"
  done
done
if [ -n "$bad" ]; then fail policy-accept "$bad"; else ok policy-accept; fi

echo "== dns-untouched"
dns_now=$(on "$VM1" dns_state)
if [ "$dns_now" != "$DNS1" ]; then fail dns-untouched "before: $DNS1; after: $dns_now"
elif on "$VM1" x sh -c "ss -Hlun 'sport = :53' | grep -v '127.0.0.53' | grep -q 127.0.0.1"; then fail dns-untouched "a stub listens on 127.0.0.1:53"
elif on "$VM1" x sh -c "nft list ruleset | grep -q 'dport 53'"; then fail dns-untouched "the table mentions port 53"
else ok dns-untouched; fi

echo "== baseline-alerts"
mark
rules_before=$(jx rules list --dir "$JCTL" | wc -l)
bg "python3 -c \"import socket, time; s = socket.create_connection(('$IP3', 4445), 5); time.sleep(40)\""
# The alert says the agent judged the connection; the process must still run.
if ! wait_inc 10 egress alert "i.get('remote', {}).get('port') == 4445 and i['severity'] == 'medium'"; then fail baseline-alerts "no Medium egress alert: $(x tail -3 $LOG)"
elif ! x pgrep -f 'create_connection' >/dev/null; then fail baseline-alerts "python3 was killed: $(x tail -3 $LOG)"
elif [ "$(jx rules list --dir "$JCTL" | wc -l)" != "$rules_before" ]; then fail baseline-alerts "an alert proposed a rule: $(jx rules list --dir "$JCTL")"
else ok baseline-alerts; fi
x pkill -f create_connection

echo "== nonbaseline-killed-blocked"
mark
promoted=$(ctl_count 'rule-promoted')
bg "/opt/beacon/beacon $IP3:4444"
if ! gone 5 '/opt/beacon/beacon'; then fail nonbaseline-killed-blocked "the beacon still runs"
elif ! wait_inc 3 egress killed "i.get('exe') == '/opt/beacon/beacon'"; then fail nonbaseline-killed-blocked "no egress/killed incident: $(x tail -3 $LOG)"
elif ! wait_ctl 5 $((promoted + 1)) 'rule-promoted'; then fail nonbaseline-killed-blocked "controller: $(ctl_log | tail -5)"
elif ! jx rules list --dir "$JCTL" | grep -q "remote $IP3:4444/tcp"; then fail nonbaseline-killed-blocked "no remote rule: $(jx rules list --dir "$JCTL")"
elif ! wait_out 6 "$VM1" "$DROP"; then fail nonbaseline-killed-blocked "no drop on $VM1: $(on "$VM1" x nft list chain inet xdr output)"
elif ! wait_out 6 "$VM2" "$DROP"; then fail nonbaseline-killed-blocked "no drop on $VM2 (the fleet): $(on "$VM2" x nft list chain inet xdr output)"
elif ! inc fw-block ""; then fail nonbaseline-killed-blocked "no fw-block incident on $VM1"
else ok nonbaseline-killed-blocked; fi

echo "== block-holds"
a=$(on "$VM2" fetch 4444) b=$(on "$VM2" fetch 4445)
if [ "$a" != 000 ] || [ "$b" != 200 ]; then fail block-holds "4444 gave $a (want 000), 4445 gave $b (want 200)"; else ok block-holds; fi

echo "== agent-dead"
on "$VM2" stop_agent
a=$(on "$VM2" fetch 4444)
if ! out_has "$VM2" "$DROP"; then fail agent-dead "the drop left with the agent"
elif [ "$a" != 000 ]; then fail agent-dead "4444 reachable with the agent dead ($a)"
else ok agent-dead; fi

echo "== revoke"
on "$VM2" start_agent || fail revoke "agent did not start: $(on "$VM2" x cat "$ERR")"
ids=$(rule_ids)
for id in $ids; do jx rules revoke --dir "$JCTL" "$id" >/dev/null; done
if ! wait_out_gone 8 "$VM1" "$DROP"; then fail revoke "the drop is still on $VM1"
elif ! wait_out_gone 8 "$VM2" "$DROP"; then fail revoke "the drop is still on $VM2"
elif [ "$(on "$VM2" fetch 4444)" != 200 ]; then fail revoke "4444 still unreachable after the revoke"
elif ! inc fw-unblock ""; then fail revoke "no fw-unblock incident"
else ok revoke; fi

echo "== protected-refused"
mark
bg "/opt/beacon/beacon $HOST:4446"
if ! gone 5 '/opt/beacon/beacon'; then fail protected-refused "the beacon still runs"
elif ! wait_inc 3 egress killed "i.get('remote', {}).get('port') == 4446"; then fail protected-refused "no kill for the connection to the jump box: $(x tail -3 $LOG)"
elif ! wait_ctl 6 1 'rule-rejected'; then fail protected-refused "the controller did not refuse: $(ctl_log | tail -5)"
elif jx rules list --dir "$JCTL" | grep -q "$HOST:4446"; then fail protected-refused "a rule names the jump box: $(jx rules list --dir "$JCTL")"
elif out_has "$VM1" "daddr $HOST"; then fail protected-refused "the table drops the jump box"
else ok protected-refused; fi

on "$VM2" stop_agent
stop_agent
if [ $fails = 0 ]; then echo "E2E-BLOCK PASS"; else echo "E2E-BLOCK FAIL ($fails)"; exit 1; fi
