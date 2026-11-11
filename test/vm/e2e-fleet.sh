#!/bin/bash
# Fleet rules end to end: the controller runs on the host (the jump box),
# agents in two Ubuntu 24.04 VMs (LXD) that are each other's mesh peer. A
# kill on VM1 becomes a signed rule; the rule kills a copy of the same
# binary; it holds with the controller down; a silent agent is reported; a
# revoked rule stops killing. The kill also starts a hunt that finds the
# binary on VM2; a unit's kill on VM1 kills the same unit on VM2; a VM cut
# off from etcd gets new rules through its peer; a stopped peer is
# reported. Prints "ok <case>" or "FAIL <case>: why" and ends with
# E2E-FLEET PASS.
#   XDR_E2E_KEEP=1      leaves the VMs running afterwards
# grep -q on a pipe can SIGPIPE the writer: under pipefail, grep a captured
# string instead.
set -uo pipefail
cd "$(dirname "$0")/../.."

VM1=${XDR_E2E_VM:-xdr-e2e-fleet}
VM2=${XDR_E2E_VM2:-xdr-e2e-fleet2}
VM=$VM1
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
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then lxc delete --force "$VM1" "$VM2" >/dev/null 2>&1; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

CGO_ENABLED=0 go build -trimpath -o "$OUT/beacon" ./test/vm/beacon || exit 1
# An LXD client can stall with no operation behind it; fail rather than
# wait. Launching one at a time, as two at once race on the image (qemu-img
# killed); that flake is also retried once. Two VMs at LXD's default 1 GiB
# starve a 4 GB host, so each gets VM_MEM.
VM_MEM=${VM_MEM:-768MiB}
launch() {
  timeout 600 lxc launch "$IMAGE" "$1" --vm -c limits.memory="$VM_MEM" && return 0
  lxc delete --force "$1" >/dev/null 2>&1
  timeout 600 lxc launch "$IMAGE" "$1" --vm -c limits.memory="$VM_MEM"
}
launch "$VM1" || exit 1
launch "$VM2" || exit 1
# ip_of VM: its IPv4 address on lxdbr0, once it has one.
ip_of() {
  local ip
  for _ in $(seq 120); do
    ip=$(lxc list "$1" -c4 --format csv | grep -o '^[0-9.]*' | head -1)
    [ -n "$ip" ] && { echo "$ip"; return 0; }
    sleep 2
  done
  return 1
}
for v in "$VM1" "$VM2"; do
  for _ in $(seq 120); do on "$v" x true >/dev/null 2>&1 && break; sleep 2; done
  on "$v" x systemctl is-system-running --wait >/dev/null || true
done
HOST=$(lxc network get lxdbr0 ipv4.address | cut -d/ -f1)
IP1=$(ip_of "$VM1") || exit 1
IP2=$(ip_of "$VM2") || exit 1
echo "== host $HOST, e2e $IP1, e2e2 $IP2"

# The jump box side.
bin/xdr controller init --dir "$CTL" --name "$HOST" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e --out "$OUT/bundle" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e2 --out "$OUT/bundle2" >/dev/null || exit 1
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
# wait_rule SECONDS PATTERN: the signed set lists a rule matching PATTERN.
wait_rule() {
  for _ in $(seq $(($1 * 4))); do grep -q -- "$2" <<<"$(bin/xdr rules list --dir "$CTL")" && return 0; sleep 0.25; done
  return 1
}

# The box side. setup_box NAME BUNDLE, run with on: the agent, its fleet
# bundle, a config with both VMs as mesh peers, and a baseline.
setup_box() {
  local name=$1 bundle=$2
  lxc file push bin/xdr "$VM/usr/local/sbin/xdr" --mode 0755 || return 1
  x mkdir -p /etc/xdr/fleet /var/cache/xdr-e2e /opt/beacon
  for f in ca.pem host.pem host-key.pem rules.pub; do
    lxc file push "$bundle/$f" "$VM/etc/xdr/fleet/$f" --mode 0600 || return 1
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
    "dhcp_server": [host],
    "kill": True,
    "dns": {"resolver": host},
    "fleet": {"endpoints": [host + ":2379"]},
    "mesh": {"port": 7443},
}, indent=2))
PY
  lxc file push "$OUT/$name.json" "$VM$CONF" --mode 0600 || return 1
  echo "== capture baseline on $name"
  x xdr capture --root / --out "$BASE" || return 1
  x xdr listeners --config "$CONF" > "$OUT/$name.listeners.json" || return 1
  python3 - "$OUT/$name.json" "$OUT/$name.listeners.json" <<'PY' || return 1
import json, sys
c = json.load(open(sys.argv[1]))
c["listeners"] = json.load(open(sys.argv[2])) + [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}]
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
  lxc file push "$OUT/$name.json" "$VM$CONF" --mode 0600 || return 1
  # After the capture: the beacon and the unit are in no baseline. The
  # unit is the same file on both boxes.
  lxc file push "$OUT/beacon" "$VM/opt/beacon/beacon" --mode 0755 || return 1
  printf '[Service]\nExecStart=/opt/beacon/beacon 203.0.113.9:4446\n' > "$OUT/bad.service"
  lxc file push "$OUT/bad.service" "$VM/etc/systemd/system/xdr-e2e-bad.service" --mode 0644 || return 1
  x systemctl daemon-reload
}
on "$VM1" setup_box e2e "$OUT/bundle" || exit 1
on "$VM2" setup_box e2e2 "$OUT/bundle2" || exit 1
x cp /opt/beacon/beacon /usr/local/bin/helperd
# What the hunt from VM1's beacon kill is to find on VM2.
on "$VM2" x cp /opt/beacon/beacon /var/tmp/.cache-helper
BEACON_SUM=$(sha256sum "$OUT/beacon" | cut -d' ' -f1)
PY_SUM=$(x sh -c 'sha256sum "$(readlink -f /usr/bin/python3)"' | cut -d' ' -f1)
[ ${#PY_SUM} = 64 ] || { echo "no python3 hash: '$PY_SUM'"; exit 1; }

start_ctl || exit 1
CTL_STARTED=$(date +%s)
start_agent || { x cat "$ERR"; exit 1; }
on "$VM2" start_agent || { on "$VM2" x cat "$ERR"; exit 1; }
AGENTS_UP=$(date +%s)

echo "== enrolled"
sleep $((CTL_STARTED + 18 - $(date +%s)))
if [ "$(ctl_count 'agent-silent')" != 0 ]; then fail enrolled "controller: $(grep agent-silent "$CTLOUT")"
else ok enrolled; fi

echo "== mesh-up"
sleep $((AGENTS_UP + 20 - $(date +%s)))
silent1=$(x sh -c "grep -c peer-silent $LOG")
silent2=$(on "$VM2" x sh -c "grep -c peer-silent $LOG")
if [ -z "$(x ss -Htln 'sport = :7443')" ] || [ -z "$(on "$VM2" x ss -Htln 'sport = :7443')" ]; then
  fail mesh-up "no mesh listener: $(x grep -h mesh "$ERR" $LOG; on "$VM2" x grep -h mesh $LOG)"
elif [ "$silent1" != 0 ] || [ "$silent2" != 0 ]; then
  fail mesh-up "peer-silent: $(x grep -h peer-silent $LOG; on "$VM2" x grep -h peer-silent $LOG)"
else ok mesh-up; fi

echo "== beacon-killed"
mark
# Not the host: it is protected, so no rule may name it.
bg "/opt/beacon/beacon 203.0.113.9:4444"
if ! gone 5 '/opt/beacon/beacon'; then fail beacon-killed "the beacon still runs"
elif ! wait_inc 2 egress killed "i.get('exe') == '/opt/beacon/beacon'"; then fail beacon-killed "no egress/killed incident"
elif ! wait_ctl 3 2 'rule-promoted'; then fail beacon-killed "controller: $(cat "$CTLOUT")"
elif ! grep -q "hash $BEACON_SUM" <<<"$(bin/xdr rules list --dir "$CTL")"; then fail beacon-killed "no hash rule: $(bin/xdr rules list --dir "$CTL")"
else ok beacon-killed; fi

echo "== hunt-found"
# VM2 walks its whole disk; the window is 60 s.
if ! wait_ctl 90 1 'hunt-summary'; then fail hunt-found "no summary: $(grep hunt "$CTLOUT")"
elif ! grep 'hunt-summary' "$CTLOUT" | head -1 | grep -q 'found on e2e2'; then fail hunt-found "$(grep hunt "$CTLOUT"; on "$VM2" x grep -h hunt $LOG)"
else ok hunt-found; fi

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

echo "== unit-rule"
mark
x systemctl start --no-block xdr-e2e-bad.service
if ! wait_inc 5 egress killed "i.get('origin') == 'unit:xdr-e2e-bad.service' and i.get('origin_sha256')"; then
  fail unit-rule "no egress/killed incident from the unit: $(x tail -3 $LOG)"
elif ! wait_rule 5 ' unit xdr-e2e-bad.service@'; then
  fail unit-rule "no unit rule: $(bin/xdr rules list --dir "$CTL"; grep rule- "$CTLOUT" | tail -5)"
else
  sleep 3 # the new set reaches VM2
  on "$VM2" mark
  on "$VM2" x systemctl start --no-block xdr-e2e-bad.service
  if ! on "$VM2" wait_inc 5 rule-unit killed; then fail unit-rule "VM2: $(on "$VM2" x tail -3 $LOG)"
  else ok unit-rule; fi
fi

echo "== mesh-relay"
# VM2 can no longer reach etcd: its endpoint is a port nothing serves.
on "$VM2" stop_agent
on "$VM2" conf "c['fleet']['endpoints'] = ['$HOST:7443']"
on "$VM2" start_agent || fail mesh-relay "VM2's agent did not start: $(on "$VM2" x cat "$ERR")"
sleep 5
# rules_version: the version of the set a box has cached.
rules_version() {
  x python3 -c "import json, base64; e = json.load(open('/var/lib/xdr/rules.json')); print(json.loads(base64.b64decode(e['payload']))['version'])"
}
id=$(bin/xdr rules list --dir "$CTL" | awk '$2 == "remote" && $3 == "203.0.113.9:4445/tcp" {print $1}')
if [ -z "$id" ]; then fail mesh-relay "no remote rule to revoke: $(bin/xdr rules list --dir "$CTL")"
else
  want=$(bin/xdr rules revoke --dir "$CTL" "$id" | sed -n 's/.*version \([0-9]*\)$/\1/p')
  got=""
  for _ in $(seq 40); do
    got=$(on "$VM2" rules_version 2>/dev/null)
    [ "$got" = "$want" ] && break
    sleep 0.25
  done
  if [ -z "$want" ] || [ "$got" != "$want" ]; then fail mesh-relay "VM2 holds version '$got', want '$want'; VM1 holds $(rules_version)"
  else ok mesh-relay; fi
fi

echo "== peer-silent"
on "$VM2" mark
stop_agent
if ! on "$VM2" wait_inc 20 peer-silent ""; then fail peer-silent "VM2: $(on "$VM2" x tail -3 $LOG)"
else ok peer-silent; fi

on "$VM2" stop_agent
if [ $fails = 0 ]; then echo "E2E-FLEET PASS"; else echo "E2E-FLEET FAIL ($fails)"; exit 1; fi
