#!/bin/bash
# The SSH gate end to end on one box, with the controller on the jump box:
# sshd and PAM are rendered from the signed config; an unapproved session
# is ended after the grace; an approval by the controller or a break-glass
# token from inside the session keeps it; a gray session is left alone; a
# new account is locked; with the agent dead, blue logins are refused,
# recovery still gets in, and a pause token lets blue in; a rotation sends
# a hash only. Logins come through the jump box, as they must. Runs on the
# ssh backend (inventory.ini). Prints "ok <case>" or "FAIL <case>: why" and
# ends with E2E-GATE PASS.
#   XDR_E2E_KEEP=1      leaves the box as it is (until its dead-man timer)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-gate runs on the ssh backend"; exit 1; }

CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
GRACE=15
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh
VM=${XDR_E2E_VM:-${BOXES[0]}}

OUT=$(mktemp -d)
CTL=$OUT/ctl
pids=()
cleanup() {
  for p in "${pids[@]}"; do kill "$p" 2>/dev/null; done
  ctl_kill
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then boxes_down "$VM"; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

boxes_up "$VM" || exit 1
HOST=$(jump_ip)
IP=$(ip_of "$VM")
DHCP=$(dhcp_server)
echo "== jump box $HOST, $VM $IP"

# The test accounts' key.
ssh-keygen -q -t ed25519 -N "" -C xdr-e2e -f "$OUT/key" || exit 1
PUB=$(cat "$OUT/key.pub")
# uss USER CMD...: log in as USER through the jump box, as a person would.
uss() {
  local u=$1; shift
  ssh -F "$SSHCFG" -n -i "$OUT/key" -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none -l "$u" "$VM" "$@"
}
# alive PID: the background login PID still runs.
alive() { kill -0 "$1" 2>/dev/null; }

# The jump box side.
bin/xdr controller init --dir "$CTL" --name "$HOST" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e --out "$OUT/bundle" >/dev/null || exit 1
printf '{"listen": "%s:2379", "protect": ["%s"], "gray_users": ["gray1"], "recovery": "xdrrecover", "auto": ["root"]}\n' \
  "$HOST" "$HOST" > "$CTL/controller.json"
jsync "$CTL" || exit 1
SIGN_DIR=$CTL
jx() { jb "$JXDR" "$@"; }
FROM=$(date -u -d '-10 min' +%Y-%m-%dT%H:%M:%SZ)
for act in approve-session pause; do
  bin/xdr controller mint-breakglass --dir "$CTL" --hosts e2e --action $act --from "$FROM" --every 2h --count 1 --out "$OUT/tok-$act" >/dev/null || exit 1
done
APPROVE=$(cat "$OUT"/tok-approve-session/*.tok)
PAUSE=$(cat "$OUT"/tok-pause/*.tok)

# The box: accounts before the baseline, so alice is in it.
for u in alice gray1 xdrrecover; do
  x useradd -m -s /bin/bash "$u" || exit 1
  x sh -c "mkdir -p /home/$u/.ssh && echo '$PUB' > /home/$u/.ssh/authorized_keys && chown -R $u: /home/$u/.ssh && chmod 700 /home/$u/.ssh && chmod 600 /home/$u/.ssh/authorized_keys" || exit 1
done
push bin/xdr /usr/local/sbin/xdr 0755 || exit 1
x mkdir -p /etc/xdr/fleet /var/cache/xdr-e2e
for f in ca.pem host.pem host-key.pem rules.pub; do
  push "$OUT/bundle/$f" /etc/xdr/fleet/$f 0600 || exit 1
done
echo "== capture baseline"
x xdr capture --root / --out "$BASE" || exit 1
python3 - "$HOST" "$IP" "$DHCP" "$PUB" > "$OUT/agent.json" <<'PY'
import json, sys
host, ip, dhcp, pub = sys.argv[1:]
print(json.dumps({
    "host": "e2e",
    "jump": [host],
    "xdr_ports": [7443, 2379],
    "listeners": [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}],
    "dhcp_server": [dhcp],
    "gray_users": ["gray1"],
    "kill": True,
    "dns": {"resolver": host},
    "fleet": {"endpoints": [host + ":2379"]},
    "ssh": {"blue_users": ["alice"], "recovery": "xdrrecover", "recovery_key": pub,
            "auto": ["root"], "grace": "15s"},
}, indent=2))
PY
push_conf "$OUT/agent.json" || exit 1
x xdr listeners --config "$CONF" > "$OUT/listeners.json" || exit 1
python3 - "$OUT/agent.json" "$OUT/listeners.json" <<'PY' || exit 1
import json, sys
c = json.load(open(sys.argv[1]))
c["listeners"] = json.load(open(sys.argv[2])) + [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}]
json.dump(c, open(sys.argv[1], "w"), indent=2)
PY
push_conf "$OUT/agent.json" || exit 1

starts_ctl=0
ctl_run 1
for _ in $(seq 40); do grep -q '^controller: listening' <<<"$(ctl_log)" && break; sleep 0.25; done
start_agent || { x cat "$ERR"; exit 1; }
sleep 4 # the first guard tick renders sshd and PAM

echo "== render"
T=$(x sshd -T -C "user=alice,host=x,addr=$HOST")
if ! grep -q '^passwordauthentication no' <<<"$T"; then fail render "passwords on: $(grep -i password <<<"$T")"
elif ! grep -q "^allowusers alice@$HOST" <<<"$T" || ! grep -q '^allowusers gray1$' <<<"$T"; then fail render "AllowUsers: $(grep allowusers <<<"$T")"
elif ! x grep -q 'pam_exec.so quiet /usr/local/sbin/xdr gate' /etc/pam.d/sshd; then fail render "no gate in pam.d/sshd"
elif ! x grep -q 'pam_succeed_if.so quiet user in gray1:xdrrecover' /etc/pam.d/sshd; then fail render "no exempt line"
else ok render; fi

# session_of USER: the id in USER's last session-pending since mark.
session_of() {
  x sh -c "cat $LOG" | tail -n +$((MARK + 1)) | python3 -c '
import json, re, sys
ids = [re.match(r"session (\S+) ", i["detail"]).group(1) for i in map(json.loads, sys.stdin)
       if i["kind"] == "session-pending" and i.get("user") == sys.argv[1]]
print(ids[-1] if ids else "")' "$1"
}

echo "== pending-terminated"
mark
start=$(date +%s)
uss alice sleep 60 & p=$!; pids+=($p)
for _ in $(seq $(((GRACE + 10) * 4))); do alive $p || break; sleep 0.25; done
took=$(($(date +%s) - start))
if alive $p; then fail pending-terminated "alive after $took s"
elif ! inc session-pending "" "i.get('user') == 'alice'"; then fail pending-terminated "no session-pending: $(x tail -3 $LOG)"
elif ! wait_inc 3 session-terminated killed "i.get('user') == 'alice'"; then fail pending-terminated "no session-terminated: $(x tail -3 $LOG)"
elif [ $took -lt $((GRACE - 1)) ]; then fail pending-terminated "ended after $took s, before the grace"
elif ! grep -q 'session-terminated' <<<"$(ctl_log)"; then fail pending-terminated "the controller did not hear of it"
else ok pending-terminated; fi

echo "== approved"
mark
uss alice sleep 60 & p=$!; pids+=($p)
id=""
for _ in $(seq 40); do id=$(session_of alice); [ -n "$id" ] && break; sleep 0.25; done
if [ -z "$id" ]; then fail approved "no session-pending"
else
  jx controller approve-session --dir "$JCTL" --host e2e "$id" >/dev/null || fail approved "approve-session failed"
  sleep $((GRACE + 10))
  if alive $p; then ok approved; else fail approved "session $id ended: $(x tail -3 $LOG)"; fi
fi
kill $p 2>/dev/null

echo "== own-session-breakglass"
mark
uss alice "/usr/local/sbin/xdr breakglass '$APPROVE' && sleep 60" > "$OUT/bg.out" 2>&1 & p=$!; pids+=($p)
sleep $((GRACE + 10))
if alive $p && wait_inc 2 breakglass "" "'approve-session' in i.get('detail', '')"; then ok own-session-breakglass
else fail own-session-breakglass "alive? $(alive $p && echo yes || echo no); $(cat "$OUT/bg.out"); $(x grep -h breakglass $LOG)"; fi
kill $p 2>/dev/null

echo "== gray-untouched"
mark
uss gray1 sleep 60 & p=$!; pids+=($p)
sleep $((GRACE + 10))
if ! alive $p; then fail gray-untouched "gray session ended: $(x tail -3 $LOG)"
elif ! wait_inc 3 session alert "i.get('user') == 'gray1'"; then
  fail gray-untouched "no session alert: $(x loginctl list-sessions --no-legend); $(x grep -h gray1 $LOG | tail -3); $(x grep -h 'sessions:' "$ERR" | tail -2)"
else ok gray-untouched; fi
kill $p 2>/dev/null

echo "== new-user-disabled"
mark
x useradd -m -s /bin/bash evil
# A new account with no password already shows L; the expiry is the agent's.
if ! wait_inc 5 user-disabled repaired "i.get('user') == 'evil'"; then fail new-user-disabled "no user-disabled: $(x tail -3 $LOG)"
elif [ "$(x passwd -S evil | awk '{print $2}')" != L ] || [ "$(x getent shadow evil | cut -d: -f8)" != 1 ]; then
  fail new-user-disabled "not locked and expired: $(x getent shadow evil | cut -d: -f1,3-)"
else ok new-user-disabled; fi

echo "== agent-dead"
stop_agent
if uss alice true 2>/dev/null; then fail agent-dead "alice got in with the agent dead"
elif ! uss xdrrecover true; then fail agent-dead "recovery locked out"
else
  out=$(uss xdrrecover /usr/local/sbin/xdr breakglass "$PAUSE")
  if ! grep -q 'agent down: token spooled' <<<"$out"; then fail agent-dead "breakglass: $out"
  elif ! uss alice true; then fail agent-dead "alice still refused with a pause token spooled"
  else ok agent-dead; fi
fi
start_agent || { fail agent-dead "agent did not start again: $(x cat "$ERR")"; }

echo "== rotate"
before=$(x getent shadow alice | cut -d: -f2)
out=$(jx controller rotate --dir "$JCTL" --host e2e --users alice)
pw=$(awk -F'\t' '$3 == "alice" {print $4}' <<<"$out")
after=""
for _ in $(seq 40); do after=$(x getent shadow alice | cut -d: -f2); [ "$after" != "$before" ] && break; sleep 0.25; done
if [ ${#pw} != 20 ]; then fail rotate "rotate printed: $out"
elif [ "${after:0:3}" != '$6$' ] || [ "$after" = "$before" ]; then fail rotate "shadow '$after' (was '$before')"
elif ! jx controller creds --dir "$JCTL" | grep -qP "^e2e\tssh\talice\t$pw$"; then fail rotate "creds: $(jx controller creds --dir "$JCTL")"
elif jx controller rotate --dir "$JCTL" --host e2e --users gray1 >/dev/null 2>&1; then fail rotate "gray1 rotated"
elif x grep -q "$pw" $LOG; then fail rotate "the password is in the box's log"
else ok rotate; fi

stop_agent
if [ $fails = 0 ]; then echo "E2E-GATE PASS"; else echo "E2E-GATE FAIL ($fails)"; exit 1; fi
