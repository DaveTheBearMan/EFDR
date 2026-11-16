#!/bin/bash
# The operator's console on real boxes: the controller runs on the jump box
# with the console on, one target runs the agent with the SSH gate and the
# drift scan, and the console is driven through its HTTPS API from the jump
# box itself (curl -k, a cookie jar). It shows what the agent reports and
# every approval it offers is carried out on the box: sessions approved and
# killed, a dropped cron file removed and restored, a held scored process
# killed on the operator's click, a rotation, a break-glass token, and text
# with markup in it left as text. Prints "ok <case>" or "FAIL <case>: why"
# and ends with E2E-CONSOLE PASS. Runs on the ssh backend.
#   XDR_E2E_KEEP=1      leaves the box as it is (until its dead-man timer)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-console runs on the ssh backend"; exit 1; }

CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
GRACE=15
PW='e2e console passphrase'
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

CGO_ENABLED=0 go build -trimpath -o "$OUT/beacon" ./test/vm/beacon || exit 1
boxes_up "$VM" || exit 1
HOST=$(jump_ip)
IP=$(ip_of "$VM")
echo "== jump box $HOST, $VM $IP"

ssh-keygen -q -t ed25519 -N "" -C xdr-e2e -f "$OUT/key" || exit 1
PUB=$(cat "$OUT/key.pub")
uss() {
  local u=$1; shift
  ssh -F "$SSHCFG" -n -i "$OUT/key" -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none -l "$u" "$VM" "$@"
}
alive() { kill -0 "$1" 2>/dev/null; }

# The jump box side, with the console on.
bin/xdr controller init --dir "$CTL" --name "$HOST" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e --out "$OUT/bundle" >/dev/null || exit 1
printf '{"listen": "%s:2379", "protect": ["%s"], "gray_users": ["gray1"], "recovery": "xdrrecover", "auto": ["root"], "console": {"listen": "%s:8443"}}\n' \
  "$HOST" "$HOST" "$HOST" > "$CTL/controller.json"
jsync "$CTL" || exit 1
SIGN_DIR=$CTL
jx() { jb "$JXDR" "$@"; }
# The operator's password goes in on stdin, as it would by hand.
printf '%s\n' "$PW" | ssh -F "$SSHCFG" "$JUMP" "$JXDR controller console-password --dir $JCTL" >/dev/null || exit 1

# The box: accounts before the baseline, so alice is in it.
for u in alice gray1 xdrrecover; do
  x useradd -m -s /bin/bash "$u" || exit 1
  x sh -c "mkdir -p /home/$u/.ssh && echo '$PUB' > /home/$u/.ssh/authorized_keys && chown -R $u: /home/$u/.ssh && chmod 700 /home/$u/.ssh && chmod 600 /home/$u/.ssh/authorized_keys" || exit 1
done
push bin/xdr /usr/local/sbin/xdr 0755 || exit 1
x mkdir -p /etc/xdr/fleet /var/cache/xdr-e2e /opt/beacon
for f in ca.pem host.pem host-key.pem rules.pub; do
  push "$OUT/bundle/$f" /etc/xdr/fleet/$f 0600 || exit 1
done
echo "== capture baseline"
x xdr capture --root / --out "$BASE" || exit 1
python3 - "$HOST" "$PUB" > "$OUT/agent.json" <<'PY'
import json, sys
host, pub = sys.argv[1:]
print(json.dumps({
    "host": "e2e",
    "jump": [host],
    "xdr_ports": [7443, 2379],
    "listeners": [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}],
    "scored": [{"proto": "tcp", "port": 8081}],
    "gray_users": ["gray1"],
    "kill": True,
    "scan": {"interval": "5s"},
    "fleet": {"endpoints": [host + ":2379"]},
    "ssh": {"blue_users": ["alice"], "recovery": "xdrrecover", "recovery_key": pub, "auto": ["root"], "grace": "15s"},
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
# After the capture: the beacon is in no baseline.
push "$OUT/beacon" /opt/beacon/beacon 0755 || exit 1

ctl_run 1
for _ in $(seq 40); do grep -q '^console: https://' <<<"$(ctl_log)" && break; sleep 0.25; done
grep -q '^console: https://' <<<"$(ctl_log)" || { echo "the console did not start:"; ctl_log; exit 1; }
start_agent || { x cat "$ERR"; exit 1; }

BASEURL=https://$HOST:8443
CJ=$JROOT/cookies
# capi METHOD PATH [JSON]: the console's API from the jump box, with the cookie jar.
capi() {
  local m=$1 p=$2 body=${3:-}
  if [ -n "$body" ]; then
    jb curl -sk -m 15 -b "$CJ" -c "$CJ" -X "$m" -H 'X-XDR: 1' -H 'Content-Type: application/json' -d "$body" "$BASEURL$p"
  else
    jb curl -sk -m 15 -b "$CJ" -c "$CJ" -X "$m" -H 'X-XDR: 1' "$BASEURL$p"
  fi
}
code() { jb curl -sk -m 15 -o /dev/null -w '%{http_code}' "$@"; }
# state_has PYEXPR: the view (v) satisfies the expression.
state_has() {
  capi GET /api/state | python3 -c 'import json, sys; v = json.load(sys.stdin); sys.exit(0 if eval(sys.argv[1]) else 1)' "$1" 2>/dev/null
}
wait_state() { for _ in $(seq $(($1 * 2))); do state_has "$2" && return 0; sleep 0.5; done; return 1; }
# approval_id PYCOND: the id of the first approval a satisfying a.
approval_id() {
  capi GET /api/state | python3 -c '
import json, sys
v = json.load(sys.stdin)
for a in v["Approvals"]:
    if eval(sys.argv[1]):
        print(a["ID"])
        break' "$1" 2>/dev/null
}
wait_approval() {
  local id=""
  for _ in $(seq $(($1 * 2))); do id=$(approval_id "$2"); [ -n "$id" ] && { echo "$id"; return 0; }; sleep 0.5; done
  return 1
}
decide() { capi POST /api/decide "{\"id\": \"$1\", \"action\": \"$2\"}"; }
sleep 8 # the agent has joined and made its first scan

echo "== auth"
bad=""
[ "$(code "$BASEURL/api/state")" = 401 ] || bad="$bad no-cookie-not-401"
[ "$(code -X POST -H 'Content-Type: application/json' -d '{"password":"wrong password here"}' "$BASEURL/login")" = 401 ] || bad="$bad wrong-password-not-401"
[ "$(code -c "$CJ" -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" "$BASEURL/login")" = 204 ] || bad="$bad login-failed"
[ "$(code -b "$CJ" "$BASEURL/api/state")" = 200 ] || bad="$bad cookie-not-200"
[ "$(code -b "$CJ" -X POST -H 'Content-Type: application/json' -d '{}' "$BASEURL/api/decide")" = 403 ] || bad="$bad post-without-header-not-403"
if jb curl -skI -m 15 "$BASEURL/" | tr -d '\r' | grep -qi "^content-security-policy: default-src 'none'"; then :; else bad="$bad no-csp"; fi
if [ -n "$bad" ]; then fail auth "$bad"; else ok auth; fi

echo "== state"
if ! wait_state 20 'any(h["Name"] == "e2e" and h["Status"] == "up" for h in v["Hosts"]) and v["Summary"]["AgentsTotal"] == 1'; then
  fail state "$(capi GET /api/state | head -c 600)"
else ok state; fi

echo "== session-approve"
uss alice sleep 90 & p=$!; pids+=($p)
id=$(wait_approval 20 'a["Kind"] == "session" and a["Host"] == "e2e"') || id=""
if [ -z "$id" ]; then fail session-approve "no pending session in the approvals: $(capi GET /api/state | head -c 600)"
elif ! state_has 'any(a["ID"] == "'"$id"'" and a["Deadline"] > v["Now"] for a in v["Approvals"])'; then fail session-approve "no deadline"
else
  decide "$id" approve >/dev/null || fail session-approve "decide failed"
  sleep $((GRACE + 10))
  if alive $p; then ok session-approve; else fail session-approve "session $id ended after the approval: $(x tail -3 $LOG)"; fi
  # A second click is refused.
  if [ "$(code -b "$CJ" -X POST -H 'X-XDR: 1' -H 'Content-Type: application/json' -d "{\"id\":\"$id\",\"action\":\"approve\"}" "$BASEURL/api/decide")" != 409 ]; then fail session-approve "a second click was not refused with 409"; fi
fi
kill $p 2>/dev/null

echo "== session-kill"
uss alice sleep 90 & p=$!; pids+=($p)
id=$(wait_approval 20 'a["Kind"] == "session" and a["Host"] == "e2e"') || id=""
if [ -z "$id" ]; then fail session-kill "no pending session"
else
  decide "$id" kill >/dev/null || fail session-kill "decide failed"
  for _ in $(seq 40); do alive $p || break; sleep 0.25; done
  if alive $p; then fail session-kill "session $id still alive after the kill: $(x tail -3 $LOG)"; else ok session-kill; fi
fi

echo "== drift-and-remove"
EVIL=/etc/cron.d/xdr-e2e-evil
x sh -c "printf '%s\n' '* * * * * root /tmp/xdr-e2e-x' > $EVIL && chmod 644 $EVIL"
want=$(x sha256sum $EVIL | cut -d' ' -f1)
id=$(wait_approval 45 'a["Kind"] == "file" and a["Params"].get("path") == "'"$EVIL"'" and "remove" in a["Actions"]') || id=""
if [ -z "$id" ]; then fail drift-and-remove "no file approval within 45 s: $(capi GET /api/state | head -c 600)"
else
  decide "$id" remove >/dev/null || fail drift-and-remove "decide failed"
  gone=""
  for _ in $(seq 40); do x test -e $EVIL || { gone=1; break; }; sleep 0.25; done
  uid=$(wait_approval 20 'a["Kind"] == "file" and "undo" in a["Actions"] and a["Params"].get("path") == "'"$EVIL"'"') || uid=""
  if [ -z "$gone" ]; then fail drift-and-remove "the file is still on the box: $(x tail -3 $LOG)"
  elif [ -z "$uid" ]; then fail drift-and-remove "no undo entry after the removal"
  else
    decide "$uid" undo >/dev/null || fail drift-and-remove "undo failed"
    back=""
    for _ in $(seq 40); do x test -e $EVIL && { back=1; break; }; sleep 0.25; done
    if [ -z "$back" ] || [ "$(x sha256sum $EVIL | cut -d' ' -f1)" != "$want" ]; then fail drift-and-remove "the file did not come back byte for byte"
    else ok drift-and-remove; fi
  fi
fi
x rm -f $EVIL

echo "== held-kill"
# A scored-port process that also dials out: held, never killed unasked.
bg "/opt/beacon/beacon listen :8081 203.0.113.9:4445"
id=$(wait_approval 20 'a["Kind"] == "proc" and a["Host"] == "e2e" and "beacon" in a["Title"]') || id=""
if [ -z "$id" ]; then fail held-kill "no held process in the approvals; the box logged: $(x grep -h beacon $LOG | tail -3 | head -c 900)"
elif ! x pgrep -f 'beacon listen' >/dev/null; then fail held-kill "the scored process was killed with no approval"
else
  sleep 3
  if ! x pgrep -f 'beacon listen' >/dev/null; then fail held-kill "it died on its own before the click"
  else
    decide "$id" kill >/dev/null || fail held-kill "decide failed"
    if gone 8 'beacon listen'; then ok held-kill; else fail held-kill "the process still runs after the kill: $(x tail -3 $LOG)"; fi
  fi
fi

echo "== creds"
before=$(x getent shadow alice | cut -d: -f2)
rot=$(capi POST /api/rotate '{"host": "e2e", "users": ["alice"], "samba": []}')
pw=$(capi GET /api/creds | python3 -c 'import json, sys; c = json.load(sys.stdin); print([e["Password"] for e in c["entries"] if e["Account"] == "alice" and e["Host"] == "e2e"][0])' 2>/dev/null)
after=""
for _ in $(seq 40); do after=$(x getent shadow alice | cut -d: -f2); [ "$after" != "$before" ] && break; sleep 0.25; done
block=$(capi GET /api/creds | python3 -c 'import json, sys; print(json.load(sys.stdin)["block"])' 2>/dev/null)
if [ ${#pw} != 20 ]; then fail creds "no 20-character password: $rot"
elif [ "${after:0:3}" != '$6$' ] || [ "$after" = "$before" ]; then fail creds "shadow '$after' (was '$before')"
elif ! grep -qP "^e2e\tssh\talice\t$pw\$" <<<"$block"; then fail creds "copy-all block: $block"
elif x grep -q "$pw" $LOG; then fail creds "the password is in the box's log"
elif [ "$(code -b "$CJ" -X POST -H 'X-XDR: 1' -H 'Content-Type: application/json' -d '{"host":"e2e","users":["gray1"]}' "$BASEURL/api/rotate")" != 400 ]; then fail creds "gray1 was not refused"
else ok creds; fi

echo "== breakglass"
tok=$(capi POST /api/breakglass '{"host": "e2e", "action": "pause", "minutes": 30}' | python3 -c 'import json, sys; print(json.load(sys.stdin)["token"])' 2>/dev/null)
out=$(printf '%s\n' "$tok" | xin /usr/local/sbin/xdr breakglass - 2>&1)
if [ -z "$tok" ]; then fail breakglass "no token"
elif ! grep -q 'pause' <<<"$out"; then fail breakglass "the box did not take it: $out"
elif [ "$(code -b "$CJ" -X POST -H 'X-XDR: 1' -H 'Content-Type: application/json' -d '{"host":"nope","action":"pause","minutes":30}' "$BASEURL/api/breakglass")" != 400 ]; then fail breakglass "a token for a host that is not enrolled"
else ok breakglass; fi

echo "== hostile-text"
HOSTILE='<img src=x onerror=alert(1)>'
x sh -c "printf '%s\n' '* * * * * root /tmp/h' > '/etc/cron.d/$HOSTILE'"
if ! wait_state 45 'any("<img src=x onerror=alert(1)>" in a["Title"] for a in v["Approvals"])'; then fail hostile-text "the hostile file name never reached the approvals"
else
  ctype=$(jb curl -skI -m 15 "$BASEURL/app.js" | tr -d '\r' | grep -i '^content-type' | head -1)
  if ! grep -qi 'javascript' <<<"$ctype"; then fail hostile-text "app.js content type: $ctype"
  elif jb curl -sk -m 15 "$BASEURL/app.js" | grep -q 'innerHTML'; then fail hostile-text "the served script uses innerHTML"
  else ok hostile-text; fi
fi
x rm -f "/etc/cron.d/$HOSTILE"

stop_agent
if [ $fails = 0 ]; then echo "E2E-CONSOLE PASS"; else echo "E2E-CONSOLE FAIL ($fails)"; exit 1; fi
