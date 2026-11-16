#!/bin/bash
# Self-protection and self-healing on real boxes: `xdr install` on the first
# target, then the agent is killed, its units stopped and their files
# deleted, a binary copy corrupted, the manifest rewritten by a stranger,
# the files tried by a gray account, the box cut off from the fleet by a
# foreign table and a blackhole route; the second target, never installed,
# is put in place by the controller's reinstall over SSH; last a signed
# uninstall token takes the install away again. The controller (with the
# console, whose state shows the hosts) runs on the jump box. Prints
# "ok <case>" or "FAIL <case>: why" and ends with E2E-PROTECT PASS. Runs on
# the ssh backend.
#   XDR_E2E_KEEP=1      leaves the boxes as they are (until their dead-man timers)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-protect runs on the ssh backend"; exit 1; }

CONF=/etc/xdr/agent.json
BASE=/var/cache/xdr-e2e/base.json.gz
LOG=/var/lib/xdr/incidents.jsonl
PW='e2e protect passphrase'
COPIES="/usr/local/sbin/xdr /usr/lib/xdr/xdr /var/lib/xdr/bin/xdr"
PINNED=/etc/xdr/pinned.sha256
MANIFEST=/var/lib/xdr/manifest.json
IBASE=/var/lib/xdr/baseline.json.gz
UNITS="xdr-agent.service xdr-guard-a.service xdr-guard-b.service xdr-ensure.timer"
# Everything install puts down besides the config, the bundle and the backup.
LAUNCH="/etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-guard-a.service /etc/systemd/system/xdr-guard-b.service"
LAUNCH="$LAUNCH /etc/systemd/system/xdr-ensure.service /etc/systemd/system/xdr-ensure.timer /etc/cron.d/xdr-ensure"
LAUNCH="$LAUNCH /usr/lib/systemd/system-generators/xdr-generator /etc/apt/apt.conf.d/99xdr /usr/lib/xdr/launch"
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh
VM=${XDR_E2E_VM:-${BOXES[0]}}
VM2=${XDR_E2E_VM2:-${BOXES[1]}}

OUT=$(mktemp -d)
CTL=$OUT/ctl
cleanup() {
  ctl_kill
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then boxes_down "$VM" "$VM2"; fi
  rm -rf "$OUT"
}
trap cleanup EXIT

boxes_up "$VM" "$VM2" || exit 1
HOST=$(jump_ip)
IP=$(ip_of "$VM")
IP2=$(ip_of "$VM2")
echo "== jump box $HOST, $VM $IP, $VM2 $IP2"

ssh-keygen -q -t ed25519 -N "" -C xdr-e2e -f "$OUT/key" || exit 1
PUB=$(cat "$OUT/key.pub")
uss() {
  local u=$1; shift
  ssh -F "$SSHCFG" -n -i "$OUT/key" -o IdentitiesOnly=yes -o ControlMaster=no -o ControlPath=none -l "$u" "$VM" "$@"
}
# active UNIT...: every one of them is active on the box.
active() {
  local s
  s=$(x systemctl is-active "$@" 2>/dev/null) || return 1
  [ "$(grep -cx active <<<"$s")" = $# ]
}
# within SECONDS CMD...: CMD succeeds within SECONDS; prints how long it took.
within() {
  local secs=$1 t0=$SECONDS; shift
  while [ $((SECONDS - t0)) -le "$secs" ]; do
    "$@" 2>/dev/null && { echo $((SECONDS - t0)); return 0; }
    sleep 0.5
  done
  return 1
}
pinned_ok() { # every copy matches the pinned hash
  x sh -c "p=\$(cat $PINNED) && for c in $COPIES; do [ \"\$(sha256sum \$c | cut -d' ' -f1)\" = \"\$p\" ] || exit 1; done"
}
agent_pid() { x systemctl show -p MainPID --value xdr-agent.service; }
dead() { x true && ! x kill -0 "$1" 2>/dev/null; }

# The jump box side, with the console on (its state shows the hosts), and the
# controller's reinstall key: the deploy key the targets already authorise,
# placed on the jump box only.
bin/xdr controller init --dir "$CTL" --name "$HOST" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e --out "$OUT/bundle" >/dev/null || exit 1
bin/xdr controller enroll --dir "$CTL" --host e2e2 --out "$OUT/bundle2" >/dev/null || exit 1
python3 - "$HOST" "$IP2" "$JROOT" > "$CTL/controller.json" <<'PY'
import json, sys
host, ip2, jroot = sys.argv[1:]
print(json.dumps({
    "listen": host + ":2379", "protect": [host], "gray_users": ["gray1"], "recovery": "xdrrecover", "auto": ["root"],
    "console": {"listen": host + ":8443"},
    # An hour, while the manual reinstall is tested; 20 s for the automatic one.
    "reinstall": {"key": jroot + "/reinstall.key", "user": "root", "after": "1h",
                  "hosts": {"e2e2": {"addr": ip2, "config": jroot + "/ctl/e2e2.json"}}},
}))
PY
# The second box's config: no baseline of its own there (the embedded one
# is empty in a test build), so it only reports.
python3 - "$HOST" > "$CTL/e2e2.json" <<'PY'
import json, sys
host = sys.argv[1]
print(json.dumps({"host": "e2e2", "jump": [host], "xdr_ports": [7443, 2379], "kill": False,
                  "scan": {"off": True}, "fleet": {"endpoints": [host + ":2379"]}}, indent=2))
PY
jsync "$CTL" || exit 1
VM=$JUMP push "$KEY" "$JROOT/reinstall.key" 0600 || exit 1
SIGN_DIR=$CTL
jx() { jb "$JXDR" "$@"; }
printf '%s\n' "$PW" | ssh -F "$SSHCFG" "$JUMP" "$JXDR controller console-password --dir $JCTL" >/dev/null || exit 1

# The first box: accounts before the baseline.
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
    # root (the harness) is a platform account: a kill leaves its session.
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
# The installed unit runs the agent on the embedded baseline (empty in a
# test build) and the one `xdr install --baseline` puts down: this box's
# capture.

ctl_run 1
for _ in $(seq 40); do grep -q '^console: https://' <<<"$(ctl_log)" && break; sleep 0.25; done
grep -q '^console: https://' <<<"$(ctl_log)" || { echo "the console did not start:"; ctl_log; exit 1; }

BASEURL=https://$HOST:8443
CJ=$JROOT/cookies
login() { jb curl -sk -m 15 -o /dev/null -c "$CJ" -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" "$BASEURL/login"; }
login || exit 1
state_has() {
  jb curl -sk -m 15 -b "$CJ" -H 'X-XDR: 1' "$BASEURL/api/state" |
    python3 -c 'import json, sys; v = json.load(sys.stdin); sys.exit(0 if eval(sys.argv[1]) else 1)' "$1" 2>/dev/null
}
host_up() { state_has 'any(h["Name"] == "'"$1"'" and h["Status"] == "up" for h in v["Hosts"])'; }
ctl_has() { grep -q -- "$1" <<<"$(ctl_log)"; }

echo "== install"
mark
out=$(x xdr install --config "$CONF" --baseline "$BASE" 2>&1)
bad=""
for _ in $(seq 60); do active $UNITS && break; sleep 0.5; done
active $UNITS || bad="$bad units-not-active($(x systemctl is-active $UNITS | tr '\n' ' '))"
pinned_ok || bad="$bad copies-differ-from-pinned"
[ "$(x cat $PINNED)" = "$(sha256sum bin/xdr | cut -d' ' -f1)" ] || bad="$bad pinned-is-not-this-build"
x test -s $MANIFEST || bad="$bad no-manifest"
for f in $COPIES $PINNED $MANIFEST $LAUNCH $CONF $IBASE /var/lib/xdr/backup/manifest.json; do
  x lsattr "$f" 2>/dev/null | cut -d' ' -f1 | grep -q i || bad="$bad not-immutable:$f"
done
# The unit passes the installed baseline.
x grep -q -- "--baseline $IBASE" /etc/systemd/system/xdr-agent.service || bad="$bad unit-without-baseline"
# The agent runs under its unit, from an installed copy.
exe=$(x readlink "/proc/$(agent_pid)/exe")
grep -qx "/usr/local/sbin/xdr" <<<"$exe" || bad="$bad agent-exe=$exe"
again=$(x xdr install --config "$CONF" 2>&1)
grep -q 'already installed; nothing changed' <<<"$again" || bad="$bad second-install:$again"
if [ -n "$bad" ]; then fail install "$bad; install said: $(tail -3 <<<"$out")"; else ok install; fi
within 30 host_up e2e >/dev/null || echo "note: e2e not up in the console yet"

echo "== restart-agent"
pid=$(agent_pid)
n0=$(x systemctl show -p NRestarts --value xdr-agent.service)
x kill -9 "$pid"
back() { p=$(agent_pid) && [ "$p" != 0 ] && [ "$p" != "$pid" ] && active xdr-agent.service; }
if ! t=$(within 5 back); then fail restart-agent "not back within 5 s: $(x systemctl status xdr-agent.service --no-pager | head -5)"
else
  n1=$(x systemctl show -p NRestarts --value xdr-agent.service)
  if [ "$n1" -gt "$n0" ]; then ok restart-agent; echo "   back in ${t} s, restarts $n0 -> $n1"
  else fail restart-agent "back in ${t} s, but not by the unit's restart (NRestarts $n0 -> $n1)"; fi
fi

echo "== stop-all-units"
since=$(x date '+%Y-%m-%d %H:%M:%S')
x systemctl stop $UNITS
down=$(x systemctl is-active $UNITS | tr '\n' ' ')
# The guards bring each other back at once; the timer and cron must also
# run ensure on their own within the 90 s.
cron_ran() { x journalctl --since "$since" -t CRON --no-pager | grep -q 'xdr ensure'; }
timer_ran() { x journalctl --since "$since" -u xdr-ensure.service --no-pager | grep -q 'Finished xdr-ensure.service'; }
if ! t=$(within 90 active $UNITS); then fail stop-all-units "not all back within 90 s: $(x systemctl is-active $UNITS | tr '\n' ' ')"
elif ! within 90 cron_ran >/dev/null; then fail stop-all-units "cron did not run ensure within 90 s"
elif ! within 30 timer_ran >/dev/null; then fail stop-all-units "the timer did not run ensure"
else ok stop-all-units; echo "   right after the stop: $down; all active after ${t} s; cron and the timer ran ensure"; fi

echo "== delete-unit-files"
mark
x sh -c "chattr -i /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-guard-b.service; rm -f /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-guard-b.service"
units_back() {
  x test -f /etc/systemd/system/xdr-agent.service && x test -f /etc/systemd/system/xdr-guard-b.service &&
    x sh -c "lsattr /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-guard-b.service | cut -d' ' -f1 | grep -c i | grep -qx 2"
}
if ! t=$(within 30 units_back); then fail delete-unit-files "not restored (and immutable) within 30 s"
elif ! within 30 active $UNITS >/dev/null; then fail delete-unit-files "restored, but not all active: $(x systemctl is-active $UNITS | tr '\n' ' ')"
elif x systemctl show -p NeedDaemonReload --value xdr-agent.service | grep -qx yes; then fail delete-unit-files "systemd was not reloaded"
else ok delete-unit-files; echo "   restored in ${t} s"; fi

echo "== corrupt-a-copy"
mark
C3=/var/lib/xdr/bin/xdr
x sh -c "chattr -i $C3; dd if=/dev/urandom of=$C3 bs=4k count=1 conv=notrunc status=none" 2>/dev/null
restored() { pinned_ok && x lsattr $C3 | cut -d' ' -f1 | grep -q i; }
if ! t=$(within 30 restored); then fail corrupt-a-copy "$C3 not restored within 30 s"
elif ! active xdr-agent.service; then fail corrupt-a-copy "the agent is not running"
elif ! wait_inc 15 tamper "" "i.get('path') == '$C3' and 'ensure' in i.get('detail', '')"; then
  fail corrupt-a-copy "restored in ${t} s, but no tamper incident from ensure: $(x sh -c "tail -n +$((MARK + 1)) $LOG | grep tamper | tail -4")"
else ok corrupt-a-copy; echo "   restored in ${t} s"; fi

echo "== tamper-kills-actor"
mark
x cp /bin/bash /tmp/xdr-e2e-actor
x cp /bin/sleep /tmp/xdr-e2e-sleep
# The actor rewrites the manifest with its own bytes (the box stays sane)
# and becomes a sleep copy from /tmp under the same pid.
master=$(x sh -c 'echo $PPID') # the harness's sshd session process
bg "/tmp/xdr-e2e-actor -c 'echo \$\$ > /tmp/xdr-e2e-actor.pid; c=\$(cat $MANIFEST); chattr -i $MANIFEST; printf %s \"\$c\" > $MANIFEST; exec /tmp/xdr-e2e-sleep 300'"
apid=""
for _ in $(seq 20); do apid=$(x cat /tmp/xdr-e2e-actor.pid 2>/dev/null) && [ -n "$apid" ] && break; sleep 0.1; done
t0=$SECONDS
if [ -z "$apid" ]; then fail tamper-kills-actor "the actor did not start"
elif ! within 2 dead "$apid" >/dev/null; then
  fail tamper-kills-actor "pid $apid ($(x readlink /proc/$apid/exe)) still runs after 2 s"
elif ! wait_inc 5 tamper killed "i['pid'] == $apid and i['severity'] == 'critical'"; then
  fail tamper-kills-actor "no Critical tamper/killed for pid $apid: $(x sh -c "tail -n +$((MARK + 1)) $LOG | grep tamper | tail -4")"
elif ! x true || ! x kill -0 "$master" 2>/dev/null; then fail tamper-kills-actor "the harness's root session went"
else ok tamper-kills-actor; echo "   killed pid $apid within $((SECONDS - t0)) s"; fi
x chattr +i $MANIFEST

echo "== tamper-by-gray"
mark
sum0=$(x sha256sum $MANIFEST $PINNED /usr/lib/xdr/xdr | sha256sum)
gout=$(uss gray1 sh -c "echo x >> $MANIFEST; echo x > $PINNED; cp /bin/true /usr/lib/xdr/xdr; rm -f /etc/systemd/system/xdr-agent.service; echo done" 2>&1)
sleep 3
sum1=$(x sha256sum $MANIFEST $PINNED /usr/lib/xdr/xdr | sha256sum)
if ! grep -q done <<<"$gout"; then fail tamper-by-gray "gray1 did not get a shell: $gout"
elif [ "$sum0" != "$sum1" ] || ! x test -f /etc/systemd/system/xdr-agent.service; then fail tamper-by-gray "gray1 changed the files: $gout"
elif ! grep -qi 'permission denied\|not permitted' <<<"$gout"; then fail tamper-by-gray "no permission error: $gout"
elif inc tamper killed; then fail tamper-by-gray "something was killed: $(x sh -c "tail -n +$((MARK + 1)) $LOG | grep tamper")"
else ok tamper-by-gray; fi

echo "== reinstall"
bad=""
on "$VM2" x test -e $MANIFEST && bad="$bad already-installed"
# (By size and hash: nothing of the key itself goes to the target.)
KEYSUM=$(sha256sum "$KEY" | cut -d' ' -f1)
keyfiles() {
  on "$VM2" x sh -c "find /etc /root /var/lib/xdr /usr/lib/xdr /usr/local/sbin /tmp /var/tmp -xdev -type f -size $(stat -c %s "$KEY")c -exec sha256sum {} + 2>/dev/null" |
    awk -v s="$KEYSUM" '$1 == s { print $2 }' | sort
}
keys_before=$(keyfiles)
rout=$(jx controller reinstall --dir "$JCTL" --host e2e2 2>&1) || bad="$bad reinstall-failed:$(tail -3 <<<"$rout")"
if [ -z "$bad" ]; then
  within 30 on "$VM2" active $UNITS >/dev/null || bad="$bad units:$(on "$VM2" x systemctl is-active $UNITS | tr '\n' ' ')"
  on "$VM2" pinned_ok || bad="$bad copies"
  within 40 host_up e2e2 >/dev/null || bad="$bad not-up-in-the-console"
  # The key stays on the jump box: no file on the target holds it now that did not before.
  keys_after=$(keyfiles)
  [ "$keys_after" = "$keys_before" ] || bad="$bad the-reinstall-key-on-the-target:$keys_after"
fi
if [ -n "$bad" ]; then fail reinstall "$bad"; else ok reinstall; fi

echo "== reinstall-auto"
# The controller again, its reinstall after 20 s of silence; then the
# second box's agent silenced: its units stopped, the box marked
# uninstalled so ensure and the guards stand down (as an uninstall by
# hand would leave it). The controller puts it back on its own.
bad=""
jb python3 -c "import json; p = '$JCTL/controller.json'; c = json.load(open(p)); c['reinstall']['after'] = '20s'; json.dump(c, open(p, 'w'))" || exit 1
ctl_kill
ctl_run 2
for _ in $(seq 40); do grep -q '^console: https://' <<<"$(ctl_log)" && break; sleep 0.25; done
login || bad="$bad console-login"
within 60 host_up e2e2 >/dev/null || bad="$bad e2e2-not-up-after-the-restart"
pid2=$(on "$VM2" agent_pid)
on "$VM2" x sh -c "touch /var/lib/xdr/uninstalled && systemctl stop $UNITS"
on "$VM2" active xdr-agent.service && bad="$bad the-agent-did-not-stop"
t0=$SECONDS
reinstalled() { ctl_has '^e2e2 .* reinstall repaired '; }
if [ -n "$bad" ]; then fail reinstall-auto "$bad"
elif ! within 180 reinstalled >/dev/null; then
  fail reinstall-auto "no reinstall within 180 s: $(ctl_log | grep -E '^e2e2 .*(silent|reinstall|back)' | tail -5 | tr '\n' ' ')"
else
  t=$((SECONDS - t0))
  ctl_has '^e2e2 .* agent-silent alert ' || bad="$bad no-agent-silent"
  ctl_has '^e2e2 .* reinstall alert ' || bad="$bad no-reinstall-alert"
  within 30 on "$VM2" active $UNITS >/dev/null || bad="$bad units:$(on "$VM2" x systemctl is-active $UNITS | tr '\n' ' ')"
  p=$(on "$VM2" agent_pid)
  { [ "$p" != 0 ] && [ "$p" != "$pid2" ]; } || bad="$bad agent-pid=$p(was-$pid2)"
  on "$VM2" x test -e /var/lib/xdr/uninstalled && bad="$bad still-marked-uninstalled"
  within 40 host_up e2e2 >/dev/null || bad="$bad not-up-in-the-console"
  if [ -n "$bad" ]; then fail reinstall-auto "$bad"; else ok reinstall-auto; echo "   reinstalled ${t} s after the silence began"; fi
fi

echo "== isolation-ladder"
mark
ctl_before=$(ctl_log | grep -c '^e2e .*isolation-over')
cat > "$OUT/evil.nft" <<EOF
table inet e2e_evil {
  chain out { type filter hook output priority -10; policy accept; ip daddr $HOST tcp dport 2379 drop; }
  chain in { type filter hook input priority -10; policy accept; ip saddr $HOST tcp dport 8081 drop; }
}
EOF
push "$OUT/evil.nft" /root/xdr-e2e-evil.nft 0600 || exit 1
# A net under the agent: if the ladder does nothing, this lifts the cut in
# 3 min so the harness gets back in (it is after every deadline below).
x systemd-run --unit=xdr-e2e-unblock --on-active=180 /bin/sh -c "ip route del blackhole $HOST/32; nft delete table inet e2e_evil" >/dev/null
# The cut comes 2 s after this command returns: it takes the harness's way in too.
bg "sh -c 'sleep 2; nft -f /root/xdr-e2e-evil.nft; ip route add blackhole $HOST/32'"
sleep 4
healed() { inc isolation-over healed; }
ctl_heard() { [ "$(ctl_log | grep -c '^e2e .*isolation-over')" -gt "$ctl_before" ]; }
if ! t=$(within 120 healed); then
  fail isolation-ladder "no isolation-over within 120 s: $(x sh -c "tail -n +$((MARK + 1)) $LOG | grep -E 'isolation|tamper' | tail -6")"
else
  bad=""
  inc isolation alert || bad="$bad no-isolation-alert"
  n_nft=$(x sh -c "tail -n +$((MARK + 1)) $LOG" | grep '"kind":"tamper"' | grep '"action":"removed"' | grep -c 'e2e_evil')
  n_rt=$(x sh -c "tail -n +$((MARK + 1)) $LOG" | grep '"kind":"tamper"' | grep '"action":"removed"' | grep -c 'blackhole')
  [ "$n_nft" = 1 ] || bad="$bad nft-removals=$n_nft"
  [ "$n_rt" = 1 ] || bad="$bad route-removals=$n_rt"
  x ip route show type blackhole | grep -q . && bad="$bad blackhole-still-there"
  x nft list table inet e2e_evil | grep -q 'dport 2379' && bad="$bad etcd-drop-still-there"
  x nft list table inet e2e_evil | grep -q 'dport 8081' || bad="$bad the-scored-rule-was-removed"
  within 30 ctl_heard >/dev/null || bad="$bad controller-never-heard-isolation-over"
  within 30 host_up e2e >/dev/null || bad="$bad not-up-in-the-console"
  [ -n "$bad" ] && bad="$bad; the box logged: $(x sh -c "tail -n +$((MARK + 1)) $LOG | grep -E 'isolation|tamper' | cut -c1-400")"
  if [ -n "$bad" ]; then fail isolation-ladder "$bad"; else ok isolation-ladder; echo "   healed in ${t} s"; fi
fi
x systemctl stop xdr-e2e-unblock.timer 2>/dev/null
x nft delete table inet e2e_evil 2>/dev/null

echo "== uninstall-token"
mark
bin/xdr controller mint-breakglass --dir "$CTL" --hosts e2e --action uninstall --from "$(date -u -d '-10 min' +%Y-%m-%dT%H:%M:%SZ)" \
  --every 2h --out "$OUT/tok" >/dev/null || exit 1
tok=$(cat "$OUT"/tok/*.tok)
uout=$(x /usr/local/sbin/xdr breakglass "$tok" 2>&1)
gone_all() {
  x sh -c "for f in $COPIES $PINNED $MANIFEST $LAUNCH $CONF $IBASE; do [ -e \$f ] && exit 1; done; [ ! -e /var/lib/xdr/backup ]" &&
    ! x nft list table inet xdr >/dev/null 2>&1 &&
    ! x pgrep -f '[x]dr (agent|guard|ensure)' >/dev/null
}
if ! within 30 gone_all >/dev/null; then
  fail uninstall-token "not all gone within 30 s (breakglass said: $uout): $(x sh -c "for f in $COPIES $PINNED $MANIFEST $LAUNCH $CONF /var/lib/xdr/backup; do [ -e \$f ] && echo \$f; done; nft list tables | grep xdr; pgrep -af '[x]dr (agent|guard|ensure)'; systemctl is-active $UNITS; tail -n +$((MARK + 1)) $LOG | grep uninstall" | tr '\n' ' ')"
else
  # A minute and more: cron, the timer and the guards would have had their turn.
  sleep 65
  bad=""
  gone_all || bad="$bad something-came-back"
  left=$(x sh -c "systemctl list-units --all --plain --no-legend 'xdr-*' | grep -v xdr-e2e; systemctl list-unit-files --plain --no-legend 'xdr-*' | grep -v xdr-e2e; ls /etc/systemd/system/*.wants /run/systemd/generator/*.wants 2>/dev/null | grep '^xdr-'")
  [ -n "$left" ] && bad="$bad units-left:$(tr '\n' ' ' <<<"$left")"
  imm=$(x sh -c "lsattr -R /etc/xdr /var/lib/xdr /usr/lib/xdr /etc/systemd/system /etc/cron.d 2>/dev/null | awk 'NF >= 2 && \$1 ~ /^[-a-zA-Z]+\$/ && \$1 ~ /i/'")
  [ -n "$imm" ] && bad="$bad immutable-left:$(tr '\n' ' ' <<<"$imm")"
  inc uninstall uninstalled || bad="$bad no-uninstall-incident"
  # The box can still be logged in to: no gate is left in PAM, and
  # sshd_config is the baseline's again (sshd reloaded, never restarted).
  x grep -q 'pam_exec.so.*gate' /etc/pam.d/sshd && bad="$bad the-gate-is-left-in-pam"
  x grep -q '^# Written by xdr' /etc/ssh/sshd_config && bad="$bad the-rendered-sshd_config-is-left"
  x sshd -t || bad="$bad sshd-t-refuses-the-restored-config"
  grep -q 'uninstall sent; the agent is removing the install' <<<"$uout" || bad="$bad breakglass-said:$uout"
  ssh -F "$SSHCFG" -n -o ControlMaster=no -o ControlPath=none "$VM" true || bad="$bad a-fresh-root-login-is-refused"
  if [ -n "$bad" ]; then fail uninstall-token "$bad"; else ok uninstall-token; fi
fi

if [ $fails = 0 ]; then echo "E2E-PROTECT PASS"; else echo "E2E-PROTECT FAIL ($fails)"; exit 1; fi
