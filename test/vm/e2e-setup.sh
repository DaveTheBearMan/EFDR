#!/bin/bash
# deploy/setup.sh on real boxes: the jump box runs it, with --answers, for
# the controller and then for one target, with the lab's deploy key (put on
# the jump box only) and root as an auto account so the session survives
# the gate. Then: the controller is active and takes the password, the
# target's agent is active and up in the console, the recovery account was
# made and holds exactly the generated key, whose private half is 0600 on
# the jump box and nowhere on the target, and the password is in no output,
# journal or `ps` line seen during the runs. Bad answers (a host name, a
# port) are refused before anything is done; a second run, with answers and
# through the menu on stdin, changes nothing. First runs setup-shim.sh (the
# prompts, locally, with fakes). Prints "ok <case>" or "FAIL <case>: why"
# and ends with E2E-SETUP PASS. Runs on the ssh backend.
#   XDR_E2E_KEEP=1      leaves the boxes as they are (until the dead-man timer)
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=${XDR_E2E_BACKEND:-ssh}
[ "$XDR_E2E_BACKEND" = ssh ] || { echo "e2e-setup runs on the ssh backend"; exit 1; }

PW='e2e setup passphrase 7'
D=/root/xdr-day1
NAME=e2e
# shellcheck source=test/vm/lib.sh
. test/vm/lib.sh
VM=${XDR_E2E_VM:-${BOXES[0]}}

OUT=$(mktemp -d)
JCTL=$JROOT/ctl
JHOME=$JROOT/home
JRESET=$JROOT/xdr-e2e-reset
ctl_reset() { jb sh "$JRESET" controller >/dev/null 2>&1; }
cleanup() {
  if [ "${XDR_E2E_KEEP:-}" != 1 ]; then
    ctl_reset
    x rm -rf "$D"
    boxes_down "$VM"
  fi
  rm -rf "$OUT"
}

echo "== setup-shim"
if out=$(test/vm/setup-shim.sh 2>&1); then ok setup-shim; else fail setup-shim "$(grep FAIL <<<"$out")"; fi

trap cleanup EXIT
boxes_up "$VM" || exit 1
VM=$JUMP push test/vm/remote-reset.sh "$JRESET" 0755 || exit 1
ctl_reset
x rm -rf "$D"
HOST=$(jump_ip)
IP=$(ip_of "$VM")
echo "== jump box $HOST, $VM $IP"

# A kept run (XDR_E2E_KEEP=1) leaves its controller and setup files here.
jb rm -rf "$JCTL" "$JHOME" "$JROOT/ps.log" "$JROOT/cookies"
jb mkdir -p "$JROOT/deploy" || exit 1
for f in setup.sh prep-target.sh; do VM=$JUMP push "deploy/$f" "$JROOT/deploy/$f" 0755 || exit 1; done
VM=$JUMP push "$KEY" "$JROOT/deploykey" 0600 || exit 1
printf '%s\n' "$PW" >"$OUT/pw"
VM=$JUMP push "$OUT/pw" "$JROOT/pw" 0600 || exit 1
# watch.sh OUT PS CMD...: CMD, its output to OUT; every `ps` line while it runs to PS.
cat >"$OUT/watch.sh" <<'EOF'
#!/bin/bash
out=$1 ps=$2
shift 2
"$@" >"$out" 2>&1 </dev/null &
pid=$!
while kill -0 $pid 2>/dev/null; do ps -eo args >>"$ps"; sleep 0.1; done
wait $pid
EOF
VM=$JUMP push "$OUT/watch.sh" "$JROOT/watch.sh" 0755 || exit 1
T0=$(jb date +%s)
# setup TAG [ANSWERS LINES]: deploy/setup.sh --answers on the jump box;
# its output in $OUT/TAG.out, its exit in rc.
setup() {
  local tag=$1
  shift
  printf '%s\n' "$@" >"$OUT/$tag.ans"
  VM=$JUMP push "$OUT/$tag.ans" "$JROOT/$tag.ans" 0600 || return 1
  jb env XDR_SETUP_HOME="$JHOME" "$JROOT/watch.sh" "$JROOT/$tag.out" "$JROOT/ps.log" \
    "$JROOT/deploy/setup.sh" --xdr "$JXDR" --answers "$JROOT/$tag.ans"
  rc=$?
  jb cat "$JROOT/$tag.out" >"$OUT/$tag.out"
}
BASEURL=https://$HOST:8443
CJ=$JROOT/cookies
capi() { jb curl -sk -m 15 -b "$CJ" -c "$CJ" -H 'X-XDR: 1' "$@"; }
code() { jb curl -sk -m 15 -o /dev/null -w '%{http_code}' "$@"; }
state_has() {
  capi "$BASEURL/api/state" | python3 -c 'import json, sys; v = json.load(sys.stdin); sys.exit(0 if eval(sys.argv[1]) else 1)' "$1" 2>/dev/null
}
wait_state() { for _ in $(seq $(($1 * 2))); do state_has "$2" && return 0; sleep 0.5; done; return 1; }

CTL=(ACTION=controller "CONTROLLER_DIR=$JCTL" "JUMP_IP=$HOST" "CONSOLE_PASSWORD_FILE=$JROOT/pw" GRAY=gray1 AUTO=root RECOVERY=xdrrecover)
TGT=(ACTION=target "CONTROLLER_DIR=$JCTL" "TARGET_ADDR=$IP" SSH_USER=root "SSH_KEY=$JROOT/deploykey" BLUE=none GRAY=gray1
  AUTO=root RECOVERY=xdrrecover CREATE_RECOVERY=yes RECOVERY_KEY_MODE=generate KILL=off BASELINE=none REBUILD=no CONFIRM=yes)

echo "== controller"
setup ctl "${CTL[@]}"
up=""
for _ in $(seq 40); do [ "$(code "$BASEURL/api/state")" = 401 ] && { up=1; break; }; sleep 0.5; done
if [ $rc != 0 ]; then fail controller "exit $rc: $(tail -15 "$OUT/ctl.out")"
elif [ "$(jb systemctl is-active xdr-controller.service)" != active ]; then fail controller "xdr-controller.service is not active"
elif ! grep -q '^ok   xdr-controller.service is active' "$OUT/ctl.out" || ! grep -q "console: https://$HOST:8443" "$OUT/ctl.out"; then fail controller "its output: $(cat "$OUT/ctl.out")"
elif [ -z "$up" ]; then fail controller "the console does not answer"
elif [ "$(code -c "$CJ" -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" "$BASEURL/login")" != 204 ]; then fail controller "the console refuses the password"
else ok controller; fi

echo "== bad-answers"
ba=""
setup badname "${TGT[@]}" TARGET_NAME=E2e_box SCORED=tcp/8081
grep -q 'TARGET_NAME=E2e_box is rejected' "$OUT/badname.out" && [ $rc != 0 ] || ba="a bad host name: exit $rc: $(cat "$OUT/badname.out")"
setup badport "${TGT[@]}" TARGET_NAME=$NAME SCORED=tcp/8081,tcp/70000
grep -q 'SCORED=tcp/8081,tcp/70000 is rejected' "$OUT/badport.out" && [ $rc != 0 ] || ba="$ba a bad port: exit $rc: $(cat "$OUT/badport.out")"
if [ -n "$ba" ]; then fail bad-answers "$ba"
elif x test -e "$D" || jb test -e "$JCTL/hosts"; then fail bad-answers "something was done: $D on the target or a host enrolled"
else ok bad-answers; fi

echo "== target"
setup tgt "${TGT[@]}" TARGET_NAME=$NAME SCORED=tcp/8081
if [ $rc != 0 ]; then fail target "exit $rc: $(tail -25 "$OUT/tgt.out")"
elif ! grep -q '^ok   xdr-agent is active on' "$OUT/tgt.out" || ! grep -q '^ok   xdrrecover created on' "$OUT/tgt.out"; then fail target "its output: $(tail -25 "$OUT/tgt.out")"
elif [ "$(x systemctl is-active xdr-agent.service)" != active ]; then fail target "xdr-agent.service: $(x systemctl is-active xdr-agent.service)"
elif ! wait_state 40 "any(h['Name'] == '$NAME' and h['Status'] == 'up' and h['Kill'] != 'on' for h in v['Hosts'])"; then
  fail target "not up (kill not on) in the console: $(capi "$BASEURL/api/state" | python3 -c 'import json, sys; print(json.load(sys.stdin)["Hosts"])' 2>&1 | head -c 600)"
elif [ "$(x python3 -c 'import json; print(json.load(open("/etc/xdr/agent.json"))["kill"])')" != False ]; then fail target "the agent's config has kill on"
else ok target; fi

echo "== recovery"
PUB=$(jb cat "$JHOME/xdr-recovery/$NAME.pub")
# Line 4: the private half (line 2 is the same in every unencrypted ed25519 key).
PRIVLINE=$(jb sed -n 4p "$JHOME/xdr-recovery/$NAME")
held=""
for _ in $(seq 60); do [ "$(x cat /home/xdrrecover/.ssh/authorized_keys 2>/dev/null)" = "$PUB" ] && { held=1; break; }; sleep 0.5; done
if [ -z "$PUB" ] || [ -z "$PRIVLINE" ]; then fail recovery "no key pair in $JHOME/xdr-recovery"
elif ! x id -u xdrrecover >/dev/null; then fail recovery "xdrrecover was not created"
elif [ -z "$held" ]; then fail recovery "authorized_keys is not exactly the key: $(x cat /home/xdrrecover/.ssh/authorized_keys 2>&1 | head -c 300)"
elif [ "$(jb stat -c %a "$JHOME/xdr-recovery/$NAME")" != 600 ]; then fail recovery "the private key is $(jb stat -c %a "$JHOME/xdr-recovery/$NAME")"
elif x grep -rlF -- "$PRIVLINE" /root /home /etc /tmp /var/tmp /var/lib/xdr 2>/dev/null | grep -q .; then fail recovery "the private key is on the target"
else ok recovery; fi

echo "== no-password-leak"
jb journalctl --since "@$T0" --no-pager >"$OUT/journal" 2>/dev/null
jb cat "$JROOT/ps.log" >"$OUT/ps.log"
leak=$(grep -lF -- "$PW" "$OUT"/*.out "$OUT/journal" "$OUT/ps.log" "$OUT"/*.ans 2>/dev/null)
if [ ! -s "$OUT/ps.log" ]; then fail no-password-leak "no ps lines were captured"
elif ! grep -q 'deploy/setup.sh' "$OUT/ps.log"; then fail no-password-leak "the ps capture never saw setup.sh"
elif [ -n "$leak" ]; then fail no-password-leak "the password is in $leak"
else ok no-password-leak; fi

echo "== second-run"
snap() {
  jb sh -c "cd $JCTL && md5sum hosts controller.json console.json; md5sum $JHOME/xdr-setup/bundles/$NAME.tgz $JHOME/xdr-recovery/$NAME*; systemctl show -p MainPID --value xdr-controller.service"
  x sh -c "stat -c '%n %s %Y' $D/* /home/xdrrecover/.ssh/authorized_keys /etc/xdr/agent.json; systemctl show -p MainPID --value xdr-agent.service; ls /home"
}
snap >"$OUT/before" 2>&1
setup ctl2 "${CTL[@]}"
rc1=$rc
setup tgt2 "${TGT[@]}" TARGET_NAME=$NAME SCORED=tcp/8081
rc2=$rc
# Through the menu, on stdin: add the same target (dir, name, address,
# user root by default, key), then status, then quit.
printf '2\n%s\n%s\n%s\n\n%s\n3\n\n4\n' "$JCTL" "$NAME" "$IP" "$JROOT/deploykey" |
  ssh -F "$SSHCFG" "$JUMP" "XDR_SETUP_HOME=$JHOME $JROOT/deploy/setup.sh --xdr $JXDR" >"$OUT/menu.out" 2>&1
rc3=$?
snap >"$OUT/after" 2>&1
if [ $rc1 != 0 ] || ! grep -q 'nothing changed' "$OUT/ctl2.out"; then fail second-run "controller: exit $rc1: $(cat "$OUT/ctl2.out")"
elif [ $rc2 != 0 ] || ! grep -q 'XDR is already installed' "$OUT/tgt2.out"; then fail second-run "target: exit $rc2: $(cat "$OUT/tgt2.out")"
elif [ $rc3 != 0 ] || ! grep -q 'XDR is already installed' "$OUT/menu.out"; then fail second-run "menu: exit $rc3: $(tail -20 "$OUT/menu.out")"
elif ! grep -qE "^  $NAME +$IP +xdr-agent active" "$OUT/menu.out"; then fail second-run "menu status: $(grep -A3 'enrolled hosts' "$OUT/menu.out")"
elif ! diff "$OUT/before" "$OUT/after" >"$OUT/diff"; then fail second-run "something changed: $(cat "$OUT/diff")"
elif grep -qF -- "$PW" "$OUT/ctl2.out" "$OUT/tgt2.out" "$OUT/menu.out"; then fail second-run "the password was printed"
else ok second-run; fi

if [ $fails = 0 ]; then echo "E2E-SETUP PASS"; else echo "E2E-SETUP FAIL ($fails)"; exit 1; fi
