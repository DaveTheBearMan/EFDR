#!/bin/bash
# deploy/setup.sh's questions, with fakes: ssh, xdr, systemctl, id and ip
# are shims in a temporary directory, so this runs anywhere and touches
# nothing outside it. The menu is fed on stdin (the controller, then "add a
# target" with bad answers it must ask again, status, the same target again)
# and --answers files are checked for what they must refuse. Prints "ok
# <case>" or "FAIL <case>: why" and ends with SETUP-SHIM PASS.
set -uo pipefail
cd "$(dirname "$0")/../.."
REPO=$PWD
T=$(mktemp -d)
trap '[ -n "${KEEP:-}" ] || rm -rf "$T"' EXIT
S=$T/shim
mkdir -p "$S" "$T/home"
fails=0
ok() { echo "ok $1"; }
fail() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
PW='shim console passphrase'

cat >"$S/id" <<'EOF'
#!/bin/bash
[ "${1:-}" = -u ] && [ $# = 1 ] && { echo 0; exit 0; }
exec /usr/bin/id "$@"
EOF
cat >"$S/systemctl" <<'EOF'
#!/bin/bash
echo active
EOF
cat >"$S/ip" <<'EOF'
#!/bin/bash
echo "1.1.1.1 via 192.0.2.1 dev eth0 src 192.0.2.7 uid 0"
EOF
# The target: its state is files in $SHIM.
cat >"$S/ssh" <<'EOF'
#!/bin/bash
args=()
while [ $# -gt 0 ]; do
  case $1 in -i | -o) shift 2 ;; -n) shift ;; *) break ;; esac
done
dest=$1; shift
[ "${1:-}" = -- ] && shift
cmd="$*"
printf '%s :: %s\n' "$dest" "$cmd" >>"$SHIM/ssh.log"
cmd=${cmd# }
case $cmd in
"id -u ") echo 0 ;;
"id -u xdrrecover ") [ -e "$SHIM/created" ] ;;
"useradd "*) touch "$SHIM/created" ;;
"sh -c test\\ -e"*) [ -e "$SHIM/installed" ] && exit 0; exit 1 ;;
"mkdir "* | "tar "*) ;;
"sh -c cat"*) cat >/dev/null ;;
*prep-target.sh*) cat <<'J'
{"host": "web01", "listeners": [{"proto": "tcp", "port": 22, "exe": "/usr/sbin/sshd"}],
 "accounts": [{"name": "alice", "uid": 1000, "shell": "/bin/bash", "home": "/home/alice"},
              {"name": "bob", "uid": 1001, "shell": "/bin/bash", "home": "/home/bob"}],
 "ports": [{"proto": "tcp", "port": 22, "local": "0.0.0.0:22"}, {"proto": "tcp", "port": 80, "local": "0.0.0.0:80"},
           {"proto": "tcp", "port": 80, "local": "[::]:80"}, {"proto": "tcp", "port": 443, "local": "0.0.0.0:443"}]}
J
;;
*install-target.sh*) echo "ok   xdr-agent.service is active"; touch "$SHIM/installed" ;;
"systemctl is-active xdr-agent"*) [ -e "$SHIM/installed" ] && echo active || { echo inactive; exit 3; } ;;
*) echo "shim ssh: unexpected $cmd" >&2; exit 99 ;;
esac
EOF
cat >"$S/xdr" <<'EOF'
#!/bin/bash
printf '%s\n' "$*" >>"$SHIM/xdr.log"
arg() { local k=$1; shift; while [ $# -gt 0 ]; do [ "$1" = "$k" ] && { echo "$2"; return; }; shift; done; }
case "$1 ${2:-}" in
"version "*) echo shim ;;
"controller install")
  d=$(arg --dir "$@")
  mkdir -p "$d"
  if [ ! -s "$d/console.json" ]; then cat >"$SHIM/pwin"; echo '{}' >"$d/console.json"; fi
  python3 -c 'import json, sys
print(json.dumps({"listen": sys.argv[2] + ":2379", "gray_users": [g for g in sys.argv[3].split(",") if g],
  "auto": [a for a in sys.argv[4].split(",") if a], "recovery": sys.argv[5], "console": {"listen": sys.argv[2] + ":8443"}}))' \
    x "$(arg --name "$@")" "$(arg --gray "$@")" "$(arg --auto "$@")" "$(arg --recovery "$@")" >"$d/controller.json" ;;
"controller add-target")
  echo bundle >"$(arg --out "$@")"
  echo "$(arg --host "$@")" >>"$(arg --dir "$@")/hosts" ;;
*) exit 2 ;;
esac
EOF
chmod +x "$S"/*
cp "$REPO/deploy/setup.sh" "$REPO/deploy/prep-target.sh" "$T/"
ssh-keygen -q -t ed25519 -N "" -f "$T/key" </dev/null
export SHIM=$T PATH=$S:$PATH XDR_SETUP_HOME=$T/home HOME=$T/home
run() { bash "$T/setup.sh" --xdr "$S/xdr" "$@"; }

echo "== syntax"
if bash -n "$REPO/deploy/setup.sh"; then ok syntax; else fail syntax "bash -n"; fi
if command -v shellcheck >/dev/null; then
  if shellcheck -S warning "$REPO/deploy/setup.sh"; then ok shellcheck; else fail shellcheck "warnings above"; fi
fi

echo "== menu"
{
  printf '1\n%s\n\ngray1\n\n\n' "$T/ctl"     # controller: dir, jump IP (the default), gray, auto, recovery
  printf 'short\nshort\n%s\n%s\n' "$PW" "$PW" # too short, then twice
  printf '2\n\nBad_Name\nweb01\n192.0.2.10\n\n%s\n' "$T/key" # target: dir, a bad name, address, user, key
  printf '1\n\ntcp/99999\n2,tcp/443\n'      # blue alice, gray (the controller's), a bad port, then tcp/80 and tcp/443
  printf '\n\n\n\n\n\ny\n'                   # recovery, create it, generate, auto, kill, baseline, go ahead
  printf '3\n\n'                             # status
  printf '2\n\n\n\n\n\n'                     # the same target again: all remembered
  printf '4\n'
} | run >"$T/out" 2>&1
rc=$?
at=$(grep 'controller add-target' "$T/xdr.log")
want="controller add-target --dir $T/ctl --host web01 --out $T/home/xdr-setup/bundles/web01.tgz --listeners $T/home/xdr-setup/web01-facts.json --scored tcp/80,tcp/443 --kill off --blue alice --gray gray1 --auto root --recovery xdrrecover --recovery-key $T/home/xdr-recovery/web01.pub"
if [ $rc != 0 ]; then fail menu "exit $rc: $(tail -20 "$T/out")"
elif [ "$(cat "$T/pwin" 2>/dev/null)" != "$PW" ]; then fail menu "controller install did not get the password on stdin"
elif ! grep -q 'controller install --dir '"$T/ctl"' --name 192.0.2.7 --gray gray1 --auto root --recovery xdrrecover$' "$T/xdr.log"; then fail menu "controller install: $(head -2 "$T/xdr.log")"
elif [ "$at" != "$want" ]; then fail menu "add-target: got [$at]"
elif [ "$(grep -c 'Bad_Name: a lower-case host name\|lower-case host name' "$T/out")" = 0 ]; then fail menu "the bad name was not refused"
elif ! grep -q 'tcp/99999: the port is not 1 to 65535' "$T/out"; then fail menu "the bad port was not refused"
elif ! grep -q 'the two do not match\|12 to 1024' "$T/out"; then fail menu "the short password was not refused"
elif [ "$(grep -c '^root@192.0.2.10 :: *useradd -m -s /bin/bash xdrrecover' "$T/ssh.log")" != 1 ]; then fail menu "useradd: $(grep useradd "$T/ssh.log")"
elif [ "$(stat -c %a "$T/home/xdr-recovery/web01")" != 600 ]; then fail menu "the private key is not 0600"
elif ! grep -q 'web01 .*192.0.2.10 .*xdr-agent active' "$T/out"; then fail menu "status: $(grep -A3 'enrolled hosts' "$T/out")"
elif ! grep -q 'XDR is already installed on 192.0.2.10' "$T/out"; then fail menu "the second add did not see the install"
elif [ "$(grep -c 'controller add-target' "$T/xdr.log")" != 1 ]; then fail menu "the second add ran add-target again"
elif grep -rqF "$PW" "$T/out" "$T/xdr.log" "$T/ssh.log"; then fail menu "the password is in the output or an argv"
else ok menu; fi

echo "== answers"
printf '%s\n' "$PW" >"$T/pw"
base="ACTION=target
CONTROLLER_DIR=$T/ctl
TARGET_ADDR=192.0.2.11
SSH_USER=root
SSH_KEY=$T/key
BLUE=alice
GRAY=gray1
SCORED=tcp/80
RECOVERY=xdrrecover
CREATE_RECOVERY=yes
RECOVERY_KEY_MODE=generate
AUTO=root
KILL=off
BASELINE=none
CONFIRM=yes"
n=$(wc -l <"$T/ssh.log")
check() { # CASE ANSWERS MESSAGE
  printf '%s\n' "$2" >"$T/ans"
  local o
  o=$(run --answers "$T/ans" 2>&1)
  if [ $? = 0 ]; then fail "$1" "accepted: $o"
  elif ! grep -q -- "$3" <<<"$o"; then fail "$1" "not the reason: $o"
  elif [ "$(wc -l <"$T/ssh.log")" != "$n" ]; then fail "$1" "it went to the target"
  else ok "$1"; fi
}
check answers-bad-name "$base
TARGET_NAME=Web_01" 'TARGET_NAME=Web_01 is rejected'
check answers-bad-port "$(sed 's#^SCORED=.*#SCORED=tcp/80,http#' <<<"$base")
TARGET_NAME=web02" 'SCORED=tcp/80,http is rejected'
check answers-missing "$base" 'TARGET_NAME is missing'
check answers-password-inline "$base
TARGET_NAME=web02
CONSOLE_PASSWORD=$PW" 'unknown key CONSOLE_PASSWORD'

if [ $fails = 0 ]; then echo "SETUP-SHIM PASS"; else echo "SETUP-SHIM FAIL ($fails)"; exit 1; fi
