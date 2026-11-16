#!/bin/bash
# install-target.sh: puts XDR on this box from the bundle `xdr controller
# add-target` made. Run it as root in the directory the bundle was unpacked
# in, with the xdr binary copied beside it:
#   ./install-target.sh [--no-install] [--again] [--binary FILE]
#     --no-install  put the bundle, config and baseline down; do not run xdr install
#     --again       install over an existing install (pause the agent first)
#     --binary FILE the xdr binary (default: ./xdr beside this script)
# It never touches sshd or PAM itself: the agent does that, from its config.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
BIN=$HERE/xdr
NO_INSTALL=0
AGAIN=0
ETC=/etc/xdr
STATE=/var/lib/xdr
CAPTURE=$STATE/day1-baseline.json.gz

die() { echo "install-target: $*" >&2; exit 1; }
usage() { sed -n '2,10s/^# \{0,1\}//p' "$0"; }
while [ $# -gt 0 ]; do
  case $1 in
  --no-install) NO_INSTALL=1 ;;
  --again) AGAIN=1 ;;
  --binary) [ $# -ge 2 ] || die "--binary needs a file"; BIN=$2; shift ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || die "run me as root"
[ -f "$BIN" ] && [ -x "$BIN" ] || die "no xdr binary at $BIN: copy bin/xdr next to this script (or give --binary FILE)"
for f in agent.json agent.json.sig fleet/ca.pem fleet/host.pem fleet/host-key.pem fleet/rules.pub; do
  [ -s "$HERE/$f" ] || die "$HERE/$f is missing: unpack the whole add-target bundle here"
done

if [ -e $STATE/manifest.json ] || [ -e $ETC/pinned.sha256 ] || [ -e /etc/systemd/system/xdr-agent.service ]; then
  if [ $AGAIN = 0 ]; then
    cat >&2 <<'EOF'
install-target: XDR is already installed on this box: refusing.
Installing over a running agent rewrites the files it guards; that is tamper
and this script's process tree is killed. To install again:
  1. mint a pause token for this host in the console (Hosts, break-glass, pause)
  2. on this box:  /usr/local/sbin/xdr breakglass -     (paste the token, then Ctrl-D)
  3. within the pause:  ./install-target.sh --again
EOF
    exit 3
  fi
  echo "== --again: installing over the existing install (the agent should be paused)"
fi

HOST=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["host"])' "$HERE/agent.json")
ENDPOINT=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["fleet"]["endpoints"][0])' "$HERE/agent.json")

# The baseline: the bundle's; else an earlier install's; else the one built
# into the binary; else one captured now, before anything is installed.
BASEARG=()
if [ -s "$HERE/baseline.json.gz" ]; then
  echo "== baseline: the bundle's"
  BASEARG=(--baseline "$HERE/baseline.json.gz")
elif [ -s $STATE/baseline.json.gz ]; then
  echo "== baseline: the earlier install's ($STATE/baseline.json.gz)"
elif [ "$("$BIN" version --baseline 2>/dev/null || echo 0)" -gt 0 ]; then
  echo "== baseline: the one built into the binary"
else
  echo "== baseline: capturing this box now (a minute or two)"
  install -d -m 0755 $STATE
  if ! out=$("$BIN" capture --root / --out "$CAPTURE" 2>&1); then
    printf '%s\n' "$out" | tail -5 >&2
    die "the capture failed"
  fi
  echo "   $(grep -c 'warning' <<<"$out" || true) files could not be read (capture warnings)"
  BASEARG=(--baseline "$CAPTURE")
fi

echo "== bundle and config to $ETC"
# An earlier install's files are immutable; --again puts new ones down.
for f in $ETC/agent.json $ETC/agent.json.sig $ETC/fleet/ca.pem $ETC/fleet/host.pem $ETC/fleet/host-key.pem $ETC/fleet/rules.pub; do
  [ -e "$f" ] && chattr -i "$f" 2>/dev/null || true
done
install -d -m 0755 $ETC
install -d -m 0700 $ETC/fleet
for f in ca.pem host.pem host-key.pem rules.pub; do
  install -m 0600 "$HERE/fleet/$f" "$ETC/fleet/$f"
done
install -m 0600 "$HERE/agent.json" $ETC/agent.json
install -m 0644 "$HERE/agent.json.sig" $ETC/agent.json.sig

if [ $NO_INSTALL = 1 ]; then
  echo "== --no-install: not installed. To install:"
  echo "   $BIN install --config $ETC/agent.json ${BASEARG[*]:-}"
  exit 0
fi

echo "== xdr install"
"$BIN" install --config $ETC/agent.json "${BASEARG[@]}"
if [ "${BASEARG[1]:-}" = "$CAPTURE" ]; then rm -f "$CAPTURE"; fi # installed as $STATE/baseline.json.gz

echo "== checks"
bad=0
active=""
for _ in $(seq 30); do
  systemctl is-active --quiet xdr-agent.service && { active=1; break; }
  sleep 1
done
if [ -n "$active" ]; then echo "ok   xdr-agent.service is active"
else echo "FAIL xdr-agent.service is not active: journalctl -u xdr-agent -n 30"; bad=1; fi
if /usr/local/sbin/xdr incidents >/dev/null; then echo "ok   xdr incidents reads the log"
else echo "FAIL xdr incidents cannot read the log"; bad=1; fi
EH=${ENDPOINT%:*}
EP=${ENDPOINT##*:}
EH=${EH#[}
EH=${EH%]}
if timeout 3 bash -c 'exec 3<>"/dev/tcp/$1/$2"' _ "$EH" "$EP" 2>/dev/null; then echo "ok   the controller answers at $ENDPOINT"
else echo "FAIL no answer from the controller at $ENDPOINT within 3 s (is xdr-controller running on the jump box?)"; bad=1; fi
echo
echo "In the console: Hosts shows $HOST up with kill off. Check its incidents; turn kill on there (Hosts panel) once the box looks right."
exit $bad
