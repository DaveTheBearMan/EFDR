#!/bin/bash
# setup.sh: the guided day-1 setup. Run it as root on the jump box, from
# the repo (or with the xdr binary and prep-target.sh beside it): it asks
# what it needs and does deploy/README.md's steps, the controller on this
# box and each target over SSH.
#   deploy/setup.sh [--answers FILE] [--xdr PATH]
#     --answers FILE  no questions: KEY=VALUE lines (see deploy/README.md,
#                     "Guided setup"); a missing answer is an error
#     --xdr PATH      the xdr binary (default: ./bin/xdr, the repo's
#                     bin/xdr, or /usr/local/sbin/xdr: the first that runs)
# Nothing on a target changes before you confirm a printed summary. The
# console password is read with the echo off and goes to xdr on stdin only.
#   XDR_SETUP_HOME  where the setup keeps its files (default /root):
#                   xdr-setup/ (bundles, facts, targets) and xdr-recovery/
set -euo pipefail
umask 077

HERE=$(cd "$(dirname "$0")" && pwd)
SETUP_HOME=${XDR_SETUP_HOME:-/root}
STATE=$SETUP_HOME/xdr-setup
RECDIR=$SETUP_HOME/xdr-recovery
STAGE=/root/xdr-day1 # on the target
ANSWERS=""
XDR=""

die() { echo "setup: $*" >&2; exit 1; }
warn() { echo "WARNING: $*" >&2; }
usage() { sed -n '2,14s/^# \{0,1\}//p' "$0"; }

while [ $# -gt 0 ]; do
  case $1 in
  --answers) [ $# -ge 2 ] || die "--answers needs a file"; ANSWERS=$2; shift ;;
  --xdr) [ $# -ge 2 ] || die "--xdr needs a path"; XDR=$2; shift ;;
  -h | --help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
  esac
  shift
done

[ "$(id -u)" = 0 ] || die "run me as root on the jump box"
runs() { [ -f "$1" ] && [ -x "$1" ] && "$1" version >/dev/null 2>&1; }
if [ -n "$XDR" ]; then
  runs "$XDR" || die "--xdr $XDR: not an xdr binary that runs"
else
  for c in "$PWD/bin/xdr" "$HERE/../bin/xdr" /usr/local/sbin/xdr; do
    if runs "$c"; then XDR=$c; break; fi
  done
  [ -n "$XDR" ] || die "no xdr binary (./bin/xdr, $HERE/../bin/xdr, /usr/local/sbin/xdr): build it (make build) or give --xdr PATH"
fi
XDR=$(cd "$(dirname "$XDR")" && pwd)/$(basename "$XDR")
PREP=$HERE/prep-target.sh
[ -r "$PREP" ] || die "no prep-target.sh beside me ($PREP)"

# ---- validators: VALUE -> the normalised value on stdout, or a reason on
# stderr and status 1. CHOICES is the numbered list a pick may index.
CHOICES=()
# Validators run in a subshell: bad ends it.
bad() { echo "  $*" >&2; exit 1; }
trim() { local s=$1; s=${s#"${s%%[![:space:]]*}"}; s=${s%"${s##*[![:space:]]}"}; printf '%s' "$s"; }
pick() { # a number from CHOICES, or the token itself
  if [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le ${#CHOICES[@]} ]; then printf '%s' "${CHOICES[$1 - 1]}"
  else printf '%s' "$1"; fi
}
v_abs() { [[ $1 == /* && $1 != *[[:space:]]* ]] || bad "an absolute path, no spaces"; printf '%s' "$1"; }
v_ip() {
  python3 -c 'import ipaddress, sys; print(ipaddress.ip_address(sys.argv[1]))' "$1" 2>/dev/null || bad "an IP address (the targets reach the controller at it)"
}
v_name() { [[ $1 =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || bad "an account name (lower case, as useradd takes)"; printf '%s' "$1"; }
v_names() {
  local s out=() t n
  s=$(trim "$1")
  case $s in "" | none | -) return 0 ;; esac
  IFS=, read -ra parts <<<"$s"
  for t in "${parts[@]}"; do
    t=$(trim "$t")
    [ -n "$t" ] || continue
    if [[ $t =~ ^[0-9]+$ ]]; then
      [ "$t" -ge 1 ] && [ "$t" -le ${#CHOICES[@]} ] || bad "$t: no such number in the list"
      t=${CHOICES[$t - 1]}
    fi
    n=$(v_name "$t") || return 1
    [[ " ${out[*]} " == *" $n "* ]] || out+=("$n")
  done
  (IFS=,; printf '%s' "${out[*]}")
}
v_name_or_none() { case $1 in none | -) return 0 ;; esac; v_name "$1"; }
v_host() {
  local s=$1 l
  [ -n "$s" ] && [ ${#s} -le 253 ] && [ "$s" != root ] || bad "a lower-case host name (letters, digits, -, dots), not root"
  IFS=. read -ra labels <<<"$s"
  [[ $s != *. && $s != .* && $s != *..* ]] || bad "a lower-case host name: no empty label"
  for l in "${labels[@]}"; do
    [[ $l =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || bad "$s: a lower-case host name (letters, digits, -, dots; no - at a label's ends)"
  done
  printf '%s' "$s"
}
v_addr() { [[ $1 =~ ^[A-Za-z0-9_.:]([A-Za-z0-9_.:-]*)$ ]] || bad "the target's IP address or DNS name"; printf '%s' "$1"; }
v_key() {
  local f=$1
  case $f in none | -) return 0 ;; esac
  f=${f/#\~/$HOME}
  [ -f "$f" ] && [ -r "$f" ] || bad "$f: no such key file (or none)"
  printf '%s' "$f"
}
v_file() { [ -f "$1" ] && [ -r "$1" ] || bad "$1: no such file"; printf '%s' "$1"; }
v_file_or_none() { case $1 in "" | none | -) return 0 ;; esac; v_file "${1/#\~/$HOME}"; }
v_scored() {
  local s out=() t p n
  s=$(trim "$1")
  [ -n "$s" ] || bad "at least one scored port (tcp/80 form, or a number from the list)"
  IFS=, read -ra parts <<<"$s"
  for t in "${parts[@]}"; do
    t=$(pick "$(trim "$t")")
    [ -n "$t" ] || continue
    [[ $t =~ ^(tcp|udp)/([0-9]{1,5})$ ]] || bad "$t: not tcp/PORT or udp/PORT"
    n=$((10#${BASH_REMATCH[2]}))
    [ "$n" -ge 1 ] && [ "$n" -le 65535 ] || bad "$t: the port is not 1 to 65535"
    p=${BASH_REMATCH[1]}/$n
    [[ " ${out[*]} " == *" $p "* ]] || out+=("$p")
  done
  [ ${#out[@]} -gt 0 ] || bad "at least one scored port"
  (IFS=,; printf '%s' "${out[*]}")
}
v_onoff() { case $1 in on | off) printf '%s' "$1" ;; *) bad "on or off" ;; esac; }
v_yn() { case $1 in y | Y | yes | YES | Yes) printf yes ;; n | N | no | NO | No) printf no ;; *) bad "y or n" ;; esac; }
v_action() { case $1 in controller | target | status) printf '%s' "$1" ;; *) bad "controller, target or status" ;; esac; }
v_keymode() {
  case $1 in g | generate) printf generate; return ;; esac
  local f=${1/#\~/$HOME}
  [ -f "$f" ] && [ -r "$f" ] || bad "generate, or the path of an existing public key (.pub)"
  ! grep -q 'PRIVATE KEY' "$f" || bad "$f is a private key: give its .pub"
  [ "$(grep -c . "$f")" = 1 ] && grep -qE '^(ssh-|ecdsa-|sk-)' "$f" || bad "$f: one authorized_keys line (ssh-ed25519 AAAA...)"
  printf '%s' "$f"
}

# ---- answers
KEYS="ACTION CONTROLLER_DIR JUMP_IP CONSOLE_PASSWORD_FILE GRAY AUTO RECOVERY TARGET_NAME TARGET_ADDR SSH_USER SSH_KEY
  BLUE SCORED KILL RECOVERY_KEY_MODE CREATE_RECOVERY BASELINE REBUILD CONFIRM"
declare -A ANS=()
validator() {
  case $1 in
  ACTION) echo v_action ;; CONTROLLER_DIR) echo v_abs ;; JUMP_IP) echo v_ip ;; CONSOLE_PASSWORD_FILE) echo v_file ;;
  GRAY | AUTO | BLUE) echo v_names ;; RECOVERY) echo v_name_or_none ;; TARGET_NAME) echo v_host ;;
  TARGET_ADDR) echo v_addr ;; SSH_USER) echo v_name ;; SSH_KEY) echo v_key ;; SCORED) echo v_scored ;;
  KILL) echo v_onoff ;; RECOVERY_KEY_MODE) echo v_keymode ;; BASELINE) echo v_file_or_none ;;
  CREATE_RECOVERY | REBUILD | CONFIRM) echo v_yn ;;
  esac
}
if [ -n "$ANSWERS" ]; then
  [ -r "$ANSWERS" ] || die "--answers $ANSWERS: cannot read it"
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line=${line%$'\r'}
    [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
    [[ $line =~ ^[[:space:]]*([A-Z_]+)=(.*)$ ]] || die "$ANSWERS:$n: not KEY=VALUE"
    k=${BASH_REMATCH[1]} v=${BASH_REMATCH[2]}
    [[ " ${KEYS//$'\n'/ } " == *" $k "* ]] || die "$ANSWERS:$n: unknown key $k (a password goes in a file: CONSOLE_PASSWORD_FILE)"
    if [[ $v =~ ^\"(.*)\"$ || $v =~ ^\'(.*)\'$ ]]; then v=${BASH_REMATCH[1]}; fi
    ANS[$k]=$v
    # Every answer is checked before anything is done (a pick by number
    # has no list yet: answers give names).
    ("$(validator "$k")" "$v") >/dev/null || die "$ANSWERS:$n: $k=$v is rejected"
  done <"$ANSWERS"
  [ -n "${ANS[ACTION]:-}" ] || die "$ANSWERS: ACTION is missing (controller, target or status)"
fi

# ask VAR PROMPT [DEFAULT]: sets VAR, from the answers or the operator,
# with VAR's validator; asks again on a bad answer.
ask() {
  local var=$1 prompt=$2 def=${3-} inp out val
  val=$(validator "$var")
  if [ -n "$ANSWERS" ]; then
    [ -n "${ANS[$var]+x}" ] || die "$ANSWERS: $var is missing ($prompt)"
    out=$("$val" "${ANS[$var]}") || die "$ANSWERS: $var=${ANS[$var]} is rejected"
    printf -v "$var" '%s' "$out"
    return 0
  fi
  while :; do
    if [ -n "$def" ]; then printf '%s [%s]: ' "$prompt" "$def"; else printf '%s: ' "$prompt"; fi
    IFS= read -r inp || { echo; die "end of input"; }
    inp=$(trim "$inp")
    [ -n "$inp" ] || inp=$def
    if out=$("$val" "$inp"); then
      printf -v "$var" '%s' "$out"
      return 0
    fi
  done
}
# shown VALUE: a list default as the prompt shows it.
shown() { if [ -n "$1" ]; then printf '%s' "$1"; else printf none; fi; }
isyes() { [ "$1" = yes ]; }
# soft WHY: the step did not finish; the menu goes on, --answers exits 1.
FAILED=0
soft() { echo "FAIL $*" >&2; FAILED=1; }

# The console password: twice with the echo off, or the first line of
# CONSOLE_PASSWORD_FILE. Sets PW; never printed, never in argv.
PW=""
get_password() {
  local p1="" p2=""
  if [ -n "$ANSWERS" ]; then
    ask CONSOLE_PASSWORD_FILE "console password file"
    IFS= read -r p1 <"$CONSOLE_PASSWORD_FILE" || [ -n "$p1" ] || die "$CONSOLE_PASSWORD_FILE: empty"
    [ ${#p1} -ge 12 ] && [ ${#p1} -le 1024 ] || die "$CONSOLE_PASSWORD_FILE: the password must be 12 to 1024 characters"
    PW=$p1
    return 0
  fi
  while :; do
    printf 'console password (12+ characters, not shown): '
    IFS= read -r -s p1 || { echo; die "end of input"; }
    echo
    printf 'again: '
    IFS= read -r -s p2 || { echo; die "end of input"; }
    echo
    if [ "$p1" != "$p2" ]; then echo "  the two do not match"
    elif [ ${#p1} -lt 12 ] || [ ${#p1} -gt 1024 ]; then echo "  12 to 1024 characters"
    else PW=$p1; return 0; fi
  done
}

jump_default() {
  local ip
  ip=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1) || true
  [ -n "$ip" ] || ip=$(hostname -I 2>/dev/null | awk '{print $1}') || true
  printf '%s' "$ip"
}
# ctl_json PYEXPR: a value of the controller's controller.json (c), or "".
ctl_json() {
  python3 -c 'import json, sys
c = json.load(open(sys.argv[1]))
v = eval(sys.argv[2])
print(",".join(v) if isinstance(v, list) else (v or ""))' "$CONTROLLER_DIR/controller.json" "$1" 2>/dev/null || true
}
console_url() { local l; l=$(ctl_json '(c.get("console") or {}).get("listen")'); [ -n "$l" ] && printf 'https://%s' "$l"; }
unit_active() { # UNIT SECONDS
  local i
  for ((i = 0; i < $2 * 2; i++)); do
    [ "$(systemctl is-active "$1" 2>/dev/null)" = active ] && return 0
    sleep 0.5
  done
  return 1
}

# ---- 1: the controller on this box
do_controller() {
  ask CONTROLLER_DIR "controller directory" "${CONTROLLER_DIR:-/root/xdr-ctl}"
  local had="" jd
  [ -s "$CONTROLLER_DIR/controller.json" ] && had=1
  jd=${JUMP_IP:-}
  [ -z "$had" ] || [ -n "$jd" ] || jd=$(ctl_json 'c["listen"].rsplit(":", 1)[0].strip("[]")')
  [ -n "$jd" ] || jd=$(jump_default)
  ask JUMP_IP "this box's IP address, as the targets reach it" "$jd"
  local g=${GRAY-} a=${AUTO-root} r=${RECOVERY-xdrrecover}
  if [ -n "$had" ]; then
    [ -n "${GRAY+x}" ] || g=$(ctl_json 'c.get("gray_users")')
    [ -n "${AUTO+x}" ] || a=$(ctl_json 'c.get("auto")')
    [ -n "${RECOVERY+x}" ] || r=$(ctl_json 'c.get("recovery")')
  fi
  ask GRAY "gray-team accounts (comma-separated)" "$(shown "$g")"
  ask AUTO "platform (auto) accounts, never rotated" "$(shown "$a")"
  ask RECOVERY "recovery account" "$(shown "$r")"
  local args=(controller install --dir "$CONTROLLER_DIR" --name "$JUMP_IP" --gray "$GRAY" --auto "$AUTO" --recovery "$RECOVERY")
  echo "== xdr ${args[*]}"
  if [ -s "$CONTROLLER_DIR/console.json" ]; then
    echo "   (the console password is set already and kept)"
    "$XDR" "${args[@]}" </dev/null || die "xdr controller install failed"
  else
    [ -n "$PW" ] || get_password
    printf '%s\n' "$PW" | "$XDR" "${args[@]}" || die "xdr controller install failed"
  fi
  if unit_active xdr-controller.service 20; then echo "ok   xdr-controller.service is active"
  else soft "xdr-controller.service is $(systemctl is-active xdr-controller.service 2>/dev/null || true): journalctl -u xdr-controller -n 30"; return 0; fi
  echo "console: $(console_url) (log in with the console password)"
}

# ---- 2: a target, over SSH
SSHO=()
DEST=""
SUDO=()
r() { ssh "${SSHO[@]}" -n "$DEST" -- "${SUDO[*]:-}" "$(printf '%q ' "$@")"; }   # CMD... on the target
rin() { ssh "${SSHO[@]}" "$DEST" -- "${SUDO[*]:-}" "$(printf '%q ' "$@")"; }    # with this stdin
# put SRC PATH MODE: SRC to PATH on the target.
put() { rin sh -c 'cat > "$1.new" && chmod "$2" "$1.new" && mv "$1.new" "$1"' put "$2" "$3" <"$1"; }

remember_target() {
  mkdir -p "$STATE"
  local f=$STATE/targets
  { [ -f "$f" ] && awk -v n="$TARGET_NAME" '$1 != n' "$f"; printf '%s %s %s %s\n' "$TARGET_NAME" "$TARGET_ADDR" "$SSH_USER" "${SSH_KEY:--}"; } >"$f.new"
  mv "$f.new" "$f"
}
ssh_setup() { # ADDR USER KEY
  SSHO=(-o StrictHostKeyChecking=accept-new -o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR)
  [ -z "$3" ] || SSHO=(-i "$3" -o IdentitiesOnly=yes "${SSHO[@]}")
  DEST=$2@$1
  SUDO=()
  [ "$2" = root ] || SUDO=(sudo -n --)
}

do_target() {
  ask CONTROLLER_DIR "controller directory" "${CONTROLLER_DIR:-/root/xdr-ctl}"
  [ -s "$CONTROLLER_DIR/controller.json" ] || die "$CONTROLLER_DIR has no controller: set it up first (menu 1)"
  ask TARGET_NAME "target host name (lower case, as the console shows it)" "${TARGET_NAME:-}"
  ask TARGET_ADDR "its address (IP or DNS name, from this box)" "${TARGET_ADDR:-}"
  ask SSH_USER "ssh user" "${SSH_USER:-root}"
  local kd=${SSH_KEY-}
  if [ -z "${SSH_KEY+x}" ] && [ -f "$HOME/.ssh/deploykey" ]; then kd=$HOME/.ssh/deploykey; fi
  ask SSH_KEY "ssh key (none: ssh's defaults)" "$(shown "$kd")"
  ssh_setup "$TARGET_ADDR" "$SSH_USER" "$SSH_KEY"

  local err
  if ! err=$(r id -u 2>&1 </dev/null); then
    soft "cannot ssh to $DEST${SSH_KEY:+ with $SSH_KEY}: $err"
    echo "     check the address, the key and that this box may reach port 22 there" >&2
    return 0
  fi
  if [ "$(tail -1 <<<"$err")" != 0 ]; then soft "$DEST is not root there (and sudo -n does not make it so)"; return 0; fi
  echo "ok   ssh $DEST"

  local name=$TARGET_NAME bundle=$STATE/bundles/$TARGET_NAME.tgz facts=$STATE/$TARGET_NAME-facts.json force=()
  local enrolled="" installed=""
  grep -qxF "$name" "$CONTROLLER_DIR/hosts" 2>/dev/null && enrolled=1
  r sh -c 'test -e /etc/systemd/system/xdr-agent.service || test -e /var/lib/xdr/manifest.json || test -e /etc/xdr/pinned.sha256' && installed=1
  if [ -n "$installed" ]; then
    echo "$name: XDR is already installed on $TARGET_ADDR (xdr-agent $(r systemctl is-active xdr-agent 2>/dev/null || true))${enrolled:+, and it is enrolled}."
    echo "Nothing is changed. To install it again: a pause token for $name (console, break-glass), then"
    echo "on the box: /usr/local/sbin/xdr breakglass -   and within the pause: $STAGE/install-target.sh --again"
    remember_target
    return 0
  fi
  if [ -n "$enrolled" ] || [ -e "$bundle" ]; then
    [ -z "$enrolled" ] || echo "$name exists: it is enrolled in $CONTROLLER_DIR already (XDR is not installed on it yet)."
    [ ! -e "$bundle" ] || echo "Its bundle $bundle exists."
    ask REBUILD "rebuild the bundle for $name (add-target --force: a new host certificate) and install it? y/N" N
    isyes "$REBUILD" || { echo "nothing done for $name"; return 0; }
    force=(--force)
  fi

  echo "== facts: prep-target.sh on $name (writes nothing there but $STAGE)"
  mkdir -p "$STATE/bundles"
  r mkdir -p -m 0700 "$STAGE"
  put "$XDR" "$STAGE/xdr" 0755
  put "$PREP" "$STAGE/prep-target.sh" 0755
  r "$STAGE/prep-target.sh" >"$facts.new" || { rm -f "$facts.new"; die "prep-target.sh failed on $name"; }
  mv "$facts.new" "$facts"
  local accounts ports
  mapfile -t accounts < <(python3 -c 'import json, sys
for a in json.load(open(sys.argv[1]))["accounts"]: print(a["name"])' "$facts")
  mapfile -t ports < <(python3 -c 'import json, sys
seen = []
for p in json.load(open(sys.argv[1]))["ports"]:
    k = "%s/%d" % (p["proto"], p["port"])
    if k not in seen: seen.append(k); print(k + " " + p["local"])' "$facts")

  echo "accounts on $name (uid >= 1000, login shell):"
  local i
  for i in "${!accounts[@]}"; do printf '  %2d  %s\n' $((i + 1)) "${accounts[$i]}"; done
  [ ${#accounts[@]} -gt 0 ] || echo "  (none)"
  CHOICES=("${accounts[@]}")
  ask BLUE "blue-team accounts (numbers or names, comma-separated)" "$(shown "${BLUE-}")"
  local gd=${GRAY-}
  [ -n "${GRAY+x}" ] || gd=$(ctl_json 'c.get("gray_users")')
  ask GRAY "gray-team accounts" "$(shown "$gd")"

  echo "listening on $name:"
  local pc=()
  for i in "${!ports[@]}"; do printf '  %2d  %s\n' $((i + 1)) "${ports[$i]}"; pc+=("${ports[$i]%% *}"); done
  CHOICES=("${pc[@]}")
  ask SCORED "scored ports (numbers from the list or tcp/80, comma-separated)" "${SCORED:-}"
  CHOICES=()

  local rd=${RECOVERY-}
  [ -n "${RECOVERY+x}" ] || rd=$(ctl_json 'c.get("recovery")')
  [ -n "${RECOVERY+x}" ] || [ -n "$rd" ] || rd=xdrrecover
  ask RECOVERY "recovery account (none: no recovery account)" "$(shown "$rd")"
  local create="" pub="" gen=""
  if [ -n "$RECOVERY" ]; then
    if ! r id -u "$RECOVERY" >/dev/null 2>&1; then
      echo "$RECOVERY does not exist on $name."
      ask CREATE_RECOVERY "create it (useradd -m -s /bin/bash $RECOVERY)? Y/n" Y
      if isyes "$CREATE_RECOVERY"; then create=1
      else warn "without the account the agent alerts recovery-missing and there is no recovery login"; fi
    fi
    local kmd=generate
    [ -f "$RECDIR/$name.pub" ] && kmd=$RECDIR/$name.pub
    echo "recovery key: generate a new ed25519 pair into $RECDIR/$name, or give an existing .pub"
    ask RECOVERY_KEY_MODE "generate or PATH.pub" "$kmd"
    if [ "$RECOVERY_KEY_MODE" = generate ]; then
      pub=$RECDIR/$name.pub
      if [ -f "$RECDIR/$name" ] && [ -f "$pub" ]; then echo "   $RECDIR/$name exists: it is used, not replaced"
      else gen=1; fi
    else pub=$RECOVERY_KEY_MODE; fi
  fi

  local ad=${AUTO-}
  [ -n "${AUTO+x}" ] || ad=$(ctl_json 'c.get("auto")')
  [ -n "${AUTO+x}" ] || [ -n "$ad" ] || ad=root
  ask AUTO "auto (platform) accounts: the gate lets them through" "$(shown "$ad")"
  local lockout=""
  [[ ",$BLUE,$AUTO," == *",$SSH_USER,"* ]] || lockout=1
  echo "kill: off means the agent only reports what it would kill; you switch it on per host in the console later."
  ask KILL "kill" "${KILL:-off}"
  ask BASELINE "a baseline file to install with (none: captured on the box at install)" "$(shown "${BASELINE-}")"

  echo
  echo "======== summary for $name ($DEST) ========"
  [ -z "$create" ] || echo "  on $name: useradd -m -s /bin/bash $RECOVERY"
  [ -z "$gen" ] || echo "  here: a new ed25519 key pair $RECDIR/$name (private, 0600) and $pub"
  echo "  here: xdr controller add-target --host $name --out $bundle ${force[*]:-}"
  echo "          --scored $SCORED --blue $(shown "$BLUE") --gray $(shown "$GRAY") --auto $(shown "$AUTO")"
  echo "          --recovery $(shown "$RECOVERY")${pub:+ --recovery-key $pub} --kill $KILL${BASELINE:+ --baseline $BASELINE}"
  echo "  on $name: the bundle into $STAGE, then $STAGE/install-target.sh (baseline, /etc/xdr, xdr install)"
  if [ -n "$lockout" ]; then
    echo "  !! $SSH_USER is not a blue or auto account: once the agent runs, the SSH gate holds or ends"
    echo "  !! this session and new ones as $SSH_USER. No dead-man timer is set for you. Add $SSH_USER to auto"
    echo "  !! (or blue), or keep a console session ready to approve it."
  fi
  echo "==========================================="
  ask CONFIRM "go ahead? y/N" N
  isyes "$CONFIRM" || { echo "nothing done for $name"; return 0; }

  if [ -n "$gen" ]; then
    mkdir -p -m 0700 "$RECDIR"
    rm -f "$RECDIR/$name.new" "$RECDIR/$name.new.pub"
    ssh-keygen -q -t ed25519 -N "" -C "xdr-recovery-$name" -f "$RECDIR/$name.new" </dev/null
    chmod 0600 "$RECDIR/$name.new"
    mv "$RECDIR/$name.new.pub" "$pub" && mv "$RECDIR/$name.new" "$RECDIR/$name"
    echo "ok   recovery key pair: $RECDIR/$name (private) and $pub"
  fi
  if [ -n "$create" ]; then
    if r id -u "$RECOVERY" >/dev/null 2>&1; then echo "ok   $RECOVERY exists on $name already (left as it is)"
    else r useradd -m -s /bin/bash "$RECOVERY" || die "useradd $RECOVERY failed on $name"; echo "ok   $RECOVERY created on $name"; fi
  fi
  local at=(controller add-target --dir "$CONTROLLER_DIR" --host "$name" --out "$bundle" --listeners "$facts"
    --scored "$SCORED" --kill "$KILL" "${force[@]}")
  [ -z "$BLUE" ] || at+=(--blue "$BLUE")
  [ -z "$GRAY" ] || at+=(--gray "$GRAY")
  [ -z "$AUTO" ] || at+=(--auto "$AUTO")
  [ -z "$RECOVERY" ] || at+=(--recovery "$RECOVERY" --recovery-key "$pub")
  [ -z "$BASELINE" ] || at+=(--baseline "$BASELINE")
  echo "== xdr ${at[*]}"
  "$XDR" "${at[@]}" </dev/null || die "add-target failed for $name"
  remember_target

  echo "== install on $name"
  put "$bundle" "$STAGE/$name.tgz" 0600
  r tar -C "$STAGE" -xzf "$STAGE/$name.tgz"
  local rc=0
  r "$STAGE/install-target.sh" || rc=$?
  local st
  st=$(r systemctl is-active xdr-agent.service 2>/dev/null) || true
  echo
  if [ "$st" = active ]; then echo "ok   xdr-agent is active on $name"
  else echo "FAIL xdr-agent on $name is ${st:-unknown} (install-target.sh exit $rc): ssh $DEST journalctl -u xdr-agent -n 30"; fi
  echo "console: $(console_url): Hosts shows $name up, kill $KILL. Read its incidents for a while; each"
  echo "would-kill is what kill would have done. Switch kill on there when it looks right."
  if [ -n "$RECOVERY" ] && [ "${RECOVERY_KEY_MODE:-}" = generate ]; then
    echo "The recovery account's private key is $RECDIR/$name on THIS box: copy it off (to your laptop),"
    echo "then delete it here. With it: ssh -i KEY $RECOVERY@$TARGET_ADDR skips the gate."
  fi
  if [ "$st" != active ] || [ $rc != 0 ]; then FAILED=1; fi
}

# ---- 3: status
do_status() {
  ask CONTROLLER_DIR "controller directory" "${CONTROLLER_DIR:-/root/xdr-ctl}"
  echo "xdr-controller.service: $(systemctl is-active xdr-controller.service 2>/dev/null || true)"
  [ ! -s "$CONTROLLER_DIR/controller.json" ] || echo "console: $(console_url)"
  echo "enrolled hosts ($CONTROLLER_DIR/hosts):"
  local h line a u k st
  if [ ! -s "$CONTROLLER_DIR/hosts" ]; then echo "  (none)"; return 0; fi
  while IFS= read -r h; do
    [ -n "$h" ] || continue
    line=$(awk -v n="$h" '$1 == n' "$STATE/targets" 2>/dev/null | tail -1)
    if [ -z "$line" ]; then printf '  %-24s (not set up from here: address unknown)\n' "$h"; continue; fi
    read -r _ a u k <<<"$line"
    [ "$k" != - ] || k=""
    ssh_setup "$a" "$u" "$k"
    st=$(r systemctl is-active xdr-agent 2>/dev/null </dev/null) || st=${st:-unreachable}
    printf '  %-24s %-20s xdr-agent %s\n' "$h" "$a" "$st"
  done <"$CONTROLLER_DIR/hosts"
}

if [ -n "$ANSWERS" ]; then
  case ${ANS[ACTION]} in
  controller) do_controller ;;
  target) do_target ;;
  status) do_status ;;
  esac
  exit $FAILED
fi

while :; do
  echo
  echo "XDR day-1 setup (xdr: $XDR)"
  echo "  1  set up / update the controller on this box"
  echo "  2  add a target host"
  echo "  3  status"
  echo "  4  quit"
  printf 'choice [4]: '
  IFS= read -r c || { echo; exit 0; }
  case $(trim "$c") in
  1) do_controller ;;
  2) do_target ;;
  3) do_status ;;
  4 | q | "") exit 0 ;;
  *) echo "  1, 2, 3 or 4" ;;
  esac
done
