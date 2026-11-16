# The ssh backend of the VM tests: the boxes are the [targets] of
# inventory.ini, reached through the [controller] host, which is also the
# jump box (as in the competition, where SSH comes only from the jump box).
# The agents' firewall cuts the targets' other ways in, so each target gets
# a dead-man timer that puts it back as it was (xdr-e2e-reset) unless the
# test ends first and does that itself.
#   XDR_E2E_INVENTORY  default inventory.ini
#   XDR_E2E_KEY        default ~/.ssh/deploykey
#   XDR_E2E_DEADMAN    default 30min
# shellcheck shell=bash

INV=${XDR_E2E_INVENTORY:-inventory.ini}
KEY=${XDR_E2E_KEY:-$HOME/.ssh/deploykey}
DEADMAN=${XDR_E2E_DEADMAN:-30min}
JROOT=/root/xdr-e2e
JXDR=/usr/local/sbin/xdr

# inv GROUP [VAR]: the names of GROUP's hosts, or their VAR.
inv() {
  awk -v g="[$1]" -v v="${2:-}" '
    /^\[/ { on = ($0 == g); next }
    on && NF && $1 !~ /^[#;]/ {
      if (v == "") { print $1; next }
      for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] == v) print kv[2] }
    }' "$INV"
}
# hostvar NAME VAR
hostvar() {
  awk -v n="$1" -v v="$2" '$1 == n { for (i = 2; i <= NF; i++) { split($i, kv, "="); if (kv[1] == v) print kv[2] } }' "$INV" | head -1
}
[ -r "$INV" ] || { echo "no inventory: $INV"; exit 1; }
mapfile -t BOXES < <(inv targets)
JUMP=$(inv controller | head -1)
[ -n "$JUMP" ] && [ ${#BOXES[@]} -gt 0 ] || { echo "$INV: needs a [controller] host and [targets]"; exit 1; }

# One master connection per host, so a command costs one round trip.
SSHDIR=$(mktemp -d)
SSHCFG=$SSHDIR/config
{
  printf 'Host *\n  User root\n  IdentityFile %s\n  IdentitiesOnly yes\n  BatchMode yes\n' "$KEY"
  printf '  ConnectTimeout 10\n  ServerAliveInterval 5\n  ServerAliveCountMax 4\n'
  printf '  StrictHostKeyChecking accept-new\n  LogLevel ERROR\n'
  printf '  ControlMaster auto\n  ControlPath %s/%%C\n  ControlPersist 120\n' "$SSHDIR"
  printf 'Host %s\n  HostName %s\n' "$JUMP" "$(hostvar "$JUMP" ansible_host)"
  for b in "${BOXES[@]}"; do printf 'Host %s\n  HostName %s\n  ProxyJump %s\n' "$b" "$(hostvar "$b" private_ip)" "$JUMP"; done
} > "$SSHCFG"

# rsh HOST CMD...: CMD's words, quoted, run by root's shell on HOST.
rsh() { local h=$1; shift; ssh -F "$SSHCFG" "$h" "$(printf '%q ' "$@")" </dev/null; }
x() { rsh "$VM" "$@"; }
# push SRC PATH MODE: copy a local file to PATH on the box.
push() { ssh -F "$SSHCFG" "$VM" "cat > '$2.new' && chmod $3 '$2.new' && mv '$2.new' '$2'" < "$1"; }
jb() { rsh "$JUMP" "$@"; }
# jsync DIR: the controller's directory, made on this host, on the jump
# box; sets JCTL to its path there.
jsync() {
  JCTL=$JROOT/$(basename "$1")
  tar -C "$(dirname "$1")" -cf - "$(basename "$1")" | ssh -F "$SSHCFG" "$JUMP" "rm -rf '$JCTL' && mkdir -p $JROOT && tar -C $JROOT -xf -"
}

# boxes_up BOX...: the jump box has this build; each box is reset to how
# prep found it and its dead-man timer armed.
boxes_up() {
  local VM
  jb true || { echo "jump box $JUMP unreachable"; return 1; }
  jb systemctl stop xdr-e2e-ctl >/dev/null 2>&1
  jb mkdir -p $JROOT
  VM=$JUMP push bin/xdr $JXDR 0755 || return 1
  for VM in "$@"; do
    x true || { echo "$VM unreachable through $JUMP"; return 1; }
    push test/vm/remote-reset.sh /usr/local/sbin/xdr-e2e-reset 0755 || return 1
    x xdr-e2e-reset || return 1
    x systemctl stop xdr-e2e-deadman.timer >/dev/null 2>&1
    x systemctl reset-failed xdr-e2e-deadman >/dev/null 2>&1
    x systemd-run --unit=xdr-e2e-deadman --on-active="$DEADMAN" /usr/local/sbin/xdr-e2e-reset >/dev/null || return 1
  done
}
boxes_down() {
  local VM
  ctl_kill
  jb rm -rf $JROOT
  for VM in "$@"; do
    if x xdr-e2e-reset && x systemctl stop xdr-e2e-deadman.timer; then continue; fi
    echo "warning: $VM did not reset; its dead-man timer does within $DEADMAN"
  done
  ssh -F "$SSHCFG" -O exit "$JUMP" 2>/dev/null
  rm -rf "$SSHDIR"
}
ip_of() { hostvar "$1" private_ip; }
jump_ip() { hostvar "$JUMP" private_ip; }
# The boxes' DHCP server: their default gateway.
dhcp_server() { VM=${BOXES[0]} x ip -4 route show default | awk '{print $3; exit}'; }

# ctl_run N: start the controller on the jump box; its output goes to CTLOUT
# there.
ctl_run() {
  CTLOUT=$JROOT/ctl.$1.out
  jb systemctl reset-failed xdr-e2e-ctl >/dev/null 2>&1
  jb systemd-run --unit=xdr-e2e-ctl -p StandardOutput=truncate:"$CTLOUT" -p StandardError=inherit \
    $JXDR controller run --dir "$JCTL" >/dev/null
}
ctl_kill() { jb systemctl stop xdr-e2e-ctl >/dev/null 2>&1; jb systemctl reset-failed xdr-e2e-ctl >/dev/null 2>&1; }
ctl_log() { jb cat "$CTLOUT"; }
