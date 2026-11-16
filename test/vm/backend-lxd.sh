# The LXD backend of the VM tests: the boxes are VMs on this host, which is
# also the jump box. Commands go over lxc exec, which does not use the
# network, so the firewall cannot lock the test out.
# shellcheck shell=bash

BOXES=(xdr-e2e-fleet xdr-e2e-fleet2)
IMAGE=${XDR_E2E_IMAGE:-ubuntu:24.04}
# Two VMs at LXD's default 1 GiB starve a 4 GB host, so each gets VM_MEM.
VM_MEM=${VM_MEM:-768MiB}
# The controller's binary, run on the jump box.
JXDR=bin/xdr

x() { lxc exec "$VM" -- "$@"; }
xin() { lxc exec "$VM" -- "$@"; } # x with stdin, for secrets kept out of argv
# push SRC PATH MODE: copy a local file to PATH on the box.
push() { lxc file push "$1" "$VM$2" --mode "$3"; }
# jb CMD...: run on the jump box, which is here.
jb() { "$@"; }
# jsync DIR: the controller's directory, made on this host, on the jump
# box; sets JCTL to its path there.
jsync() { JCTL=$1; }

# An LXD client can stall with no operation behind it; fail rather than
# wait. Launching one at a time, as two at once race on the image (qemu-img
# killed); that flake is also retried once.
launch() {
  timeout 600 lxc launch "$IMAGE" "$1" --vm -c limits.memory="$VM_MEM" && return 0
  lxc delete --force "$1" >/dev/null 2>&1
  timeout 600 lxc launch "$IMAGE" "$1" --vm -c limits.memory="$VM_MEM"
}
# boxes_up BOX...: launched and booted.
boxes_up() {
  local VM
  for VM in "$@"; do launch "$VM" || return 1; done
  for VM in "$@"; do
    for _ in $(seq 120); do x true >/dev/null 2>&1 && break; sleep 2; done
    x systemctl is-system-running --wait >/dev/null || true
  done
}
boxes_down() { lxc delete --force "$@" >/dev/null 2>&1; }
# ip_of BOX: its IPv4 address on lxdbr0, once it has one.
ip_of() {
  local ip
  for _ in $(seq 120); do
    ip=$(lxc list "$1" -c4 --format csv | grep -o '^[0-9.]*' | head -1)
    [ -n "$ip" ] && { echo "$ip"; return 0; }
    sleep 2
  done
  return 1
}
# jump_ip: the jump box's address as the boxes see it.
jump_ip() { lxc network get lxdbr0 ipv4.address | cut -d/ -f1; }

CTLPID=""
# ctl_run N: start the controller; its output goes to CTLOUT.
ctl_run() {
  CTLOUT=$OUT/ctl.$1.out
  "$JXDR" controller run --dir "$JCTL" > "$CTLOUT" 2>&1 &
  CTLPID=$!
}
ctl_kill() {
  [ -n "$CTLPID" ] && kill "$CTLPID" 2>/dev/null && wait "$CTLPID" 2>/dev/null
  CTLPID=""
}
ctl_log() { cat "$CTLOUT"; }
