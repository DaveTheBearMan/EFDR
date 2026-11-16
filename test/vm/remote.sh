#!/bin/bash
# The hosts of inventory.ini as test boxes.
#   remote.sh check   each host answers, as the tests reach it, and its state
#   remote.sh reset   each target back as it was before its first test
set -uo pipefail
cd "$(dirname "$0")/../.."
XDR_E2E_BACKEND=ssh
# shellcheck source=test/vm/backend-ssh.sh
. test/vm/backend-ssh.sh
trap 'ssh -F "$SSHCFG" -O exit "$JUMP" 2>/dev/null; rm -rf "$SSHDIR"' EXIT

state() {
  x sh -c 'printf "%s: %s, agent %s, firewall %s, dead-man %s, saved %s\n" "$(hostname)" "$(hostname -I | cut -d" " -f1)" \
    "$(systemctl is-active xdr-agent 2>/dev/null)" "$(nft list table inet xdr >/dev/null 2>&1 && echo up || echo none)" \
    "$(systemctl is-active xdr-e2e-deadman.timer 2>/dev/null)$(test -e /var/lib/xdr-e2e-armed && echo ", armed at boot")" "$(test -s /var/backups/xdr-e2e-pristine.tar && echo yes || echo no)"'
}
rc=0
case ${1:-} in
check)
  VM=$JUMP x sh -c 'echo "$(hostname): jump box, $(hostname -I | cut -d" " -f1)"' || { echo "$JUMP: unreachable"; rc=1; }
  for VM in "${BOXES[@]}"; do state || { echo "$VM: unreachable through $JUMP"; rc=1; }; done ;;
reset)
  for VM in "${BOXES[@]}"; do
    push test/vm/remote-reset.sh /usr/local/sbin/xdr-e2e-reset 0755 && x xdr-e2e-reset &&
      x systemctl stop xdr-e2e-deadman.timer 2>/dev/null; x rm -f /var/lib/xdr-e2e-armed; state || { echo "$VM: not reset"; rc=1; }
  done ;;
*) echo "usage: remote.sh check|reset" >&2; exit 2 ;;
esac
exit $rc
