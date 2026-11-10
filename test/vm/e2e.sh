#!/bin/bash
# End-to-end test of the baseline engine on a real Ubuntu 24.04 VM (LXD).
#   1. capture a clean baseline, wait, rescan: must report nothing
#   2. plant persistence, rescan: must report every planted item
set -euo pipefail
cd "$(dirname "$0")/../.."

VM=${XDR_E2E_VM:-xdr-e2e}
IMAGE=${XDR_E2E_IMAGE:-ubuntu:24.04}
x() { lxc exec "$VM" -- "$@"; }

OUT=$(mktemp -d)
trap 'lxc delete --force "$VM" >/dev/null 2>&1 || true; rm -rf "$OUT"' EXIT
lxc launch "$IMAGE" "$VM" --vm
for _ in $(seq 120); do x true >/dev/null 2>&1 && break; sleep 2; done
x systemctl is-system-running --wait || true   # "degraded" is fine here

lxc file push bin/xdr "$VM/usr/local/sbin/xdr" --mode 0755
lxc file push test/vm/plant.sh "$VM/root/plant.sh" --mode 0755
# The baseline lives under an excluded path so the scan doesn't report it.
BASE=/var/cache/xdr-e2e/base.json.gz
x mkdir -p /var/cache/xdr-e2e
x xdr capture --root / --out "$BASE"

echo "== clean-rescan (waiting 60s for background activity)"
sleep 60
if ! x xdr scan --root / --baseline "$BASE" > "$OUT/clean.txt"; then
  echo "clean-rescan FAILED: findings on an untouched box:"
  cat "$OUT/clean.txt"
  exit 1
fi

echo "== planted scan"
x /root/plant.sh
set +e
x xdr scan --root / --baseline "$BASE" > "$OUT/planted.txt"
code=$?
set -e
if [ "$code" -ne 1 ]; then
  echo "planted scan exit $code, want 1"; cat "$OUT/planted.txt"; exit 1
fi
missing=""
while IFS= read -r want; do
  grep -qF -- "$want" "$OUT/planted.txt" || missing+="$want"$'\n'
done < test/vm/expected.txt
if [ -n "$missing" ]; then
  echo "planted scan missed:"; printf '%s' "$missing"
  echo "--- full output:"; cat "$OUT/planted.txt"
  exit 1
fi
echo "E2E PASS"
