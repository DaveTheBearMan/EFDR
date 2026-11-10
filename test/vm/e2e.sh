#!/bin/bash
# End-to-end test of the baseline engine on a real Ubuntu 24.04 VM (LXD).
#   1. capture a clean baseline, wait, rescan: must report nothing
#   2. install a package, hash its .deb off the package manager's word:
#      the package layer must vouch for the package's files and nothing else
#   3. plant persistence, rescan: must report every planted item
set -euo pipefail
cd "$(dirname "$0")/../.."

VM=${XDR_E2E_VM:-xdr-e2e}
IMAGE=${XDR_E2E_IMAGE:-ubuntu:24.04}
x() { lxc exec "$VM" -- "$@"; }
# scan OUTFILE BASELINE...: run a scan in the VM, print its exit code. A
# scan that does not finish is a failure in itself (exit 124).
scan() {
  local out=$1 args=(); shift
  for b in "$@"; do args+=(--baseline "$b"); done
  set +e
  x timeout 900 xdr scan --root / "${args[@]}" > "$out"
  echo $?
  set -e
}
has() { grep -qF -- "$1" "$2"; }

OUT=$(mktemp -d)
trap 'lxc delete --force "$VM" >/dev/null 2>&1 || true; rm -rf "$OUT"' EXIT
lxc launch "$IMAGE" "$VM" --vm
for _ in $(seq 120); do x true >/dev/null 2>&1 && break; sleep 2; done
x systemctl is-system-running --wait || true   # "degraded" is fine here

lxc file push bin/xdr "$VM/usr/local/sbin/xdr" --mode 0755
lxc file push test/vm/plant.sh "$VM/root/plant.sh" --mode 0755
# The baseline lives under an excluded path so the scan doesn't report it.
BASE=/var/cache/xdr-e2e/base.json.gz
PKG=/var/cache/xdr-e2e/pkg.json.gz
TRIAGE=/var/cache/xdr-e2e/triage.json.gz
x mkdir -p /var/cache/xdr-e2e/debs
x xdr capture --root / --out "$BASE"

echo "== clean-rescan (waiting 60s for background activity)"
sleep 60
if [ "$(scan "$OUT/clean.txt" "$BASE")" -ne 0 ]; then
  echo "clean-rescan FAILED: findings on an untouched box:"
  cat "$OUT/clean.txt"
  exit 1
fi

echo "== package layer"
TREE=$'\t/usr/bin/tree\t'
x apt-get -qq -o DPkg::Lock::Timeout=300 update
x env DEBIAN_FRONTEND=noninteractive apt-get -qq -y -o DPkg::Lock::Timeout=300 install tree >/dev/null
x sh -c 'cd /var/cache/xdr-e2e/debs && apt-get -qq download tree 2>/dev/null'
x xdr pkghash --debs /var/cache/xdr-e2e/debs --out "$PKG"
scan "$OUT/nopkg.txt" "$BASE" >/dev/null
if ! has "added"$'\t'"system-binary${TREE}" "$OUT/nopkg.txt"; then
  echo "package layer FAILED: without it, the installed binary should be a finding:"; cat "$OUT/nopkg.txt"; exit 1
fi
scan "$OUT/pkg.txt" "$BASE" "$PKG" >/dev/null
if has "$TREE" "$OUT/pkg.txt" || has /usr/share/doc/tree "$OUT/pkg.txt" || has /usr/share/man/man1/tree.1.gz "$OUT/pkg.txt"; then
  echo "package layer FAILED: files shipped by the .deb are still findings:"; cat "$OUT/pkg.txt"; exit 1
fi
# The same layer over a full snapshot (the triage capture) must merge
# cleanly with what the snapshot recorded for those files.
sleep 30 # apt-get update kicks off background jobs (apt-news, command-not-found)
x xdr capture --root / --layer triage --out "$TRIAGE"
if [ "$(scan "$OUT/merged.txt" "$TRIAGE" "$PKG")" -ne 0 ]; then
  echo "package layer FAILED: package entries disagree with a snapshot of the same files:"; cat "$OUT/merged.txt"; exit 1
fi

echo "== planted scan"
x /root/plant.sh
code=$(scan "$OUT/planted.txt" "$BASE" "$PKG")
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
if has /opt/.p/ "$OUT/planted.txt"; then
  echo "planted scan walked into a proc mount:"; grep -F /opt/.p/ "$OUT/planted.txt" | head; exit 1
fi
scan "$OUT/merged-planted.txt" "$TRIAGE" "$PKG" >/dev/null
if ! has "altered"$'\t'"privilege${TREE}" "$OUT/merged-planted.txt"; then
  echo "merged layers missed the setuid bit on a packaged binary:"; cat "$OUT/merged-planted.txt"; exit 1
fi
echo "E2E PASS"
