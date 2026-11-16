#!/bin/bash
# Rotate the passwords of the given accounts on enrolled hosts (run on the
# jump box, as root, with the controller running).
#
#   rotate-passwords.sh --users web,db [--hosts web01,db01|all] [--samba db]
#                       [--dir /root/xdr-ctl] [--xdr /usr/local/sbin/xdr] [--out FILE]
#
# New passwords are generated here, kept in the controller's store (see them
# again any time with: xdr controller creds --dir DIR [--host H]) and only
# their hashes go to the agents. Gray, recovery and platform (auto) accounts
# are refused by the controller. A host the controller refuses or cannot
# reach is reported and the rest carry on; the exit status is 1 if any failed.
# The result (host, service, user, password) is printed and saved to --out
# (default ./rotated-DATE.tsv, mode 0600): give it to the scoring engine's
# owner and move it off this box.
set -euo pipefail

DIR=/root/xdr-ctl XDR= USERS= HOSTS=all SAMBA= OUT=
while [ $# -gt 0 ]; do
  case $1 in
    --dir) DIR=${2:?}; shift 2 ;;
    --xdr) XDR=${2:?}; shift 2 ;;
    --users) USERS=${2:?}; shift 2 ;;
    --hosts) HOSTS=${2:?}; shift 2 ;;
    --samba) SAMBA=${2:?}; shift 2 ;;
    --out) OUT=${2:?}; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown option $1 (try --help)" >&2; exit 2 ;;
  esac
done
[ -n "$USERS" ] || { echo "--users is required (comma-separated account names)" >&2; exit 2; }
for u in ${USERS//,/ } ${SAMBA//,/ }; do
  [[ $u =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || { echo "not an account name: $u" >&2; exit 2; }
done
if [ -z "$XDR" ]; then
  for c in ./bin/xdr /usr/local/sbin/xdr; do [ -x "$c" ] && XDR=$c && break; done
fi
[ -x "${XDR:-}" ] || { echo "no xdr binary: use --xdr PATH" >&2; exit 2; }
[ -d "$DIR" ] || { echo "no controller directory $DIR (use --dir)" >&2; exit 2; }

if [ "$HOSTS" = all ]; then
  [ -s "$DIR/hosts" ] || { echo "no enrolled hosts in $DIR/hosts" >&2; exit 2; }
  mapfile -t LIST < <(grep -v '^[[:space:]]*$' "$DIR/hosts")
else
  IFS=, read -ra LIST <<<"$HOSTS"
fi
[ -n "${OUT:-}" ] || OUT=./rotated-$(date +%Y%m%d-%H%M%S).tsv

echo "About to rotate: ${USERS} on: ${LIST[*]}${SAMBA:+ (samba: $SAMBA)}"
printf 'Scored accounts: the scoring engine must be given the new passwords or those checks FAIL.\nType yes to continue: '
read -r ans
[ "$ans" = yes ] || { echo "cancelled"; exit 1; }

umask 077
: > "$OUT"
fail=0
for h in "${LIST[@]}"; do
  args=(controller rotate --dir "$DIR" --host "$h" --users "$USERS")
  [ -n "$SAMBA" ] && args+=(--samba "$SAMBA")
  if res=$("$XDR" "${args[@]}" 2>&1); then
    printf '%s\n' "$res" >> "$OUT"
    echo "ok   $h"
  else
    echo "FAIL $h: $res" >&2
    fail=1
  fi
done
echo
echo "host	service	user	password"
cat "$OUT"
echo
echo "saved to $OUT (0600). Move it off this box once the scorer has it."
exit $fail
