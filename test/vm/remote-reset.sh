#!/bin/sh
# xdr-e2e-reset: puts a test box back as it was before its first test. The
# first run saves the files the agent may assert or rewrite; every run
# stops XDR and the tests' leftovers, drops the firewall and restores those
# files. Run by the ssh backend before and after a test, and by the box's
# dead-man timer if the test never comes back.
set -u
SAVED=/var/backups/xdr-e2e-pristine.tar
FILES="etc/ssh etc/pam.d etc/passwd etc/shadow etc/group etc/gshadow etc/hosts etc/nsswitch.conf etc/resolv.conf root/.ssh"

if [ ! -s "$SAVED" ]; then
  # shellcheck disable=SC2086
  tar -C / -cpf "$SAVED.new" $FILES && mv "$SAVED.new" "$SAVED" || { echo "xdr-e2e-reset: cannot save $SAVED" >&2; exit 1; }
fi

for u in $(systemctl list-units --all --plain --no-legend 'xdr-*' | awk '{print $1}'); do
  case $u in xdr-e2e-deadman.*) ;; *) systemctl stop "$u"; systemctl reset-failed "$u" 2>/dev/null ;; esac
done
pkill -f '^/opt/beacon/' ; pkill -f '/usr/local/bin/helperd' ; pkill -f '/var/tmp/.cache-helper'
nft delete table inet xdr 2>/dev/null

# Restore whole directories, so files a test added go too; the saved copy
# is unpacked first, so a failed unpack leaves the live files alone.
NEW=/var/backups/xdr-e2e-restore
rm -rf "$NEW" && mkdir -p "$NEW" && tar -C "$NEW" -xpf "$SAVED" || { echo "xdr-e2e-reset: cannot unpack $SAVED" >&2; exit 1; }
for f in $FILES; do
  if [ -d "$NEW/$f" ] && [ ! -L "$NEW/$f" ]; then
    rm -rf "/$f.xdr-old" && mv "/$f" "/$f.xdr-old" && mv "$NEW/$f" "/$f" && rm -rf "/$f.xdr-old"
  else
    cp -a "$NEW/$f" "/$f.xdr-new" 2>/dev/null && mv -T "/$f.xdr-new" "/$f"
  fi
done
rm -rf "$NEW"
sshd -t && systemctl try-reload-or-restart ssh.service

rm -rf /etc/xdr /var/lib/xdr /run/xdr /var/cache/xdr-e2e /opt/beacon /usr/local/bin/helperd /var/tmp/.cache-helper \
  /etc/systemd/system/xdr-e2e-*.service /usr/local/sbin/xdr /var/log/xdr-agent.*
systemctl daemon-reload
exit 0
