#!/bin/sh
# xdr-e2e-reset: puts a test box back as it was before its first test. The
# first run saves the files the agent may assert or rewrite; every run
# stops XDR and the tests' leftovers, drops the firewall and restores those
# files. Run by the ssh backend before and after a test, and by the box's
# dead-man timer if the test never comes back.
set -u
SAVED=/var/backups/xdr-e2e-pristine.tar
HOMES=/var/backups/xdr-e2e-homes # the homes there were at the first save
ARMED=/var/lib/xdr-e2e-armed     # a test is running: reset at boot
FILES="etc/ssh etc/pam.d etc/passwd etc/shadow etc/group etc/gshadow etc/hosts etc/nsswitch.conf etc/resolv.conf root/.ssh"

if [ ! -s "$SAVED" ]; then
  # shellcheck disable=SC2086
  tar -C / -cpf "$SAVED.new" $FILES && mv "$SAVED.new" "$SAVED" || { echo "xdr-e2e-reset: cannot save $SAVED" >&2; exit 1; }
  ls -A /home > "$HOMES"
fi

# The dead-man timer is transient: a reboot loses it, while the rendered
# PAM refuses root with the agent down. This unit resets an armed box at
# boot. Its name is not xdr-*, which the steps below remove.
BOOT=/etc/systemd/system/e2e-deadman-boot.service
if [ ! -s "$BOOT" ]; then
  printf '[Unit]\nDescription=xdr e2e: reset a box that rebooted mid-test\nConditionPathExists=%s\n\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/xdr-e2e-reset\n\n[Install]\nWantedBy=multi-user.target\n' "$ARMED" > "$BOOT.new" &&
    mv "$BOOT.new" "$BOOT" && systemctl daemon-reload && systemctl enable e2e-deadman-boot.service >/dev/null 2>&1
fi

# What `xdr install` put down (e2e-protect). The pinned hash goes first: with
# it gone no launch point finds a good copy and ensure restores nothing, so
# the guards, the timer and cron cannot bring back what is removed next.
INSTALLED="/etc/xdr /var/lib/xdr /usr/lib/xdr /usr/local/sbin/xdr /etc/cron.d/xdr-ensure
  /usr/lib/systemd/system-generators/xdr-generator /etc/apt/apt.conf.d/99xdr
  /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-agent.service.d
  /etc/systemd/system/xdr-guard-a.service /etc/systemd/system/xdr-guard-b.service
  /etc/systemd/system/xdr-ensure.service /etc/systemd/system/xdr-ensure.timer"
# shellcheck disable=SC2086
for p in $INSTALLED; do [ -e "$p" ] && chattr -R -i "$p" 2>/dev/null; done
rm -f /etc/xdr/pinned.sha256 /var/lib/xdr/backup/pinned.sha256 /etc/cron.d/xdr-ensure \
  /usr/lib/systemd/system-generators/xdr-generator /etc/apt/apt.conf.d/99xdr
systemctl disable --now xdr-guard-a.service xdr-guard-b.service xdr-ensure.timer xdr-ensure.service xdr-agent.service >/dev/null 2>&1
rm -rf /etc/systemd/system/xdr-agent.service /etc/systemd/system/xdr-agent.service.d \
  /etc/systemd/system/xdr-guard-a.service /etc/systemd/system/xdr-guard-b.service \
  /etc/systemd/system/xdr-ensure.service /etc/systemd/system/xdr-ensure.timer \
  /etc/systemd/system/*.wants/xdr-* /usr/lib/xdr

for u in $(systemctl list-units --all --plain --no-legend 'xdr-*' | awk '{print $1}'); do
  case $u in xdr-e2e-deadman.*) ;; *) systemctl stop "$u"; systemctl reset-failed "$u" 2>/dev/null ;; esac
done
# e2e-protect's isolation: its foreign table, blackhole routes, its actors.
nft delete table inet e2e_evil 2>/dev/null
ip route show type blackhole | while read -r r; do
  # shellcheck disable=SC2086
  ip route del $r
done
pkill -f '^/tmp/xdr-e2e-' ; rm -f /tmp/xdr-e2e-*
pkill -f '^/opt/beacon/' ; pkill -f '/usr/local/bin/helperd' ; pkill -f '/var/tmp/.cache-helper'
nft delete table inet xdr 2>/dev/null

# Restore whole directories, so files a test added go too; the saved copy
# is unpacked first, so a failed unpack leaves the live files alone.
NEW=/var/backups/xdr-e2e-restore
rm -rf "$NEW" && mkdir -p "$NEW" && tar -C "$NEW" -xpf "$SAVED" || { echo "xdr-e2e-reset: cannot unpack $SAVED" >&2; exit 1; }
# exchange A B: swap two paths in one rename (renameat2 RENAME_EXCHANGE),
# so a directory such as /etc/pam.d is never missing, not even briefly.
exchange() {
  python3 -c 'import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
sys.exit(0 if libc.renameat2(-100, os.fsencode(sys.argv[1]), -100, os.fsencode(sys.argv[2]), 2) == 0 else 1)' "$1" "$2" 2>/dev/null
}
for f in $FILES; do
  if [ -d "$NEW/$f" ] && [ ! -L "$NEW/$f" ]; then
    if [ -e "/$f" ] && exchange "$NEW/$f" "/$f"; then
      rm -rf "${NEW:?}/$f"
    else
      rm -rf "/$f.xdr-old" && { [ ! -e "/$f" ] || mv "/$f" "/$f.xdr-old"; } && mv "$NEW/$f" "/$f" && rm -rf "/$f.xdr-old"
    fi
  else
    cp -a "$NEW/$f" "/$f.xdr-new" 2>/dev/null && mv -T "/$f.xdr-new" "/$f"
  fi
done
rm -rf "$NEW"
sshd -t && systemctl try-reload-or-restart ssh.service
# Accounts a test added are gone from passwd now; so go their homes: only
# those not there at the first save (a box saved before that list was kept
# gets one from the homes whose owner is still known).
if [ ! -f "$HOMES" ]; then
  for d in /home/*; do
    [ -d "$d" ] && [ "$(stat -c %U "$d")" != UNKNOWN ] && basename "$d"
  done > "$HOMES"
fi
for d in /home/*; do
  [ -d "$d" ] || continue
  grep -qxF -- "$(basename "$d")" "$HOMES" && continue
  [ "$(stat -c %U "$d")" = UNKNOWN ] && rm -rf "$d"
done

# shellcheck disable=SC2086
for p in $INSTALLED; do [ -e "$p" ] && chattr -R -i "$p" 2>/dev/null; done
rm -rf /etc/xdr /var/lib/xdr /run/xdr /var/cache/xdr-e2e /opt/beacon /usr/local/bin/helperd /var/tmp/.cache-helper \
  /etc/systemd/system/xdr-e2e-*.service /usr/local/sbin/xdr /var/log/xdr-agent.*
systemctl daemon-reload
exit 0
