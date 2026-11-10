Infra / platform

Pre-staged, Ansible-deployed in the setup window — nothing built live
etcd shared state store — internal/mgmt interface only, authenticated
Peer agents reinstall each other — authenticate the resurrection channel
Web UI for monitoring + approvals
Break-glass escape command to declare a session safe — must work if etcd/site is down (local-file fallback)

Baseline (source)

Clean offline Ubuntu 24.04, matched to the competition’s exact point release
Pre-mark scored-service deltas as known-good (mysql, docker, smtp + their accounts)

Detection — “added” (baseline diff)

New/non-stock systemd services + timers
New/non-stock users — flag non-baseline users in first 5 min
Cronjobs (all locations)
apt/dpkg hooks
authorized_keys, sudoers.d, SUID set
ld.so.preload, update-motd.d, rc.local, profile.d/bashrc, nsswitch.conf
New services/processes surfaced in real time

Detection — “altered” (content diff)

Hash stock files vs clean box (debsums)
Byte-diff sshd_config + PAM stack (top backdoor targets)
Monitor/diff PAM modules — don’t rip-and-replace live

Response

Session-kill-unless-authenticated = primary SSH control
pam_exec at session stage, /etc/pam.d/sshd only (not common-session)
logind terminate-session after short grace window; fail-closed
platform-launched sessions auto-approve; manual sessions via escape command
exempt agent + recovery account; protect the watchdog (peer-reinstall resurrects it)
New users disabled until approved
Auto-disable sessions whose user isn’t in baseline
Destroy rules (service/file-hash) — dry-run + undo, never match scored binaries
SSH session mgmt: view/kill sessions, kill connections to non-baseline remotes
Kill unknown listeners

Hardening

SSH keys-only, password auth disabled
Rotate all creds + replace all authorized_keys at T-0; regenerate host keys
Bind sshd to mgmt interface if topology allows
Default-deny firewall — inverted: scored services allowed first, approve additions

Cut / demoted

SSH port rotation — cut as prevention; keep only as an optional probe tripwire/alert, slower interval, never every minute

Open (unresolved)

Scored services: Apache (Docker/HTTP), SMTP, MySQL — Linux only
Apache container sits outside the host baseline — needs its own handling (docroot diff, image/restart-policy inspect, container egress); rebuild-from-clean-image vs. stuck-with-theirs still undecided
Whether you start with root/sudo — still undecided
