# Day 1: controller and targets

One controller on the jump box, then each target in turn. Everything as
root. `JUMP` is the jump box's IP address as the targets reach it; `web01`
stands for the target's name (lower case).

## Guided setup

`deploy/setup.sh` does steps 1 to 4 below for you. Copy the repo's
`deploy/` and `bin/xdr` to the jump box and run it there as root:

    ssh root@JUMP mkdir -p /root/xdr-repo && scp -r deploy bin root@JUMP:/root/xdr-repo/
    ssh root@JUMP
    cd /root/xdr-repo && deploy/setup.sh

A menu: (1) the controller on this box, (2) add a target, (3) status.
It asks for everything with defaults in brackets and asks again on a bad
answer; the console password is read twice with the echo off and goes to
`xdr` on stdin only. For a target it reaches the box over SSH
(`-i KEY`, default `~/.ssh/deploykey`), runs prep-target.sh, lists the
box's accounts and listening ports to pick blue, gray and scored from,
can create the recovery account and generate its key pair (in
`/root/xdr-recovery/NAME`: copy the private key off the jump box), and
prints a summary to confirm before it changes anything there. Then
add-target, the bundle onto the box and install-target.sh, streamed.

- Rerun it any time: a host that is installed already is left alone (it
  says how to install again); an enrolled host or an existing bundle is
  rebuilt (`--force`) only if you say so.
- If the SSH user is not an auto or blue account, the gate holds or ends
  that session once the agent runs. The script warns; it sets no dead-man
  for you. Keep `root` in auto (the default) or have the console ready.
- `--answers FILE` runs it without questions, for scripts and tests:
  `KEY=VALUE` lines, every answer the run needs (a missing one is an
  error): `ACTION=controller|target|status`, `CONTROLLER_DIR`, `JUMP_IP`,
  `CONSOLE_PASSWORD_FILE` (a file holding the password, never the password
  itself), `GRAY`, `AUTO`, `RECOVERY`, `TARGET_NAME`, `TARGET_ADDR`,
  `SSH_USER`, `SSH_KEY`, `BLUE`, `SCORED`, `KILL`, `BASELINE`,
  `RECOVERY_KEY_MODE=generate|FILE.pub`, `CREATE_RECOVERY`, `REBUILD`,
  `CONFIRM` (yes/no). Lists are comma-separated names, `none` for none.

The manual steps follow.

## 0. Build (on your laptop)

    make build                       # bin/xdr, one static binary for every box

## 1. Controller (on the jump box)

    scp bin/xdr root@JUMP:/root/xdr
    ssh root@JUMP
    read -rs PW && printf '%s\n' "$PW" | /root/xdr controller install --dir /root/xdr-ctl --name JUMP \
        --gray GRAY1,GRAY2 --auto root --recovery xdrrecover
    systemctl status xdr-controller --no-pager

- The console password (12+ characters) comes from stdin and is never printed.
  An empty one is refused. Run it again any time: nothing changes unless a
  flag does; the password is kept (`--reset-password` replaces it).
- It installs `/usr/local/sbin/xdr` and `xdr-controller.service`
  (restarts on its own), etcd on `JUMP:2379`, console on `https://JUMP:8443`.
- Extra addresses nothing may ever block: `--protect 198.51.100.10,...`.

## 2. Facts (from the jump box, onto the target)

    scp /root/xdr deploy/prep-target.sh root@web01:/root/      # prep-target.sh from the repo
    ssh root@web01 'mkdir -p /root/xdr-day1 && mv /root/xdr /root/prep-target.sh /root/xdr-day1/'
    ssh root@web01 /root/xdr-day1/prep-target.sh > /root/web01-facts.json

It writes nothing on the box. In `web01-facts.json`: `ports` (pick the scored
ones), `accounts` (uid >= 1000 with a login shell: pick blue and gray),
`listeners` (passed to add-target as is).

## 3. Bundle (on the jump box)

    xdr controller add-target --dir /root/xdr-ctl --host web01 --out /root/web01.tgz \
        --listeners /root/web01-facts.json --scored tcp/80,tcp/443 \
        --blue alice,bob --gray GRAY1 --auto root \
        --recovery xdrrecover --recovery-key /root/recovery.pub

- `--kill` defaults to **off**: the agent only reports (would-kill). Turn it
  on later in the console.
- `--recovery-key` is the public half of a key you keep off the boxes.
  Without `--blue`, `--recovery` and `--auto` there is no SSH gate.
- sshd on tcp/22 is always a known listener; scored ports are left out of
  the listeners. `--baseline FILE` ships a baseline (otherwise one is
  captured on the box).
- It will not overwrite `--out` unless `--force`.

## 4. Install (from the jump box, on the target)

    scp /root/web01.tgz root@web01:/root/
    ssh root@web01 'tar -C /root/xdr-day1 -xzf /root/web01.tgz && /root/xdr-day1/install-target.sh'

It captures a baseline first (a minute or two), puts the bundle in
`/etc/xdr`, runs `xdr install`, then checks the agent unit, the incident
log and the controller port: expect three `ok` lines. It refuses a box
that already has an install (see "Install again" below). It never edits
sshd or PAM: the agent does that from its config. `--no-install` only puts
the files down and prints the install command.

## 5. Check in the console

Open `https://JUMP:8443` and log in. Hosts: `web01` is **up**, kill
**off**. Look at its incidents for a few minutes; every would-kill there is
what kill would have done. When it looks right, switch **kill on** for the
host in the Hosts panel (or for all hosts).

Repeat 2 to 5 for each further target.

## Tokens (cheat sheet)

Mint them in the console (break-glass) or on the jump box:

    xdr controller mint-breakglass --dir /root/xdr-ctl --hosts web01 --action pause \
        --from "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --every 2h --out /root/tok-web01

Use one on the target: `/usr/local/sbin/xdr breakglass -` and paste it (then Ctrl-D).

| action            | what it does                                                        |
|-------------------|---------------------------------------------------------------------|
| `pause`           | agent stops acting (and tamper stops killing) for the token's window |
| `approve-session` | lets your own SSH session through the gate                           |
| `uninstall`       | the agent removes the whole install, firewall and gate included     |

Install again over a running agent: `pause` first, then
`./install-target.sh --again` inside the window. Without the pause, the
rewrite is tamper and the installer is killed.

## Remove everything

- Target: an `uninstall` token, `xdr breakglass -`. Agent already dead:
  `xdr uninstall --token TOKEN`.
- Jump box: `systemctl disable --now xdr-controller && rm /etc/systemd/system/xdr-controller.service && systemctl daemon-reload`,
  then `rm -rf /root/xdr-ctl` (the CA, the keys, the console password).

## Locked out

- SSH to the box as the **recovery** account with its off-box key: it skips
  the gate. Become root there (however the box allows), then `xdr breakglass -` with a `pause` or
  `uninstall` token.
- Your own session is held by the gate: approve it in the console or with
  an `approve-session` token.
- Dead-man before a risky change (kill on, a new gate): leave a timer on
  the box that hands the agent an uninstall token unless you stop it:

      systemd-run --unit=day1-deadman --on-active=10min sh -c '/usr/local/sbin/xdr breakglass - < /root/uninstall-web01.tok'
      systemctl stop day1-deadman.timer          # once you know you can still get in

  (A `pause` token in its place only pauses the agent for the window.)
- Keep one root session open on the box while you switch kill on.
