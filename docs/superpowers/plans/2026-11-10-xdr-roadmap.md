# XDR Roadmap

Spec: `docs/superpowers/specs/2026-11-10-xdr-design.md`

The spec spans several subsystems. Each plan below produces working, testable software on its own and builds on the ones before it. Plans are written one at a time; each is detailed only when the previous one is done, so later plans can use real interfaces instead of guesses.

| # | Plan | Delivers | Spec sections |
|---|------|----------|---------------|
| 1 | **Foundation & baseline engine** | Single static Go binary; capture a host snapshot; diff against an embedded baseline across every persistence location; package-layer hashes from `.deb`s; LXD Ubuntu 24.04 test harness | §4 (binary, embed), §5, §6.2, §6.3 |
| 2 | **Network enforcement & reverse-shell kill** | nftables table (input/output/forward, scored-service allows, egress deny, drift re-assert); eBPF exec/connect/socket telemetry with process attribution; reverse-shell, DNS, raw-socket, unknown-listener detection; kill process subtree with scored-service guard; local incident log | §6.1, §7.1 steps 1–2, §7.2, §7.4 listeners, §8 firewall |
| 3 | **Fleet: controller, etcd, signed rules, hunt** | Controller role on jump box; single-node etcd with per-node certs + RBAC; rule proposal → validation → signing → promotion; etcd watches + peer mTLS mesh relay; heartbeats; IOC extraction and fleet-wide hunt | §4 state/trust/promotion/fleet comms, §7.1 steps 3–4, §9 heartbeats |
| 4 | **SSH gate, accounts, break-glass** | pam_exec session gate + logind terminate with grace window; platform-session auto-approve; recovery account lockdown; new-user disable; pre-minted signed break-glass tokens; T-0 credential/key rotation tooling | §7.3, §7.4 users/sessions, §8 SSH, §10 |
| 5 | **Self-protection & connectivity self-healing** | Multiple launch points, binary copies, mutual watchers, controller reinstall; tamper detection → kill actor; reconnect ladder + call-home channel | §9, §9a, §7.4 tamper |
| 6 | **Console & service inspectors** | Web UI embedded in controller (alerts, approvals, triage list, sessions, hosts, break-glass); MySQL / Docker / Postfix inspectors; approval actions (restore binary, remove with undo) | §6.2 service items, §7.1 step 6, §7.4 destroy rules, §11, §13 Apache |
| 7 | **Deployment & rehearsal** | Ansible roles for jump box + targets; baseline build pipeline from the competition base image; full red-team rehearsal script in the LXD harness | §3 deployment, end-to-end |

Order rationale: the baseline engine (1) is the source of truth for every later "is this known-good?" decision and gives a usable T-0 sweep tool on its own. Reverse-shell defense (2) is the operator's top priority and comes next. Fleet coordination (3) turns single-box detections into fleet-wide ones.
