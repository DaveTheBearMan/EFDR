#!/bin/bash
# Firewall behaviour against real packets, in throwaway network namespaces.
#
#   xb (jump 192.0.2.7, stranger 203.0.113.9) --- xa (the box, 192.0.2.5) --- xc (container, 198.51.100.130)
#
# xa publishes xc:80 on its port 8080 with a DNAT rule in a table of its
# own, as Docker does. That table also means xa tracks connections before
# the xdr table is loaded, like a host running Docker. With FW_NO_NAT=1 there
# is no such table: conntrack starts with the xdr table and picks up the
# connections already open mid-stream, like a stock server.
set -u
cd "$(dirname "$0")/../.."
[ "$(id -u)" = 0 ] || { echo "fw.sh: needs root" >&2; exit 2; }
XDR=$PWD/bin/xdr
[ -x "$XDR" ] || { echo "fw.sh: build bin/xdr first" >&2; exit 2; }

BOX=192.0.2.5 JUMP=192.0.2.7 STRANGER=203.0.113.9 CTR=198.51.100.130
tmp=$(mktemp -d)
fails=0

cleanup() {
	pkill -f "$tmp/net.py" 2>/dev/null
	for n in xa xb xc; do ip netns del $n 2>/dev/null; done
	rm -rf "$tmp"
}
trap cleanup EXIT
for n in xa xb xc; do ip netns del $n 2>/dev/null; done

cat > "$tmp/net.py" <<'PY'
"""serve PORT LOG | probe SRC HOST PORT | chat SRC HOST PORT LOG | watch SRC HOST PORT LOG

A probe asks for one answer and prints ok, timeout or refused. A chat keeps
a connection open on which both ends send a byte every 0.3 s on their own
initiative; each end appends a line to its log for every byte received.
A watch is a chat whose client sends nothing after its first byte, so the
first packet of it after the table loads is the server's.
"""
import socket, sys, threading, time

def chatter(conn, log):
    # Without this, one unacknowledged byte holds back all later ones and a
    # connection cut in one direction looks cut in both.
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    def send():
        try:
            while True:
                conn.sendall(b"x")
                time.sleep(0.3)
        except OSError:
            pass
    threading.Thread(target=send, daemon=True).start()
    while True:
        data = conn.recv(100)
        if not data:
            return
        with open(log, "a") as f:
            f.write("x\n" * len(data))

def serve(port, log):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", port))
    s.listen(16)
    def handle(conn):
        try:
            if conn.recv(1) == b"p":
                conn.sendall(b"k")
            else:
                chatter(conn, log)
        except OSError:
            pass
        finally:
            conn.close()
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()

def dial(src, host, port):
    s = socket.socket()
    s.settimeout(2)
    if src != "-":
        s.bind((src, 0))
    s.connect((host, port))
    return s

mode, args = sys.argv[1], sys.argv[2:]
if mode == "serve":
    serve(int(args[0]), args[1])
elif mode == "probe":
    try:
        s = dial(args[0], args[1], int(args[2]))
        s.sendall(b"p")
        print("ok" if s.recv(1) == b"k" else "garbled")
    except socket.timeout:
        print("timeout")
    except OSError as e:
        print("refused" if isinstance(e, ConnectionRefusedError) else "error: %s" % e)
elif mode == "watch":
    s = dial(args[0], args[1], int(args[2]))
    s.settimeout(None)
    s.sendall(b"c")
    while True:
        data = s.recv(100)
        if not data:
            break
        with open(args[3], "a") as f:
            f.write("x\n" * len(data))
elif mode == "chat":
    s = dial(args[0], args[1], int(args[2]))
    s.settimeout(None)
    s.sendall(b"c")
    chatter(s, args[3])
PY

in_ns() { local n=$1; shift; ip netns exec "$n" "$@"; }
serve() { in_ns "$1" python3 "$tmp/net.py" serve "$2" "$tmp/$1-$2.log" & }
probe() { in_ns "$1" python3 "$tmp/net.py" probe "$2" "$3" "$4"; }
lines() { wc -l < "$1" 2>/dev/null || echo 0; }
ok() { echo "ok $1"; }
fail() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
# expect CASE WANT GOT
expect() { if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "want $2, got $3"; fi; }
# grows LOG: whether the log gains lines over the next two seconds.
grows() { local a; a=$(lines "$1"); sleep 2; [ "$(lines "$1")" -gt "$a" ] && echo yes || echo no; }

for n in xa xb xc; do ip netns add $n; in_ns $n ip link set lo up; done
ip link add ab0 netns xa type veth peer name ba0 netns xb
ip link add ac0 netns xa type veth peer name ca0 netns xc
in_ns xa ip addr add $BOX/24 dev ab0
in_ns xa ip addr add 198.51.100.129/25 dev ac0
in_ns xb ip addr add $JUMP/24 dev ba0
in_ns xb ip addr add $STRANGER/32 dev ba0
in_ns xc ip addr add $CTR/25 dev ca0
in_ns xa ip link set ab0 up; in_ns xa ip link set ac0 up
in_ns xb ip link set ba0 up; in_ns xc ip link set ca0 up
in_ns xa ip route add $STRANGER/32 dev ab0
in_ns xb ip route add 198.51.100.128/25 via $BOX
in_ns xc ip route add default via 198.51.100.129
in_ns xa sysctl -qw net.ipv4.ip_forward=1
NO_NAT=${FW_NO_NAT:-}
[ -n "$NO_NAT" ] || in_ns xa nft -f - <<NFT
table ip nat {
	chain prerouting { type nat hook prerouting priority dstnat; tcp dport 8080 dnat to $CTR:80; }
}
NFT

cat > "$tmp/agent.json" <<JSON
{"host": "xa", "jump": ["$JUMP"], "dhcp": false,
 "scored": [{"proto": "tcp", "port": 80}, {"proto": "tcp", "port": 8080}]}
JSON
fw() { in_ns xa "$XDR" fw "$@" --config "$tmp/agent.json"; }

serve xa 80; serve xa 4444; serve xa 22
serve xb 9999; serve xb 7443
serve xc 80
sleep 0.5

# Without the firewall everything connects: the cases below that expect a
# timeout are then the firewall's doing.
published="xb $STRANGER $BOX 8080"
[ -z "$NO_NAT" ] || published=""
for t in "xb $STRANGER $BOX 4444" "xb $STRANGER $BOX 22" "xa - $STRANGER 9999" "xc - $STRANGER 9999" ${published:+"$published"}; do
	# shellcheck disable=SC2086
	got=$(probe $t)
	[ "$got" = ok ] || { echo "fw.sh: setup is broken: probe $t: $got" >&2; exit 2; }
done
in_ns xa ping -c1 -W1 $STRANGER >/dev/null || { echo "fw.sh: setup is broken: no ping" >&2; exit 2; }

# Two connections that are open when the table loads.
in_ns xa python3 "$tmp/net.py" chat - $STRANGER 9999 "$tmp/shell.log" &
in_ns xb python3 "$tmp/net.py" chat $STRANGER $BOX 80 "$tmp/visitor.log" &
# The operator's session, quiet while the box talks.
in_ns xb python3 "$tmp/net.py" watch $JUMP $BOX 22 "$tmp/operator.log" &
sleep 1
[ "$(grows "$tmp/shell.log")" = yes ] && [ "$(grows "$tmp/xa-80.log")" = yes ] && [ "$(grows "$tmp/operator.log")" = yes ] ||
	{ echo "fw.sh: setup is broken: the long-lived connections are silent" >&2; exit 2; }

shell_in=$(lines "$tmp/shell.log") shell_out=$(lines "$tmp/xb-9999.log")
fw apply || { echo "fw.sh: fw apply failed" >&2; exit 1; }
# The first seconds are when a half-cut connection still delivers: a sender
# whose data is never acknowledged soon stops sending. One byte may have
# been in flight when the table loaded.
sleep 3
passed() { [ $(($(lines "$1") - $2)) -gt 1 ] && echo yes || echo no; }
expect pre-existing-revshell "in no, out no" "in $(passed "$tmp/shell.log" "$shell_in"), out $(passed "$tmp/xb-9999.log" "$shell_out")"

expect scored-in ok "$(probe xb $STRANGER $BOX 80)"
expect unknown-in timeout "$(probe xb $STRANGER $BOX 4444)"
expect ssh-jump ok "$(probe xb $JUMP $BOX 22)"
expect ssh-stranger timeout "$(probe xb $STRANGER $BOX 22)"
expect egress-denied timeout "$(probe xa - $STRANGER 9999)"
expect egress-xdr ok "$(probe xa - $JUMP 7443)"
expect ping-in answered "$(in_ns xb ping -c1 -W1 $BOX >/dev/null && echo answered || echo lost)"
expect ping-out lost "$(in_ns xa ping -c1 -W1 $STRANGER >/dev/null && echo answered || echo lost)"
expect pre-existing-scored "in yes, out yes" "in $(grows "$tmp/xa-80.log"), out $(grows "$tmp/visitor.log")"
expect pre-existing-quiet-ssh yes "$(grows "$tmp/operator.log")"
[ -n "$NO_NAT" ] || expect forward-published ok "$(probe xb $STRANGER $BOX 8080)"
expect forward-egress timeout "$(probe xc - $STRANGER 9999)"

table() { in_ns xa nft list table inet xdr >/dev/null 2>&1 && echo present || echo gone; }
fw remove
fw try --timeout 3s >/dev/null
expect try-reverts "exit 1, table gone" "exit $?, table $(table)"
fw try --timeout 10s >/dev/null &
try=$!
sleep 1
fw confirm
wait $try
expect try-confirmed "exit 0, table present" "exit $?, table $(table)"

[ $fails = 0 ]
