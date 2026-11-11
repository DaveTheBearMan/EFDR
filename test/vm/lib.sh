# Shared helpers of the VM tests. The caller sets VM, CONF, BASE and LOG.
# shellcheck shell=bash

x() { lxc exec "$VM" -- "$@"; }
# bg CMD: start CMD in the VM, detached, so lxc exec returns at once.
bg() { x sh -c "setsid -f $1 </dev/null >/dev/null 2>&1"; }
fails=0
ok() { echo "ok $1"; }
fail() { echo "FAIL $1: $2"; fails=$((fails + 1)); }
# conf PYTHON: edit the agent's config in the VM (c is the dict).
conf() {
  x python3 -c "import json; c = json.load(open('$CONF')); $1; json.dump(c, open('$CONF', 'w'))"
}
starts=0
# start_agent ARGS...: start the agent; wait for its sensor line.
start_agent() {
  starts=$((starts + 1))
  ERR=/var/log/xdr-agent.$starts.err
  x systemd-run --unit=xdr-agent -p StandardOutput=append:/var/log/xdr-agent.$starts.out \
    -p StandardError=append:$ERR /usr/local/sbin/xdr agent --config "$CONF" --baseline "$BASE" --log "$LOG" "$@" >/dev/null
  for _ in $(seq 60); do
    x grep -q '^sensor:' "$ERR" 2>/dev/null && return 0
    sleep 0.5
  done
  return 1
}
stop_agent() { x systemctl stop xdr-agent; x systemctl reset-failed xdr-agent 2>/dev/null; }
hup() { x systemctl kill -s HUP --kill-whom=main xdr-agent; sleep 2; }

# mark: incidents after this count as the case's own.
mark() { MARK=$(x sh -c "wc -l < $LOG 2>/dev/null || echo 0"); }
# inc KIND ACTION [COND]: a line since mark with that kind and action ("" any)
# for which the python expression COND (over the incident i) holds.
inc() {
  x sh -c "cat $LOG 2>/dev/null" | tail -n +$((MARK + 1)) | python3 -c '
import json, sys
kind, action = sys.argv[1], sys.argv[2]
cond = sys.argv[3] if len(sys.argv) > 3 else "True"
for line in sys.stdin:
    i = json.loads(line)
    if i["kind"] == kind and action in ("", i["action"]) and eval(cond, {"i": i}):
        sys.exit(0)
sys.exit(1)' "$@"
}
# wait_inc SECONDS KIND ACTION [COND]
wait_inc() {
  local secs=$1; shift
  for _ in $(seq $((secs * 4))); do inc "$@" && return 0; sleep 0.25; done
  return 1
}
# gone SECONDS PATTERN: no process matches PATTERN (pgrep -f) within SECONDS.
gone() {
  for _ in $(seq $(($1 * 4))); do x pgrep -f "$2" >/dev/null || return 0; sleep 0.25; done
  return 1
}
