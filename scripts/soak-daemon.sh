#!/usr/bin/env bash
# Runs two daemons against each other on loopback with many torrents, for a while, adding and removing torrents
# all the time, and reports what the daemons cost: threads, open files and memory, at the start and the end, and
# whether any torrent failed or a file came out wrong. Not part of the gate (it takes minutes); run it to see that
# nothing leaks as torrents come and go.
#
#   scripts/soak-daemon.sh                  # 40 torrents, 120 seconds
#   TORRENTS=100 DURATION=600 scripts/soak-daemon.sh
#
# Needs python3 (for the tracker). Build the binaries first (`cargo build`, or set BIN to a release build's directory).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
TORRENTS=${TORRENTS:-40}
DURATION=${DURATION:-120}
for bin in daemon create_torrent; do
    [ -x "$BIN/$bin" ] || { echo "soak: $BIN/$bin is not built"; exit 2; }
done
command -v python3 >/dev/null || { echo "soak: python3 is needed"; exit 2; }

WORK=$(mktemp -d /tmp/btsoak.XXXXXX)
PIDS=()
cleanup() { for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

BASE=$((20000 + RANDOM % 20000))
TRACKER_PORT=$BASE; PORT_A=$((BASE + 1)); PORT_B=$((BASE + 2))
SOCK_A=$WORK/a.sock; SOCK_B=$WORK/b.sock

cat > "$WORK/tracker.py" <<'PY'
import http.server, socketserver, struct, sys
port, peer_port = int(sys.argv[1]), int(sys.argv[2])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = bytes([127, 0, 0, 1]) + struct.pack('>H', peer_port)
        out = b'd8:intervali30e5:peers' + str(len(body)).encode() + b':' + body + b'e'
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *args): pass
class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
Server(('127.0.0.1', port), Handler).serve_forever()
PY
python3 "$WORK/tracker.py" "$TRACKER_PORT" "$PORT_A" >/dev/null 2>&1 &
PIDS+=($!)

mkdir -p "$WORK/seed" "$WORK/torrents" "$WORK/leech"
echo "soak: making $TORRENTS torrents"
for i in $(seq 1 "$TORRENTS"); do
    python3 -c "import os; open('$WORK/seed/t$i.bin', 'wb').write(os.urandom(64 * 1024 + $i * 997))"
    "$BIN/create_torrent" "$WORK/seed/t$i.bin" --announce "http://127.0.0.1:$TRACKER_PORT/announce" --out "$WORK/torrents/t$i.torrent" --piece-length 16K --no-date --quiet
done

run_daemon() { # name port socket state
    "$BIN/daemon" run --port "$2" --no-dht --no-lsd --no-portmap --no-ipv6 --quiet --state-dir "$4" --socket "$3" >"$WORK/$1.log" 2>&1 &
    PIDS+=($!)
    LAST_PID=$!
    sleep 1.5
}
run_daemon a "$PORT_A" "$SOCK_A" "$WORK/state-a"; PID_A=$LAST_PID
run_daemon b "$PORT_B" "$SOCK_B" "$WORK/state-b"; PID_B=$LAST_PID
ctl() { local sock=$1; shift; "$BIN/daemon" "$@" --socket "$sock" --json; }

sample() { # pid : "threads fds rss_mb"
    local pid=$1
    echo "$(ps -M -p "$pid" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ') $(lsof -p "$pid" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ') $(( $(ps -o rss= -p "$pid" | tr -d ' ') / 1024 ))"
}

for i in $(seq 1 "$TORRENTS"); do
    ctl "$SOCK_A" add "$WORK/torrents/t$i.torrent" --out "$WORK/seed" >/dev/null || { echo "soak: FAIL adding to A"; exit 1; }
done
seeding() { ctl "$1" list 2>/dev/null | grep -c '"state":"seeding"'; }
for _ in $(seq 1 120); do [ "$(seeding "$SOCK_A")" -eq "$TORRENTS" ] && break; sleep 0.5; done
echo "soak: A seeds $(seeding "$SOCK_A") of $TORRENTS"
for i in $(seq 1 "$TORRENTS"); do
    ctl "$SOCK_B" add "$WORK/torrents/t$i.torrent" --out "$WORK/leech" >/dev/null || { echo "soak: FAIL adding to B"; exit 1; }
done
for _ in $(seq 1 240); do [ "$(seeding "$SOCK_B")" -eq "$TORRENTS" ] && break; sleep 0.5; done
echo "soak: B has finished $(seeding "$SOCK_B") of $TORRENTS"

START_A=$(sample "$PID_A"); START_B=$(sample "$PID_B")
echo "soak: at the start (threads fds MiB)   A: $START_A   B: $START_B"

# Churn: for the rest of the time, take a torrent off B and put it back, one a second.
END=$((SECONDS + DURATION))
churns=0
while [ $SECONDS -lt $END ]; do
    i=$((RANDOM % TORRENTS + 1))
    hash=$("$BIN/infohash" "$WORK/torrents/t$i.torrent" 2>/dev/null | awk '/info_hash/ {print $2}')
    if [ -n "$hash" ]; then
        ctl "$SOCK_B" remove "${hash:0:12}" >/dev/null 2>&1
        ctl "$SOCK_B" add "$WORK/torrents/t$i.torrent" --out "$WORK/leech" >/dev/null 2>&1
        churns=$((churns + 1))
    fi
    sleep 1
done
for _ in $(seq 1 60); do [ "$(seeding "$SOCK_B")" -eq "$TORRENTS" ] && break; sleep 0.5; done

END_A=$(sample "$PID_A"); END_B=$(sample "$PID_B")
echo "soak: at the end   (threads fds MiB)   A: $END_A   B: $END_B   after $churns removals and additions"

failed=$(ctl "$SOCK_A" list | grep -c '"state":"failed"'); failed=$((failed + $(ctl "$SOCK_B" list | grep -c '"state":"failed"')))
wrong=0
for i in $(seq 1 "$TORRENTS"); do cmp -s "$WORK/seed/t$i.bin" "$WORK/leech/t$i.bin" || wrong=$((wrong + 1)); done
status=0
[ "$failed" -eq 0 ] || { echo "soak: FAIL $failed torrent(s) in the failed state"; status=1; }
[ "$wrong" -eq 0 ] || { echo "soak: FAIL $wrong file(s) differ"; status=1; }
[ "$(seeding "$SOCK_B")" -eq "$TORRENTS" ] || { echo "soak: FAIL B has $(seeding "$SOCK_B") of $TORRENTS seeding"; status=1; }
[ "$status" -eq 0 ] && echo "soak: ok -- $TORRENTS torrents on each daemon, every file intact, none failed"
ctl "$SOCK_B" stop >/dev/null 2>&1; ctl "$SOCK_A" stop >/dev/null 2>&1
exit $status
