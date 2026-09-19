#!/usr/bin/env bash
# Checks this client against a real one, aria2, on the loopback interface:
#
#   * downloading from aria2 (plain, then with encryption required of both)
#   * aria2 downloading from this client (plain, then encrypted), and
#     fetching the metadata of a magnet link from it (BEP 9)
#   * the DHT, over IPv4 and over IPv6 (BEP 32), with an aria2 node as the
#     router, in both directions
#   * local service discovery (BEP 14) in both directions, over the real
#     multicast group -- skipped unless INTEROP_LSD=1, since it needs
#     multicast to work on this machine and takes some seconds
#
# What the harness (`cargo run --bin e2e_harness`) cannot show, since it is
# written by the same hands as the client: that another implementation of the
# protocol agrees. Needs aria2c and python3. Build the binaries first
# (`cargo build`, or set BIN to the directory of a release build).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
for tool in aria2c python3; do
    command -v "$tool" >/dev/null || { echo "interop: $tool is needed"; exit 2; }
done
for bin in download create_torrent; do
    [ -x "$BIN/$bin" ] || { echo "interop: $BIN/$bin is not built"; exit 2; }
done

WORK=$(mktemp -d)
PIDS=()
cleanup() { for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT

PASS=0
FAIL=0
check() { # name, command... : passes when the command succeeds
    local name=$1; shift
    if "$@"; then echo "PASS  $name"; PASS=$((PASS + 1)); else echo "FAIL  $name"; FAIL=$((FAIL + 1)); fi
}
same() { cmp -s "$1" "$2"; }

TRACKER_PORT=$((20000 + RANDOM % 10000))
ARIA_PORT=$((30000 + RANDOM % 5000))
OURS_PORT=$((35000 + RANDOM % 5000))
ARIA_LEECH_PORT=$((40000 + RANDOM % 5000))

python3 -c "import os; open('$WORK/data.bin', 'wb').write(os.urandom(3 * 1024 * 1024 + 4321))"

# A tracker that lists the one peer it is told of, whoever asks.
cat > "$WORK/tracker.py" <<'PY'
import http.server, socketserver, struct, sys
port, peer_port = int(sys.argv[1]), int(sys.argv[2])
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = bytes([127, 0, 0, 1]) + struct.pack('>H', peer_port)
        out = b'd8:intervali30e5:peers' + str(len(body)).encode() + b':' + body + b'e'
        self.send_response(200); self.send_header('Content-Length', str(len(out))); self.end_headers(); self.wfile.write(out)
    def log_message(self, *args): pass
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', port), Handler).serve_forever()
PY

start_tracker() { # the port of the peer it lists
    python3 "$WORK/tracker.py" "$TRACKER_PORT" "$1" >/dev/null 2>&1 &
    PIDS+=($!)
    sleep 0.7
}
stop_last() {
    local pid=${PIDS[${#PIDS[@]}-1]}
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
    unset "PIDS[${#PIDS[@]}-1]"
}

"$BIN/create_torrent" "$WORK/data.bin" --announce "http://127.0.0.1:$TRACKER_PORT/announce" --out "$WORK/tracked.torrent" --piece-length 256K --no-date --quiet
"$BIN/create_torrent" "$WORK/data.bin" --out "$WORK/untracked.torrent" --piece-length 256K --no-date --quiet
HASH=$("$BIN/infohash" "$WORK/tracked.torrent" 2>/dev/null | awk '/info_hash/ {print $2}')

ours() { # extra flags... : this client, quiet, without anything that leaves loopback
    "$BIN/download" "$@" --no-dht --no-portmap --no-tui --no-config --no-log
}

# ---- 1. this client downloads from aria2 ----------------------------------
for mode in plain encrypted; do
    rm -rf "$WORK/seed" "$WORK/out"; mkdir -p "$WORK/seed"; cp "$WORK/data.bin" "$WORK/seed/"
    crypto=(); ours_crypto=()
    [ $mode = encrypted ] && { crypto=(--bt-require-crypto=true --bt-min-crypto-level=arc4); ours_crypto=(--encryption require); }
    start_tracker "$ARIA_PORT"
    aria2c --enable-dht=false --bt-enable-lpd=false --enable-peer-exchange=false --listen-port="$ARIA_PORT" --seed-ratio=0.0 --seed-time=10 \
        -d "$WORK/seed" --bt-seed-unverified=true --bt-external-ip=127.0.0.1 ${crypto[@]+"${crypto[@]}"} "$WORK/tracked.torrent" >"$WORK/aria-seed.log" 2>&1 &
    PIDS+=($!)
    sleep 3
    timeout 90 "$BIN/download" "$WORK/tracked.torrent" --out "$WORK/out" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log ${ours_crypto[@]+"${ours_crypto[@]}"} >/dev/null 2>&1
    check "downloads from aria2 ($mode)" same "$WORK/out/data.bin" "$WORK/data.bin"
    stop_last; stop_last
done

# ---- 2. aria2 downloads from this client -----------------------------------
rm -rf "$WORK/ours"; mkdir -p "$WORK/ours"; cp "$WORK/data.bin" "$WORK/ours/"
start_tracker "$OURS_PORT"
"$BIN/download" "$WORK/tracked.torrent" --out "$WORK/ours" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" >/dev/null 2>&1 &
PIDS+=($!)
sleep 4
for mode in plain encrypted magnet; do
    rm -rf "$WORK/leech"; mkdir -p "$WORK/leech"
    crypto=()
    [ $mode = encrypted ] && crypto=(--bt-require-crypto=true --bt-min-crypto-level=arc4)
    source="$WORK/tracked.torrent"
    [ $mode = magnet ] && source="magnet:?xt=urn:btih:$HASH&tr=http%3A%2F%2F127.0.0.1%3A$TRACKER_PORT%2Fannounce"
    timeout 60 aria2c --enable-dht=false --bt-enable-lpd=false --enable-peer-exchange=false --listen-port="$ARIA_LEECH_PORT" --seed-time=0 \
        -d "$WORK/leech" --console-log-level=error ${crypto[@]+"${crypto[@]}"} "$source" >/dev/null 2>&1
    check "aria2 downloads from this client ($mode)" same "$WORK/leech/data.bin" "$WORK/data.bin"
done
stop_last; stop_last

# ---- 3. local service discovery, over the real multicast group -------------
if [ "${INTEROP_LSD:-0}" = 1 ]; then
    # aria2 leeches, this client seeds: the seeder must answer aria2's announcement.
    rm -rf "$WORK/ours" "$WORK/leech"; mkdir -p "$WORK/ours" "$WORK/leech"; cp "$WORK/data.bin" "$WORK/ours/"
    "$BIN/download" "$WORK/untracked.torrent" --out "$WORK/ours" --no-dht --lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" >/dev/null 2>&1 &
    PIDS+=($!)
    sleep 4
    timeout 100 aria2c --enable-dht=false --bt-enable-lpd=true --enable-peer-exchange=false --listen-port="$ARIA_LEECH_PORT" --seed-time=0 -d "$WORK/leech" --console-log-level=error "$WORK/untracked.torrent" >/dev/null 2>&1
    check "aria2 finds this client by local discovery" same "$WORK/leech/data.bin" "$WORK/data.bin"
    stop_last

    # This client leeches, started first; aria2 seeds and announces when it starts.
    rm -rf "$WORK/seed" "$WORK/out"; mkdir -p "$WORK/seed"; cp "$WORK/data.bin" "$WORK/seed/"
    timeout 100 "$BIN/download" "$WORK/untracked.torrent" --out "$WORK/out" --no-dht --lsd --no-portmap --no-tui --no-config --no-log >/dev/null 2>&1 &
    OURS=$!
    sleep 5
    aria2c --enable-dht=false --bt-enable-lpd=true --enable-peer-exchange=false --listen-port="$ARIA_PORT" --seed-ratio=0.0 --seed-time=2 \
        -d "$WORK/seed" --bt-seed-unverified=true --console-log-level=error "$WORK/untracked.torrent" >/dev/null 2>&1 &
    PIDS+=($!)
    wait "$OURS"
    check "this client finds aria2 by local discovery" same "$WORK/out/data.bin" "$WORK/data.bin"
else
    echo "SKIP  local service discovery (set INTEROP_LSD=1 to try it)"
fi

# ---- 4. the DHT, over IPv4 and over IPv6 (BEP 32), on loopback ------------
# An aria2 node R is the router; aria2 S seeds through it, and this client finds S by asking R;
# then this client seeds through R and aria2 L finds it. Nothing leaves the machine: the routers
# are named with BITTORRENT_RS_DHT_BOOTSTRAP, and aria2's tables are kept under $WORK.
python3 -c "import os; open('$WORK/filler.bin', 'wb').write(os.urandom(200000))"
"$BIN/create_torrent" "$WORK/filler.bin" --out "$WORK/filler.torrent" --piece-length 256K --no-date --quiet
dht_family() { # 4 or 6
    local fam=$1 router entry flags
    local rport=$((45000 + RANDOM % 4000)) sport=$((49000 + RANDOM % 1000))
    if [ "$fam" = 6 ]; then
        python3 -c "import socket; socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).bind(('::1', 0))" 2>/dev/null || { echo "SKIP  DHT over IPv6 (no IPv6 loopback)"; return; }
        router="[::1]:$rport"; entry=(--dht-entry-point6="$router"); flags=(--enable-dht=false --enable-dht6=true --dht-listen-addr6=::1)
        ours_flags=(--ipv6)
    else
        router="127.0.0.1:$rport"; entry=(--dht-entry-point="$router"); flags=(--enable-dht=true --enable-dht6=false)
        ours_flags=(--no-ipv6)
    fi
    rm -f "$WORK"/*.dat
    # R: the router, seeding something else.
    rm -rf "$WORK/rdir"; mkdir -p "$WORK/rdir"; cp "$WORK/filler.bin" "$WORK/rdir/"
    aria2c --enable-dht=true --enable-dht6=true --dht-listen-port="$rport" --dht-listen-addr6=::1 --dht-file-path="$WORK/r4.dat" --dht-file-path6="$WORK/r6.dat"         --bt-enable-lpd=false --enable-peer-exchange=false --listen-port=$((rport + 100)) --seed-ratio=0.0 --seed-time=10 -d "$WORK/rdir" --bt-seed-unverified=true         --console-log-level=error "$WORK/filler.torrent" >/dev/null 2>&1 &
    PIDS+=($!)
    sleep 3

    # S seeds through R; this client, asking R, finds it.
    rm -rf "$WORK/seed" "$WORK/out"; mkdir -p "$WORK/seed"; cp "$WORK/data.bin" "$WORK/seed/"
    aria2c "${flags[@]}" ${entry[@]+"${entry[@]}"} --dht-listen-port="$sport" --dht-file-path="$WORK/s4.dat" --dht-file-path6="$WORK/s6.dat" \
        --bt-enable-lpd=false --enable-peer-exchange=false --listen-port=$((sport + 100)) --seed-ratio=0.0 --seed-time=10 -d "$WORK/seed" --bt-seed-unverified=true \
        --console-log-level=error "$WORK/untracked.torrent" >/dev/null 2>&1 &
    PIDS+=($!)
    sleep 15
    BITTORRENT_RS_DHT_BOOTSTRAP="$router" timeout 90 "$BIN/download" "$WORK/untracked.torrent" --out "$WORK/out" --dht "${ours_flags[@]}" --no-lsd --no-portmap --no-tui --no-config --no-log >/dev/null 2>&1
    check "this client finds an aria2 seeder through the DHT (IPv$fam)" same "$WORK/out/data.bin" "$WORK/data.bin"
    stop_last

    # This client seeds through R; aria2 L, asking R, finds it.
    rm -rf "$WORK/ours" "$WORK/leech"; mkdir -p "$WORK/ours" "$WORK/leech"; cp "$WORK/data.bin" "$WORK/ours/"
    BITTORRENT_RS_DHT_BOOTSTRAP="$router" "$BIN/download" "$WORK/untracked.torrent" --out "$WORK/ours" --dht "${ours_flags[@]}" --no-lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" >/dev/null 2>&1 &
    PIDS+=($!)
    sleep 8
    timeout 90 aria2c "${flags[@]}" ${entry[@]+"${entry[@]}"} --dht-listen-port=$((sport + 1)) --dht-file-path="$WORK/l4.dat" --dht-file-path6="$WORK/l6.dat" \
        --bt-enable-lpd=false --enable-peer-exchange=false --listen-port=$((sport + 101)) --seed-time=0 -d "$WORK/leech" --console-log-level=error "$WORK/untracked.torrent" >/dev/null 2>&1
    check "aria2 finds this client through the DHT (IPv$fam)" same "$WORK/leech/data.bin" "$WORK/data.bin"
    stop_last; stop_last
}
dht_family 4
dht_family 6

echo "interop: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
