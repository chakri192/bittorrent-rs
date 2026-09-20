#!/usr/bin/env bash
# Checks this client against a second real one, Transmission (libtransmission, with its own uTP, libutp), on the
# loopback interface -- the counterpart of interop-aria2.sh for what aria2 does not speak:
#
#   * downloading from Transmission over TCP, over uTP alone (BEP 29: Transmission's TCP is switched off),
#     and with encryption required of both (MSE)
#   * Transmission downloading from this client over each of the same three, which needs this client, once it is a
#     seed, to connect out to the leecher: Transmission does not dial loopback peers a tracker names, so it is
#     this side that dials
#
# Needs transmission-daemon, transmission-remote and python3. Build the binaries first (`cargo build`, or set BIN to
# the directory of a release build). Everything stays on 127.0.0.1: no DHT, no local discovery, no port mapping.
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
for tool in transmission-daemon transmission-remote python3; do
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

BASE=$((20000 + RANDOM % 20000))
TRACKER_PORT=$BASE
TR_PEER_PORT=$((BASE + 1))
TR_RPC_PORT=$((BASE + 2))
OURS_PORT=$((BASE + 3))
RPC=127.0.0.1:$TR_RPC_PORT

python3 -c "import os; open('$WORK/data.bin', 'wb').write(os.urandom(3 * 1024 * 1024 + 4321))"
"$BIN/create_torrent" "$WORK/data.bin" --announce "http://127.0.0.1:$TRACKER_PORT/announce" --out "$WORK/data.torrent" --piece-length 256K --no-date --quiet

# A tracker that lists Transmission, whoever asks.
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
python3 "$WORK/tracker.py" "$TRACKER_PORT" "$TR_PEER_PORT" >/dev/null 2>&1 &
PIDS+=($!)
sleep 0.7

TR_PID=""
start_transmission() { # tcp, utp, encryption, download dir : a fresh daemon
    stop_transmission
    rm -rf "$WORK/cfg"; mkdir -p "$WORK/cfg"
    cat > "$WORK/cfg/settings.json" <<JSON
{ "bind_address_ipv4": "0.0.0.0", "dht_enabled": false, "lpd_enabled": false, "pex_enabled": false,
  "tcp_enabled": $1, "utp_enabled": $2, "encryption": "$3",
  "peer_port": $TR_PEER_PORT, "peer_port_random_on_start": false, "port_forwarding_enabled": false,
  "rpc_port": $TR_RPC_PORT, "rpc_bind_address": "127.0.0.1", "rpc_authentication_required": false,
  "rpc_whitelist_enabled": false, "rpc_host_whitelist_enabled": false,
  "download_dir": "$4", "download_queue_enabled": false, "seed_queue_enabled": false, "ratio_limit_enabled": false }
JSON
    transmission-daemon --foreground --config-dir "$WORK/cfg" --logfile "$WORK/transmission.log" >/dev/null 2>&1 &
    TR_PID=$!
    for _ in $(seq 1 50); do transmission-remote "$RPC" -l >/dev/null 2>&1 && return 0; sleep 0.2; done
    return 1
}
stop_transmission() {
    [ -n "$TR_PID" ] && { kill "$TR_PID" 2>/dev/null; wait "$TR_PID" 2>/dev/null; TR_PID=""; }
}
transmission_done() { # whether its one torrent has everything
    transmission-remote "$RPC" -l 2>/dev/null | sed -n 2p | grep -q ' 100% '
}
ours() { # extra flags... : this client, quiet, without anything that leaves loopback
    "$BIN/download" "$@" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log
}

for mode in tcp utp mse; do
    case $mode in
        tcp) tr_tcp=true;  tr_utp=false; tr_crypto=tolerated; ours_flags=() ;;
        utp) tr_tcp=false; tr_utp=true;  tr_crypto=tolerated; ours_flags=(--transport utp) ;;
        mse) tr_tcp=true;  tr_utp=false; tr_crypto=required;  ours_flags=(--encryption require) ;;
    esac

    # ---- this client downloads from Transmission ----------------------------
    rm -rf "$WORK/seed" "$WORK/out"; mkdir -p "$WORK/seed" "$WORK/out"; cp "$WORK/data.bin" "$WORK/seed/"
    start_transmission $tr_tcp $tr_utp $tr_crypto "$WORK/seed" || { echo "FAIL  could not start transmission-daemon"; exit 1; }
    transmission-remote "$RPC" -a "$WORK/data.torrent" -w "$WORK/seed" >/dev/null 2>&1
    sleep 3
    timeout 90 "$BIN/download" "$WORK/data.torrent" --out "$WORK/out" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --port "$OURS_PORT" ${ours_flags[@]+"${ours_flags[@]}"} >/dev/null 2>&1
    check "downloads from Transmission ($mode)" same "$WORK/out/data.bin" "$WORK/data.bin"
    stop_transmission

    # ---- Transmission downloads from this client (which dials it) -----------
    rm -rf "$WORK/ours" "$WORK/leech"; mkdir -p "$WORK/ours" "$WORK/leech"; cp "$WORK/data.bin" "$WORK/ours/"
    start_transmission $tr_tcp $tr_utp $tr_crypto "$WORK/leech" || { echo "FAIL  could not start transmission-daemon"; exit 1; }
    transmission-remote "$RPC" -a "$WORK/data.torrent" -w "$WORK/leech" >/dev/null 2>&1
    sleep 1
    timeout 120 "$BIN/download" "$WORK/data.torrent" --out "$WORK/ours" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" ${ours_flags[@]+"${ours_flags[@]}"} >/dev/null 2>&1 &
    OURS_PID=$!
    PIDS+=($OURS_PID)
    for _ in $(seq 1 90); do transmission_done && break; sleep 1; done
    check "Transmission downloads from this client ($mode)" same "$WORK/leech/data.bin" "$WORK/data.bin"
    kill "$OURS_PID" 2>/dev/null; wait "$OURS_PID" 2>/dev/null
    stop_transmission
done

echo "interop: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
