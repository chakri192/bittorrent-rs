#!/usr/bin/env bash
# Checks this client against libtorrent, the reference implementation of BitTorrent v2 (and the engine of qBittorrent, Deluge and
# others), on the loopback interface: v1 and v2, over TCP, over uTP and with encryption, in both directions, magnet links, and the
# v2 hash requests (BEP 52) that a torrent without its piece layers is downloaded with -- asked of libtorrent, and answered for it.
#
# Needs python3 with the libtorrent bindings (Homebrew: `brew install libtorrent-rasterbar`; set LT_PYTHON to that formula's python3
# if it is not the one first on the PATH). Build the binaries first (`cargo build`, or set BIN to a release build's directory).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
LT_PYTHON=${LT_PYTHON:-$(for py in python3 /opt/homebrew/bin/python3 /usr/local/bin/python3; do "$py" -c 'import libtorrent' 2>/dev/null && command -v "$py" && break; done)}
[ -n "$LT_PYTHON" ] || { echo "interop: no python3 with libtorrent (brew install libtorrent-rasterbar)"; exit 2; }
for bin in download create_torrent infohash; do
    [ -x "$BIN/$bin" ] || { echo "interop: $BIN/$bin is not built"; exit 2; }
done

WORK=$(mktemp -d)
PIDS=()
cleanup() { for pid in ${PIDS[@]+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null; done; rm -rf "$WORK"; }
trap cleanup EXIT
PASS=0; FAIL=0
check() { local name=$1; shift; if "$@"; then echo "PASS  $name"; PASS=$((PASS + 1)); else echo "FAIL  $name"; FAIL=$((FAIL + 1)); fi; }
same() { cmp -s "$1" "$2"; }

PORT=$((30000 + RANDOM % 20000))
LT_PORT=$PORT; OURS_PORT=$((PORT + 1)); OTHER=$((PORT + 2))
python3 -c "import os; open('$WORK/data.bin', 'wb').write(os.urandom(3 * 1024 * 1024 + 4321))"
"$BIN/create_torrent" "$WORK/data.bin" --out "$WORK/v1.torrent" --piece-length 256K --no-date --quiet
"$BIN/create_torrent" "$WORK/data.bin" --v2 --out "$WORK/v2.torrent" --piece-length 256K --no-date --quiet
"$LT_PYTHON" "$ROOT/scripts/strip_layers.py" "$WORK/v2.torrent" "$WORK/v2-bare.torrent"
V1=$("$BIN/infohash" "$WORK/v1.torrent" | awk '/info_hash/ {print $2}')
V2=$("$LT_PYTHON" -c "import libtorrent as lt; print(lt.torrent_info('$WORK/v2.torrent').info_hashes().v2)")
MAGNET_V1="magnet:?xt=urn:btih:$V1"
MAGNET_V2="magnet:?xt=urn:btmh:1220$V2&dn=data.bin"

lt_seed() { # torrent, transport, encryption : libtorrent seeds data.bin
    rm -rf "$WORK/lt-seed"; mkdir -p "$WORK/lt-seed"; cp "$WORK/data.bin" "$WORK/lt-seed/"
    LT_TRANSPORT=$2 LT_ENCRYPTION=${3:-} "$LT_PYTHON" "$ROOT/scripts/lt_peer.py" seed "$1" "$WORK/lt-seed" "$LT_PORT" >/dev/null 2>&1 &
    LT_PID=$!; PIDS+=($LT_PID)
    sleep 3
}
lt_stop() { kill "$LT_PID" 2>/dev/null; wait "$LT_PID" 2>/dev/null; }
ours_fetch() { # source, flags... : this client downloads from libtorrent
    local source=$1; shift
    rm -rf "$WORK/out"; mkdir -p "$WORK/out"
    timeout 90 "$BIN/download" "$source" --peer "127.0.0.1:$LT_PORT" --out "$WORK/out" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --port "$OURS_PORT" "$@" >/dev/null 2>&1
}
ours_seed() { # torrent, flags... : this client seeds data.bin
    local torrent=$1; shift
    rm -rf "$WORK/ours"; mkdir -p "$WORK/ours"; cp "$WORK/data.bin" "$WORK/ours/"
    "$BIN/download" "$torrent" --out "$WORK/ours" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" "$@" >/dev/null 2>&1 &
    OURS_PID=$!; PIDS+=($OURS_PID)
    sleep 3
}
ours_stop() { kill "$OURS_PID" 2>/dev/null; wait "$OURS_PID" 2>/dev/null; }
lt_leech() { # source, transport, encryption : libtorrent downloads from this client
    rm -rf "$WORK/lt-leech"; mkdir -p "$WORK/lt-leech"
    LT_TRANSPORT=$2 LT_ENCRYPTION=${3:-} timeout 120 "$LT_PYTHON" "$ROOT/scripts/lt_peer.py" leech "$1" "$WORK/lt-leech" "$LT_PORT" "$OURS_PORT" >/dev/null 2>&1
}

# ---- v1 ----------------------------------------------------------------------
lt_seed "$WORK/v1.torrent" both; ours_fetch "$MAGNET_V1"; check "v1: downloads from libtorrent, and gets the metadata of its magnet link (TCP)" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
lt_seed "$WORK/v1.torrent" utp; ours_fetch "$WORK/v1.torrent" --transport utp; check "v1: downloads from libtorrent over uTP" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
lt_seed "$WORK/v1.torrent" tcp forced; ours_fetch "$WORK/v1.torrent" --encryption require; check "v1: downloads from libtorrent with encryption required of both" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
ours_seed "$WORK/v1.torrent"; lt_leech "$WORK/v1.torrent" tcp; check "v1: libtorrent downloads from this client (TCP)" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop
ours_seed "$WORK/v1.torrent" --transport utp; lt_leech "$WORK/v1.torrent" utp; check "v1: libtorrent downloads from this client over uTP" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop
ours_seed "$WORK/v1.torrent" --encryption require; lt_leech "$WORK/v1.torrent" tcp forced; check "v1: libtorrent downloads from this client with encryption required of both" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop

# ---- v2 (BEP 52) -------------------------------------------------------------
lt_seed "$WORK/v2.torrent" tcp; ours_fetch "$WORK/v2.torrent"; check "v2: downloads from libtorrent (piece layers in the .torrent)" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
lt_seed "$WORK/v2.torrent" tcp; ours_fetch "$WORK/v2-bare.torrent"; check "v2: downloads a .torrent without its piece layers, asking libtorrent for them (hash requests)" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
lt_seed "$WORK/v2.torrent" tcp; ours_fetch "$MAGNET_V2"; check "v2: downloads from a magnet link with only a v2 hash: metadata, then layers, from libtorrent" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
lt_seed "$WORK/v2.torrent" utp; ours_fetch "$MAGNET_V2" --transport utp; check "v2: the same over uTP" same "$WORK/out/data.bin" "$WORK/data.bin"; lt_stop
ours_seed "$WORK/v2.torrent"; lt_leech "$WORK/v2.torrent" tcp; check "v2: libtorrent downloads from this client" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop
ours_seed "$WORK/v2.torrent"; lt_leech "$WORK/v2-bare.torrent" tcp; check "v2: libtorrent downloads a torrent without its layers, asking this client for them (hash requests)" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop
ours_seed "$WORK/v2.torrent"; lt_leech "$MAGNET_V2" tcp; check "v2: libtorrent downloads from a v2 magnet link, the metadata and the layers from this client" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop
ours_seed "$WORK/v2.torrent" --transport utp; lt_leech "$WORK/v2.torrent" utp; check "v2: libtorrent downloads from this client over uTP" same "$WORK/lt-leech/data.bin" "$WORK/data.bin"; ours_stop

# ---- padding files (BEP 47) ----------------------------------------------------
# libtorrent lays a hybrid torrent out with `.pad/N` filler files between the real ones. They are in the pieces and on no disk:
# what comes off the wire and goes on it has the zeros in it, and neither side may write them out.
mkdir -p "$WORK/pack/sub"
for f in a.bin:300000 sub/b.bin:400000 c.bin:150000; do python3 -c "import os; open('$WORK/pack/${f%%:*}', 'wb').write(os.urandom(${f##*:}))"; done
"$LT_PYTHON" "$ROOT/scripts/mk_hybrid.py" "$WORK/pack" "$WORK/pad.torrent"
same_tree() { diff -r "$1" "$2" >/dev/null 2>&1; }
rm -rf "$WORK/lt-pack"; mkdir -p "$WORK/lt-pack"; cp -R "$WORK/pack" "$WORK/lt-pack/"
LT_TRANSPORT=tcp "$LT_PYTHON" "$ROOT/scripts/lt_peer.py" seed "$WORK/pad.torrent" "$WORK/lt-pack" "$LT_PORT" >/dev/null 2>&1 &
LT_PID=$!; PIDS+=($LT_PID); sleep 3
rm -rf "$WORK/out-pack"; mkdir -p "$WORK/out-pack"
timeout 90 "$BIN/download" "$WORK/pad.torrent" --peer "127.0.0.1:$LT_PORT" --out "$WORK/out-pack" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --port "$OURS_PORT" >/dev/null 2>&1
check "padding: downloads a libtorrent hybrid torrent with padding files, writing none of them" same_tree "$WORK/out-pack/pack" "$WORK/pack"
lt_stop
rm -rf "$WORK/ours-pack"; mkdir -p "$WORK/ours-pack"; cp -R "$WORK/pack" "$WORK/ours-pack/"
"$BIN/download" "$WORK/pad.torrent" --out "$WORK/ours-pack" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" >/dev/null 2>&1 &
OURS_PID=$!; PIDS+=($OURS_PID); sleep 3
rm -rf "$WORK/lt-leech"; mkdir -p "$WORK/lt-leech"
LT_TRANSPORT=tcp timeout 120 "$LT_PYTHON" "$ROOT/scripts/lt_peer.py" leech "$WORK/pad.torrent" "$WORK/lt-leech" "$LT_PORT" "$OURS_PORT" >/dev/null 2>&1
check "padding: libtorrent downloads such a torrent from this client, the padding's zeros served in the pieces" same_tree "$WORK/lt-leech/pack" "$WORK/pack"
ours_stop

# ---- both ways on one connection -------------------------------------------------------------------------------------
# Each side has one half of the torrent and wants the other. This client dials libtorrent, which makes no connection itself, and does
# not seed: it leaves the moment it has what it wants (its download is held to 1 MiB/s so that this is not before libtorrent has had
# time to fetch its half; libtorrent stays a few seconds once it has everything, for this client to finish from it). What libtorrent gets from this client it gets over the connection this client made, on which this client
# both downloads and uploads, or not at all.
HALF=$((6 * 256 * 1024))
python3 - "$WORK/data.bin" "$WORK/half-lt.bin" "$WORK/half-ours.bin" "$HALF" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read(); half = int(sys.argv[4])
open(sys.argv[2], 'wb').write(data[:half] + bytes(len(data) - half))   # libtorrent has the first pieces
open(sys.argv[3], 'wb').write(bytes(half) + data[half:])               # this client has the rest
PY
rm -rf "$WORK/x-lt" "$WORK/x-ours"; mkdir -p "$WORK/x-lt" "$WORK/x-ours"
cp "$WORK/half-lt.bin" "$WORK/x-lt/data.bin"; cp "$WORK/half-ours.bin" "$WORK/x-ours/data.bin"
LT_LINGER=8 LT_TRANSPORT=tcp timeout 70 "$LT_PYTHON" "$ROOT/scripts/lt_peer.py" wait "$WORK/v1.torrent" "$WORK/x-lt" "$LT_PORT" >/dev/null 2>&1 &
LT_WAIT=$!; PIDS+=($LT_WAIT); sleep 3
timeout 60 "$BIN/download" "$WORK/v1.torrent" --peer "127.0.0.1:$LT_PORT" --out "$WORK/x-ours" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --max-down 1M --port "$OURS_PORT" >/dev/null 2>&1
OURS_STATUS=$?
wait "$LT_WAIT"; LT_STATUS=$?
both_complete() { [ "$OURS_STATUS" -eq 0 ] && [ "$LT_STATUS" -eq 0 ] && same "$WORK/x-lt/data.bin" "$WORK/data.bin" && same "$WORK/x-ours/data.bin" "$WORK/data.bin"; }
check "both ways: each of this client and libtorrent has half and gets the other's over the one connection this client made" both_complete

# The same, the other way about: libtorrent connects to this client, which knows of no peer (the only one it is given is not there), so
# that everything it downloads comes over the connection libtorrent made, on which libtorrent is served as well. (This client stays
# to seed, so that the end of its download does not close the connection before libtorrent has what it wants.)
rm -rf "$WORK/y-lt" "$WORK/y-ours"; mkdir -p "$WORK/y-lt" "$WORK/y-ours"
cp "$WORK/half-lt.bin" "$WORK/y-lt/data.bin"; cp "$WORK/half-ours.bin" "$WORK/y-ours/data.bin"
"$BIN/download" "$WORK/v1.torrent" --peer "127.0.0.1:9" --out "$WORK/y-ours" --no-dht --no-lsd --no-portmap --no-tui --no-config --no-log --seed --port "$OURS_PORT" >/dev/null 2>&1 &
OURS_PID=$!; PIDS+=($OURS_PID); sleep 2
LT_LINGER=8 LT_TRANSPORT=tcp timeout 70 "$LT_PYTHON" "$ROOT/scripts/lt_peer.py" leech "$WORK/v1.torrent" "$WORK/y-lt" "$LT_PORT" "$OURS_PORT" >/dev/null 2>&1
LT_STATUS=$?
sleep 1; ours_stop
both_complete_inbound() { [ "$LT_STATUS" -eq 0 ] && same "$WORK/y-lt/data.bin" "$WORK/data.bin" && same "$WORK/y-ours/data.bin" "$WORK/data.bin"; }
check "both ways, inbound: libtorrent connects to this client, and each gets the other's half over that connection" both_complete_inbound

echo "interop: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
