#!/usr/bin/env bash
# The checks that need two machines on one network, which the loopback scripts cannot make: local service
# discovery (BEP 14) between machines, and a download over a real IPv6 address. Run `serve` on one machine and
# `fetch` on another.
#
#   machine A:  scripts/interop-lan.sh serve
#               (it makes an 8 MiB file and a torrent with no tracker, prints where the torrent is, and seeds it)
#   copy the .torrent to machine B, then on B:
#   machine B:  scripts/interop-lan.sh fetch /path/to/lan-test.torrent           # found through local discovery alone
#               scripts/interop-lan.sh fetch /path/to/lan-test.torrent PEER      # a peer given as ADDRESS:PORT or [IPv6]:PORT
#
# The second form is for an IPv6 check: give machine A's global or unique-local IPv6 address and the port `serve`
# printed (link-local addresses need a scope id, which is not supported). Nothing leaves the local network, and no DHT,
# tracker or port mapping is used. Build first (`cargo build`, or set BIN to a release build's directory).
set -u
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
for bin in download create_torrent; do
    [ -x "$BIN/$bin" ] || { echo "lan: $BIN/$bin is not built"; exit 2; }
done
PORT=${PORT:-6881}

case "${1:-}" in
serve)
    DIR=$(mktemp -d /tmp/btlan.XXXXXX)
    trap 'rm -rf "$DIR"' EXIT
    python3 -c "import os; open('$DIR/lan-test.bin', 'wb').write(os.urandom(8 * 1024 * 1024))"
    "$BIN/create_torrent" "$DIR/lan-test.bin" --out "$DIR/lan-test.torrent" --piece-length 256K --no-date --quiet
    echo "lan: seeding on port $PORT. Copy this torrent to the other machine:"
    echo "       $DIR/lan-test.torrent"
    echo "lan: this machine's addresses: $(ifconfig 2>/dev/null | awk '/inet6? / && !/127.0.0.1|::1 |fe80/ {print $2}' | tr '\n' ' ')"
    echo "lan: press Ctrl-C to stop"
    "$BIN/download" "$DIR/lan-test.torrent" --out "$DIR" --no-dht --no-portmap --no-tui --no-config --no-log --seed --ipv6 --port "$PORT"
    ;;
fetch)
    TORRENT=${2:?usage: interop-lan.sh fetch FILE.torrent [PEER]}
    OUT=$(mktemp -d /tmp/btlan.XXXXXX)
    trap 'rm -rf "$OUT"' EXIT
    SOURCE=$TORRENT
    if [ -n "${3:-}" ]; then
        HASH=$("$BIN/infohash" "$TORRENT" 2>/dev/null | awk '/info_hash/ {print $2}')
        [ -n "$HASH" ] || { echo "lan: build the infohash helper too (cargo build)"; exit 2; }
        SOURCE="magnet:?xt=urn:btih:$HASH&x.pe=$3"
        echo "lan: fetching from the given peer $3 (no discovery)"
    else
        echo "lan: fetching with local discovery alone -- machine A must be seeding on this network"
    fi
    if timeout 180 "$BIN/download" "$SOURCE" --out "$OUT" --no-dht --no-portmap --no-tui --no-config --no-log --ipv6 --port "$PORT"; then
        echo "lan: PASS -- the whole file arrived and every piece checked out"
    else
        echo "lan: FAIL -- it did not arrive (is machine A seeding, and are multicast/the port allowed between the machines?)"
        exit 1
    fi
    ;;
*)
    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
