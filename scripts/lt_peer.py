#!/usr/bin/env python3
"""A libtorrent peer (the reference implementation of BitTorrent v2) for the interop scripts: it seeds or leeches one
torrent on loopback, with no DHT, no local discovery and no port mapping, and connects to the peers it is told of.

  lt_peer.py seed  TORRENT_OR_MAGNET SAVE_DIR LISTEN_PORT
  lt_peer.py leech TORRENT_OR_MAGNET SAVE_DIR LISTEN_PORT PEER_PORT [PEER_PORT...]   # exits 0 once it has it all
  lt_peer.py wait  TORRENT_OR_MAGNET SAVE_DIR LISTEN_PORT   # takes connections, makes none, exits 0 once it has it all

`wait` is for a peer that has only part of the torrent on disk and gets the rest from whoever connects to it.

LT_TRANSPORT=tcp|utp|both (default both) picks what it speaks; LT_ENCRYPTION=forced|plain picks whether it uses MSE.

Needs the libtorrent Python bindings (Homebrew: `brew install libtorrent-rasterbar`, then that formula's Python).
"""
import os, sys, time
import libtorrent as lt


# LT_ENCRYPTION=forced makes libtorrent speak only MSE (its `pe_forced`), plain makes it speak none, else either.
ENC = {"forced": 0, "plain": 2}.get(os.environ.get("LT_ENCRYPTION", ""), 1)


def session(port):
    settings = {
        "listen_interfaces": f"127.0.0.1:{port}",
        "enable_dht": False, "enable_lsd": False, "enable_upnp": False, "enable_natpmp": False,
        "enable_incoming_utp": os.environ.get("LT_TRANSPORT", "both") != "tcp", "enable_outgoing_utp": os.environ.get("LT_TRANSPORT", "both") != "tcp", "enable_incoming_tcp": os.environ.get("LT_TRANSPORT", "both") != "utp", "enable_outgoing_tcp": os.environ.get("LT_TRANSPORT", "both") != "utp",
        "allow_multiple_connections_per_ip": True, "alert_mask": lt.alert.category_t.error_notification | lt.alert.category_t.status_notification | lt.alert.category_t.peer_notification | lt.alert.category_t.connect_notification,
        "anonymous_mode": False, "out_enc_policy": ENC, "in_enc_policy": ENC, "allowed_enc_level": 3,
    }
    return lt.session(settings)


def add(ses, source, save_dir):
    if source.startswith("magnet:"):
        params = lt.parse_magnet_uri(source)
    else:
        params = lt.add_torrent_params()
        params.ti = lt.torrent_info(source)
    params.save_path = save_dir
    return ses.add_torrent(params)


def main():
    mode, source, save_dir, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
    peers = [int(p) for p in sys.argv[5:]]
    ses = session(port)
    handle = add(ses, source, save_dir)
    deadline = time.time() + 150
    connected = 0.0
    while time.time() < deadline:
        for alert in ses.pop_alerts():
            if isinstance(alert, (lt.torrent_error_alert, lt.file_error_alert, lt.peer_error_alert, lt.peer_disconnected_alert)):
                print("lt:", alert.message(), file=sys.stderr, flush=True)
        if mode in ("leech", "wait"):
            if mode == "leech" and time.time() - connected > 2:
                for p in peers:
                    try:
                        handle.connect_peer(("127.0.0.1", p))
                    except Exception as e:
                        print("connect_peer:", e, file=sys.stderr)
                connected = time.time()
            status = handle.status()
            if status.is_seeding or (status.state == lt.torrent_status.seeding):
                print("lt: complete")
                # LT_LINGER=N keeps a peer that has finished serving for N more seconds, for one that has not to finish from it.
                time.sleep(float(os.environ.get("LT_LINGER", "0")))
                return 0
        time.sleep(0.25)
    if mode in ("leech", "wait"):
        status = handle.status()
        print("lt: timed out at", status.progress, "state", status.state, file=sys.stderr)
        return 1
    return 0


sys.exit(main())
