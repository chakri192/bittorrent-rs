#!/usr/bin/env python3
"""Writes a copy of a v2 .torrent file without its `piece layers`: the torrent as a magnet link would give it, whose layers
a client has to ask peers for (BEP 52 hash requests). Usage: strip_layers.py IN.torrent OUT.torrent"""
import sys
import libtorrent as lt
meta = lt.bdecode(open(sys.argv[1], 'rb').read())
meta.pop(b'piece layers', None)
open(sys.argv[2], 'wb').write(lt.bencode(meta))
