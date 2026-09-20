#!/usr/bin/env python3
"""Writes a hybrid (v1 + v2) .torrent file for a directory, made by libtorrent, which pads the files with `.pad/N` filler files
(BEP 47) so that each begins on a piece boundary. Usage: mk_hybrid.py DIRECTORY OUT.torrent [PIECE_LENGTH]"""
import os, sys, warnings
import libtorrent as lt

warnings.simplefilter("ignore")
directory, out = os.path.abspath(sys.argv[1]), sys.argv[2]
piece_length = int(sys.argv[3]) if len(sys.argv) > 3 else 65536
storage = lt.file_storage()
lt.add_files(storage, directory)
torrent = lt.create_torrent(storage, piece_size=piece_length)
lt.set_piece_hashes(torrent, os.path.dirname(directory))
meta = torrent.generate()
padding = [f for f in meta[b"info"][b"files"] if b"p" in f.get(b"attr", b"")]
assert padding, "libtorrent made no padding files; the directory's files may all be aligned already"
open(out, "wb").write(lt.bencode(meta))
