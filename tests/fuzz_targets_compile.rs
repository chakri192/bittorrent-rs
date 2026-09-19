//! Compile-checks the bodies of the `cargo-fuzz` targets in `fuzz/`, from
//! outside the crate as the fuzz crate sees it, and runs each once.
//!
//! The fuzz crate needs a nightly toolchain to build, so `cargo test`
//! cannot build it. If a public path or a signature used by a target
//! changes, this fails on stable instead of in the nightly CI job.

#[test]
fn every_fuzz_target_body_compiles_and_survives_empty_and_garbage_input() {
    for data in [&b""[..], b"\xff\xff\xff\xff", b"d1:ad1:be", b"\x00\x00\x00\x05\x04\x00\x00\xff\xef"] {
        // bencode_decode
        let _ = bittorrent_rs::bencode::decode(data);
        // magnet_parse
        if let Ok(s) = std::str::from_utf8(data) {
            let _ = bittorrent_rs::magnet::parse_magnet_uri(s);
        }
        // torrent_parse
        let _ = bittorrent_rs::torrent::parse_torrent_file(data);
        // krpc_decode
        let _ = bittorrent_rs::dht::krpc::KrpcMessage::decode(data);
        let _ = bittorrent_rs::dht::krpc::parse_compact_nodes(data);
        // peer_message
        let mut reader = data;
        let _ = bittorrent_rs::peer::message::Message::read_from(&mut reader);
        // extension_handshake
        let _ = bittorrent_rs::peer::ExtendedHandshake::parse(data);
        // metadata_message
        let _ = bittorrent_rs::metadata::MetadataMessage::decode(data);
        // pex_parse
        let _ = bittorrent_rs::peer::pex::parse_ut_pex(data);
        let _ = bittorrent_rs::tracker::parse_compact_peers(data);
        let _ = bittorrent_rs::tracker::parse_compact_peers_v6(data);
    }
}
