# Fuzz tests

Fuzz tests for the parts of the client that read data from the network or from files.

Needs nightly Rust and `cargo-fuzz`:

```sh
rustup install nightly
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run bencode_decode
```

Available targets:

`bencode_decode`, `torrent_parse`, `magnet_parse`, `krpc_decode`, `peer_message`, `extension_handshake`, `metadata_message`, `pex_parse`, `lsd_announcement`, `utp_packet`, `control_request`, `state_entries`, `flat_json`

If a crash is found, the input that caused it is saved in `fuzz/artifacts/<target>/`.
