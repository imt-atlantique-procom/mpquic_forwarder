RUST_LOG=info cargo run --bin quiche-server -- --cert src/bin/cert.crt --key src/bin/cert.key --multipath --dgram-proto siduck --max-active-cids 4
