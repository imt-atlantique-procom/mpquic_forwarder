RUST_LOG=info cargo run --bin quiche-server -- --listen 127.0.0.1:4433 --cert src/bin/cert.crt --key src/bin/cert.key --multipath --dgram-proto siduck --max-active-cids 4
