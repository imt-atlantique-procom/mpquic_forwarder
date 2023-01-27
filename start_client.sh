RUST_LOG=info cargo run --bin quiche-client -- https://127.0.0.1:4433 --no-verify --dgram-proto siduck --multipath --address 127.0.0.1:8888 --address 127.0.0.1:9999
