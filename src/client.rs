// Copyright (C) 2020, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use crate::args::*;
use crate::common::*;

use std::cmp;
use std::net::ToSocketAddrs;

use std::io::Read;

use mio::net::TcpListener;
use mio::net::TcpStream;
use ring::rand::*;

const MAX_BUF_SIZE: usize = 65536;
const MAX_DATAGRAM_SIZE: usize = 65536;

const LISTEN_PORT: &str = "1111";

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub fn connect(args: ClientArgs, conn_args: CommonArgs) -> Result<(), ClientError> {
    let mut out = [0; MAX_DATAGRAM_SIZE];

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    // We'll only connect to the first server provided in URL list.
    let connect_url = &args.urls[0];

    // Resolve server address.
    let peer_addr = if let Some(addr) = &args.connect_to {
        addr.parse().expect("--connect-to is expected to be a string containing an IPv4 or IPv6 address with a port. E.g. 192.0.2.0:443")
    } else {
        connect_url.to_socket_addrs().unwrap().next().unwrap()
    };

    // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let bind_addr = match peer_addr {
        std::net::SocketAddr::V4(_) => format!("0.0.0.0:{}", args.source_port),
        std::net::SocketAddr::V6(_) => format!("[::]:{}", args.source_port),
    };

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop.
    let mut socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
        .unwrap();

    let migrate_socket = if args.perform_migration {
        let mut socket = mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(1), mio::Interest::READABLE)
            .unwrap();

        Some(socket)
    } else {
        None
    };

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.verify_peer(!args.no_verify);

    config
        .set_application_protos(&alpns::SIDUCK.to_vec())
        .unwrap();
    config.enable_dgram(true, 1000, 1000);

    config.set_max_idle_timeout(conn_args.idle_timeout);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(conn_args.max_data);
    config.set_initial_max_stream_data_bidi_local(conn_args.max_stream_data);
    config.set_initial_max_stream_data_bidi_remote(conn_args.max_stream_data);
    config.set_initial_max_stream_data_uni(conn_args.max_stream_data);
    config.set_initial_max_streams_bidi(conn_args.max_streams_bidi);
    config.set_initial_max_streams_uni(conn_args.max_streams_uni);
    config.set_disable_active_migration(!conn_args.enable_active_migration);
    config.set_active_connection_id_limit(conn_args.max_active_cids);

    config.set_max_connection_window(conn_args.max_window);
    config.set_max_stream_window(conn_args.max_stream_window);

    let mut keylog = None;

    if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        keylog = Some(file);

        config.log_keys();
    }

    if conn_args.no_grease {
        config.grease(false);
    }

    if conn_args.early_data {
        config.enable_early_data();
    }

    config
        .set_cc_algorithm_name(&conn_args.cc_algorithm)
        .unwrap();

    if conn_args.disable_hystart {
        config.enable_hystart(false);
    }

    let mut app_proto_selected = false;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    let rng = SystemRandom::new();
    rng.fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

    let local_addr = socket.local_addr().unwrap();

    // Create a QUIC connection and initiate handshake.
    let mut conn = quiche::connect(
        connect_url.domain(),
        &scid,
        local_addr,
        peer_addr,
        &mut config,
    )
    .unwrap();

    if let Some(keylog) = &mut keylog {
        if let Ok(keylog) = keylog.try_clone() {
            conn.set_keylog(Box::new(keylog));
        }
    }

    // Only bother with qlog if the user specified it.
    #[cfg(feature = "qlog")]
    {
        if let Some(dir) = std::env::var_os("QLOGDIR") {
            let id = format!("{:?}", scid);
            let writer = make_qlog_writer(&dir, "client", &id);

            conn.set_qlog(
                std::boxed::Box::new(writer),
                "quiche-client qlog".to_string(),
                format!("{} id={}", "quiche-client qlog", id),
            );
        }
    }

    if let Some(session_file) = &args.session_file {
        if let Ok(session) = std::fs::read(session_file) {
            conn.set_session(&session).ok();
        }
    }

    info!(
        "connecting to {:} from {:} with scid {:?}",
        peer_addr,
        socket.local_addr().unwrap(),
        scid,
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");

    while let Err(e) = socket.send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!(
                "{} -> {}: send() would block",
                socket.local_addr().unwrap(),
                send_info.to
            );
            continue;
        }

        return Err(ClientError::Other(format!("send() failed: {:?}", e)));
    }

    trace!("written {}", write);

    let app_data_start = std::time::Instant::now();

    let mut scid_sent = false;
    let mut new_path_probed = false;
    let mut migrated = false;

    let mut buf = [0; MAX_BUF_SIZE];

    // TCP listener for incoming packets
    let listen_addr = &format!("127.0.0.1:{}", LISTEN_PORT);
    let mut listener = TcpListener::bind(listen_addr.parse().unwrap()).unwrap();
    let mut tcp_stream: Option<TcpStream> = None;
    let mut buf_tcp = [0; MAX_BUF_SIZE];

    loop {
        if !conn.is_in_early_data() || app_proto_selected {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        // If the event loop reported no events, it means that the timeout
        // has expired, so handle it without attempting to read packets. We
        // will then proceed with the send loop.
        // if events.is_empty() {
        //     trace!("timed out");

        //     conn.on_timeout();
        // }

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        for event in &events {
            match event.token() {
                mio::Token(0) => {
                    let local_addr = socket.local_addr().unwrap();
                    'read: loop {
                        let (len, from) = match socket.recv_from(&mut buf) {
                            Ok(v) => v,

                            Err(e) => {
                                // There are no more UDP packets to read on this socket.
                                // Process subsequent events.
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    trace!("{}: recv() would block", local_addr);
                                    break 'read;
                                }

                                return Err(ClientError::Other(format!(
                                    "{}: recv() failed: {:?}",
                                    local_addr, e
                                )));
                            }
                        };

                        trace!("{}: got {} bytes", local_addr, len);

                        let recv_info = quiche::RecvInfo {
                            to: local_addr,
                            from,
                        };

                        // Process potentially coalesced packets.
                        let read = match conn.recv(&mut buf[..len], recv_info) {
                            Ok(v) => v,

                            Err(e) => {
                                error!("{}: recv failed: {:?}", local_addr, e);
                                continue 'read;
                            }
                        };

                        trace!("{}: processed {} bytes", local_addr, read);
                    }
                }

                // TODO
                // mio::Token(1) => let socket = migrate_socket.as_ref().unwrap(),
                mio::Token(2) => {
                    // TCP accept
                    let (mut stream, from) = listener.accept().unwrap();
                    info!("TCP connected from {}", from);
                    poll.registry()
                        .register(&mut stream, mio::Token(3), mio::Interest::READABLE)
                        .unwrap();
                    tcp_stream = Some(stream);
                }

                mio::Token(3) => {
                    // TODO read loop
                    let n = tcp_stream.as_mut().unwrap().read(&mut buf_tcp[..]).unwrap();

                    if n > 0 {
                        info!("Received tcp packet with size {}", n);
                        // avoid BufferTooShortError
                        let min = cmp::min(n, conn.dgram_max_writable_len().unwrap());

                        info!(
                            "Sending QUIC DATAGRAM with size {} (original size {})",
                            min, n
                        );

                        match conn.dgram_send(&buf_tcp[..min]) {
                            Ok(v) => v,

                            Err(e) => {
                                error!("failed to send dgram {:?}", e);

                                break;
                            }
                        }
                    }
                }

                _ => unreachable!(),
            };
        }

        trace!("done reading");

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!("connection timed out after {:?}", app_data_start.elapsed(),);

                return Err(ClientError::HandshakeFail);
            } else {
                error!("connection timed out after {:?}", app_data_start.elapsed(),);
            }

            break;
        }

        // Create a new application protocol session once the QUIC connection is
        // established.
        if (conn.is_established() || conn.is_in_early_data())
            && (!args.perform_migration || migrated)
            && !app_proto_selected
        {
            let app_proto = conn.application_proto();

            if alpns::SIDUCK.contains(&app_proto) {
                info!("Listening TCP on {}", listen_addr);
                poll.registry()
                    .register(&mut listener, mio::Token(2), mio::Interest::READABLE)
                    .unwrap();

                app_proto_selected = true;
            } else {
                error!("App proto is not SIDUCK when it's the only option");
            }
        }

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let mut sockets = vec![&socket];
        if let Some(migrate_socket) = migrate_socket.as_ref() {
            sockets.push(migrate_socket);
        }

        for socket in sockets {
            let local_addr = socket.local_addr().unwrap();

            for peer_addr in conn.paths_iter(local_addr) {
                loop {
                    let (write, send_info) =
                        match conn.send_on_path(&mut out, Some(local_addr), Some(peer_addr)) {
                            Ok(v) => v,

                            Err(quiche::Error::Done) => {
                                trace!("{} -> {}: done writing", local_addr, peer_addr);
                                break;
                            }

                            Err(e) => {
                                error!("{} -> {}: send failed: {:?}", local_addr, peer_addr, e);

                                conn.close(false, 0x1, b"fail").ok();
                                break;
                            }
                        };

                    if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            trace!("{} -> {}: send() would block", local_addr, send_info.to);
                            break;
                        }

                        return Err(ClientError::Other(format!(
                            "{} -> {}: send() failed: {:?}",
                            local_addr, send_info.to, e
                        )));
                    }

                    info!("{} -> {}: written {}", local_addr, send_info.to, write);
                }
            }
        }

        // Handle path events.
        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(..) => unreachable!(),

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                    conn.migrate(local_addr, peer_addr).unwrap();
                    migrated = true;
                }

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!("Path ({}, {}) failed validation", local_addr, peer_addr);
                }

                quiche::PathEvent::Closed(local_addr, peer_addr) => {
                    info!(
                        "Path ({}, {}) is now closed and unusable",
                        local_addr, peer_addr
                    );
                }

                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    info!(
                        "Peer reused cid seq {} (initially {:?}) on {:?}",
                        cid_seq, old, new
                    );
                }

                quiche::PathEvent::PeerMigrated(..) => unreachable!(),
            }
        }

        // See whether source Connection IDs have been retired.
        while let Some(retired_scid) = conn.retired_scid_next() {
            info!("Retiring source CID {:?}", retired_scid);
        }

        // Provides as many CIDs as possible.
        while conn.source_cids_left() > 0 {
            let (scid, reset_token) = generate_cid_and_reset_token(&rng);

            if conn.new_source_cid(&scid, reset_token, false).is_err() {
                break;
            }

            scid_sent = true;
        }

        if args.perform_migration && !new_path_probed && scid_sent && conn.available_dcids() > 0 {
            let additional_local_addr = migrate_socket.as_ref().unwrap().local_addr().unwrap();
            conn.probe_path(additional_local_addr, peer_addr).unwrap();

            new_path_probed = true;
        }

        if conn.is_closed() {
            info!(
                "connection closed, {:?} {:?}",
                conn.stats(),
                conn.path_stats().collect::<Vec<quiche::PathStats>>()
            );

            if !conn.is_established() {
                error!("connection timed out after {:?}", app_data_start.elapsed(),);

                return Err(ClientError::HandshakeFail);
            }

            if let Some(session_file) = &args.session_file {
                if let Some(session) = conn.session() {
                    std::fs::write(session_file, session).ok();
                }
            }

            break;
        }
    }

    Ok(())
}
