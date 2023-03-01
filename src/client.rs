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
use crate::scheduler::*;

use std::cmp;
use std::collections::HashMap;
use std::convert::TryInto;
use std::net::ToSocketAddrs;

use std::io::Read;

use mio::net::TcpListener;
use mio::net::TcpStream;
use ring::rand::*;

use slab::Slab;

const MAX_BUF_SIZE: usize = 65536;
const MAX_DATAGRAM_SIZE: usize = 65536;
const MAX_PAYLOAD_FOR_QUICHE: usize = 16337 - FRAGMENTATION_HEADER_SIZE; // discovered by tests that 16337 is the max size that not generates 2 packets on the stream

const LISTEN_PORT: &str = "1111";

#[derive(Debug)]
pub enum ClientError {
    HandshakeFail,
    HttpFail,
    Other(String),
}

pub fn connect(args: ClientArgs, conn_args: CommonArgs) -> Result<(), ClientError> {
    let mut out = [0; MAX_DATAGRAM_SIZE];

    let sockets_amount = std::cmp::max(args.addrs.len(), 1);
    let mut sockets = Slab::with_capacity(sockets_amount);
    let mut src_addrs = HashMap::new();

    let tcp_accept_token = sockets_amount;
    let tcp_receive_token = tcp_accept_token + 1;

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

    // Create the UDP socket backing the QUIC connection, and register it with
    // the event loop. Either we provided addresses, or we rely on the default
    // INADDR_IN or IN6ADDR_ANY depending on the IP family of the
    // server address. This is needed on macOS and BSD variants that don't
    // support binding to IN6ADDR_ANY for both v4 and v6.
    let mut addrs = Vec::new();
    let local_addr = if args.addrs.is_empty() {
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let bind_addr = bind_addr.parse().unwrap();
        let socket = mio::net::UdpSocket::bind(bind_addr).unwrap();
        let local_addr = socket.local_addr().unwrap();
        let token = sockets.insert(socket);
        src_addrs.insert(local_addr, token);
        poll.registry()
            .register(
                &mut sockets[token],
                mio::Token(token),
                mio::Interest::READABLE,
            )
            .unwrap();
        local_addr
    } else {
        for src_addr in &args.addrs {
            let socket = mio::net::UdpSocket::bind(*src_addr).unwrap();
            let local_addr = socket.local_addr().unwrap();
            let token = sockets.insert(socket);
            src_addrs.insert(local_addr, token);
            addrs.push(local_addr);
            poll.registry()
                .register(
                    &mut sockets[token],
                    mio::Token(token),
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
        *addrs.first().unwrap()
    };

    // Create the configuration for the QUIC connection.
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    config.verify_peer(!args.no_verify);

    config
        .set_application_protos(&alpns::SIDUCK.to_vec())
        .unwrap();

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
    config.set_active_connection_id_limit(std::cmp::max(
        conn_args.max_active_cids,
        sockets_amount.try_into().unwrap(),
    ));
    config.set_multipath(conn_args.multipath);

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

    if conn_args.dgrams_enabled {
        config.enable_dgram(true, 1000, 1000);
    }

    let mut app_proto_selected = false;

    // Generate a random source connection ID for the connection.
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    let rng = SystemRandom::new();
    rng.fill(&mut scid[..]).unwrap();

    let scid = quiche::ConnectionId::from_ref(&scid);

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
        peer_addr, local_addr, scid,
    );

    let (write, send_info) = conn.send(&mut out).expect("initial send failed");
    let token = src_addrs[&send_info.from];

    while let Err(e) = sockets[token].send_to(&out[..write], send_info.to) {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            trace!(
                "{} -> {}: send() would block",
                sockets[token].local_addr().unwrap(),
                send_info.to
            );
            continue;
        }

        return Err(ClientError::Other(format!("send() failed: {:?}", e)));
    }

    trace!("written {}", write);

    let app_data_start = std::time::Instant::now();

    // Consider the first path as already probed, as we established the
    // connection over it.
    let mut probed_paths = 1;

    let mut scid_sent = false;
    let mut new_path_probed = false;
    let mut migrated = false;

    let mut buf = [0; MAX_BUF_SIZE];

    // TCP listener for incoming packets
    let listen_addr = &format!("127.0.0.1:{}", LISTEN_PORT);
    let mut listener = TcpListener::bind(listen_addr.parse().unwrap()).unwrap();
    let mut tcp_stream: Option<TcpStream> = None;
    let mut buf_tcp = [0; MAX_BUF_SIZE];
    let mut buf_quic = [0; MAX_BUF_SIZE + 1];

    loop {
        if !conn.is_in_early_data() || app_proto_selected {
            poll.poll(&mut events, conn.timeout()).unwrap();
        }

        // TODO check this
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
            let token = event.token().into();

            if token < sockets_amount {
                let socket = &sockets[token];
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
            } else if token == tcp_accept_token {
                // TCP accept
                let (mut stream, from) = listener.accept().unwrap();
                info!("TCP connected from {}", from);
                poll.registry()
                    .register(
                        &mut stream,
                        mio::Token(tcp_receive_token),
                        mio::Interest::READABLE,
                    )
                    .unwrap();
                tcp_stream = Some(stream);
            } else if token == tcp_receive_token {
                // TCP packet received
                // TODO read loop?
                let n = tcp_stream.as_mut().unwrap().read(&mut buf_tcp[..]).unwrap();

                if n > 0 {
                    info!("Received tcp packet with size {}", n);

                    if conn_args.dgrams_enabled {
                        // avoid BufferTooShortError
                        // TODO implement method to send larger datagrams (with len prepended)
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
                    } else {
                        // Avoid creating more than one quic packet
                        let max_possible_len =
                            cmp::min(conn.max_send_udp_payload_size(), MAX_PAYLOAD_FOR_QUICHE);
                        let mut sent = 0;
                        while sent < n {
                            let pending = n - sent;
                            let is_fragment = pending > max_possible_len; // if there is more to send than the max possible amount
                            info!("is fragment {}", is_fragment);
                            let amount_to_send_now = cmp::min(pending, max_possible_len);

                            buf_quic[FRAGMENTATION_HEADER_IS_FRAGMENT_OFFSET] = is_fragment as u8; // add header
                            buf_quic[FRAGMENTATION_HEADER_SIZE
                                ..FRAGMENTATION_HEADER_SIZE + amount_to_send_now]
                                .clone_from_slice(&buf_tcp[sent..sent + amount_to_send_now]); // copy payload

                            match conn.stream_send(
                                0,
                                &buf_quic[..amount_to_send_now + FRAGMENTATION_HEADER_SIZE],
                                false,
                            ) {
                                Ok(sent_now) => {
                                    info!(
                                        "Sent QUIC stream with size {} (full size {})",
                                        sent_now, n
                                    );
                                    sent += sent_now - FRAGMENTATION_HEADER_SIZE;
                                }

                                Err(e) => {
                                    error!("failed to send dgram {:?}", e);

                                    break;
                                }
                            }
                        }
                    }
                }
            } else {
                unreachable!("Unknown token")
            }
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
                    .register(
                        &mut listener,
                        mio::Token(tcp_accept_token),
                        mio::Interest::READABLE,
                    )
                    .unwrap();

                app_proto_selected = true;
            } else {
                unreachable!("App proto is not SIDUCK when it's the only option");
            }
        }

        // Handle path events.
        while let Some(qe) = conn.path_event_next() {
            match qe {
                quiche::PathEvent::New(..) => unreachable!(),

                quiche::PathEvent::Validated(local_addr, peer_addr) => {
                    info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                    if conn_args.multipath {
                        conn.set_active(local_addr, peer_addr, true).ok();
                    } else if args.perform_migration {
                        conn.migrate(local_addr, peer_addr).unwrap();
                        migrated = true;
                    }
                }

                quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                    info!("Path ({}, {}) failed validation", local_addr, peer_addr);
                }

                quiche::PathEvent::Closed(local_addr, peer_addr, e, reason) => {
                    info!(
                        "Path ({}, {}) is now closed and unusable; err = {}, reason = {:?}",
                        local_addr, peer_addr, e, reason
                    );
                }

                quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                    info!(
                        "Peer reused cid seq {} (initially {:?}) on {:?}",
                        cid_seq, old, new
                    );
                }

                quiche::PathEvent::PeerMigrated(..) => unreachable!(),

                quiche::PathEvent::PeerPathStatus(..) => {}
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

        if conn_args.multipath
            && probed_paths < addrs.len()
            && conn.available_dcids() > 0
            && conn.probe_path(addrs[probed_paths], peer_addr).is_ok()
        {
            probed_paths += 1;
        }

        if !conn_args.multipath
            && args.perform_migration
            && !new_path_probed
            && scid_sent
            && conn.available_dcids() > 0
        {
            let additional_local_addr = sockets[1].local_addr().unwrap();
            conn.probe_path(additional_local_addr, peer_addr).unwrap();

            new_path_probed = true;
        }

        // Determine in which order we are going to iterate over paths.
        let scheduled_tuples = round_robin_scheduler(&conn);

        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        for (local_addr, peer_addr) in scheduled_tuples {
            let token = src_addrs[&local_addr];
            let socket = &sockets[token];
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
