/// Generate a ordered list of 4-tuples on which the host should send packets,
/// following a lowest-latency scheduling.
/// TODO use following interface when buffer is full as done by mptcp
pub fn lowest_latency_scheduler(
    conn: &quiche::Connection,
) -> impl Iterator<Item = (std::net::SocketAddr, std::net::SocketAddr)> {
    use itertools::Itertools;
    conn.path_stats()
        .sorted_by_key(|p| p.rtt)
        .map(|p| (p.local_addr, p.peer_addr))
}

/// Generate a ordered list of 4-tuples on which the host should send packets,
/// following a random scheduling.
pub fn random_scheduler(
    conn: &quiche::Connection,
) -> impl Iterator<Item = (std::net::SocketAddr, std::net::SocketAddr)> {
    use rand::seq::SliceRandom;
    use rand::thread_rng;

    let mut paths = conn.path_stats().collect::<Vec<quiche::PathStats>>();
    paths.shuffle(&mut thread_rng());
    paths.into_iter().map(|p| (p.local_addr, p.peer_addr))
}

/// Generate a ordered list of 4-tuples on which the host should send packets,
/// following a round robin scheduling.
pub fn round_robin_scheduler(
    conn: &quiche::Connection,
) -> impl Iterator<Item = (std::net::SocketAddr, std::net::SocketAddr)> {
    use itertools::Itertools;
    conn.path_stats()
        .sorted_by_key(|p| p.local_addr)
        .map(|p| (p.local_addr, p.peer_addr))
}
