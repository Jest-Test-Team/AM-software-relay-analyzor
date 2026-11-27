//! "Light active" ARP-cache refresh: send one tiny UDP datagram to the discard
//! port (9) of every host in the local subnet. The kernel must ARP-resolve
//! each target first, which populates the neighbour table that `arp` reads.
//! No port scanning, no root, nothing is expected back.

use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::time::Duration;

pub struct SweepReport {
    pub sent: usize,
    pub errors: usize,
}

/// `pace` is the delay between packets (rate limit), e.g. 4ms ≈ 250 pkt/s.
pub fn udp_sweep(targets: &[Ipv4Addr], pace: Duration) -> std::io::Result<SweepReport> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    let mut rep = SweepReport { sent: 0, errors: 0 };
    for ip in targets {
        match sock.send_to(&[0u8], SocketAddrV4::new(*ip, 9)) {
            Ok(_) => rep.sent += 1,
            // EHOSTDOWN etc. for hosts that never answered ARP last time — expected.
            Err(_) => rep.errors += 1,
        }
        std::thread::sleep(pace);
    }
    // Give outstanding ARP requests time to resolve before the table is read.
    std::thread::sleep(Duration::from_millis(1500));
    Ok(rep)
}
