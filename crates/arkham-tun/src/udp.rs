//! UDP relay, outside smoltcp: DNS to the system resolver, QUIC dropped,
//! everything else relayed to its original destination.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::mpsc;

pub(super) const MAX_UDP_SESSIONS: usize = 1024;
const UDP_IDLE_SECS: u64 = 60;
const IP_PROTO_UDP: u8 = 17;

/// Guest-session key: (guest src, guest dst).
pub(super) type UdpKey = (SocketAddr, SocketAddr);

/// First `nameserver` in a resolv.conf text (port 53), else 1.1.1.1.
pub(super) fn upstream_dns(resolv_conf: &str) -> SocketAddr {
  for line in resolv_conf.lines() {
    let line = line.trim();
    let Some(rest) = line.strip_prefix("nameserver") else {
      continue;
    };
    // Require whitespace after the keyword (not `nameserverfoo`).
    if !rest.is_empty() && !rest.starts_with(char::is_whitespace) {
      continue;
    }
    if let Some(ip) = rest.split_whitespace().next()
      && let Ok(ip) = ip.parse::<IpAddr>()
    {
      return SocketAddr::new(ip, 53);
    }
  }
  SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53)
}

/// Build an IPv4+UDP packet. UDP checksum left zero (legal for IPv4).
pub(super) fn build_udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
  let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (src.ip(), dst.ip()) else {
    return None;
  };
  let udp_len = 8 + payload.len();
  let total_len = 20 + udp_len;
  let total = u16::try_from(total_len).ok()?;
  let udp = u16::try_from(udp_len).ok()?;
  let mut pkt = vec![0u8; total_len];
  pkt[0] = 0x45;
  pkt[2..4].copy_from_slice(&total.to_be_bytes());
  pkt[8] = 64;
  pkt[9] = IP_PROTO_UDP;
  pkt[12..16].copy_from_slice(&src_ip.octets());
  pkt[16..20].copy_from_slice(&dst_ip.octets());
  let csum = ipv4_checksum(&pkt[..20]);
  pkt[10..12].copy_from_slice(&csum.to_be_bytes());
  pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
  pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
  pkt[24..26].copy_from_slice(&udp.to_be_bytes());
  pkt[28..].copy_from_slice(payload);
  Some(pkt)
}

pub(super) fn ipv4_checksum(header: &[u8]) -> u16 {
  let mut sum: u32 = 0;
  let (chunks, remainder) = header.as_chunks::<2>();
  for pair in chunks {
    sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
  }
  if let Some(&last) = remainder.first() {
    sum += u32::from(last) << 8;
  }
  while sum >> 16 != 0 {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  !u16::try_from(sum).unwrap_or(u16::MAX)
}

fn bind_marked_udp(upstream: SocketAddr, fwmark: Option<u32>) -> std::io::Result<tokio::net::UdpSocket> {
  let domain = if upstream.is_ipv4() {
    socket2::Domain::IPV4
  } else {
    socket2::Domain::IPV6
  };
  let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
  if let Some(mark) = fwmark {
    socket.set_mark(mark)?;
  }
  let bind = if upstream.is_ipv4() {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
  } else {
    SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
  };
  socket.bind(&bind.into())?;
  socket.set_nonblocking(true)?;
  tokio::net::UdpSocket::from_std(socket.into())
}

/// One UDP session: queries in, upstream replies re-packetized to the guest.
/// Exits on idle timeout; the loop lazily drops the dead entry.
pub(super) async fn udp_session_task(
  device: Arc<tun::AsyncDevice>,
  upstream: SocketAddr,
  guest_src: SocketAddr,
  guest_dst: SocketAddr,
  mut queries: mpsc::Receiver<Vec<u8>>,
  fwmark: Option<u32>,
) {
  let socket = match bind_marked_udp(upstream, fwmark) {
    Ok(socket) => socket,
    Err(err) => {
      tracing::debug!(?err, "UDP socket failed");
      return;
    }
  };
  if socket.connect(upstream).await.is_err() {
    return;
  }
  let mut buf = vec![0u8; 65536];
  loop {
    let event = async {
      tokio::select! {
        query = queries.recv() => {
          let Some(query) = query else { return false };
          socket.send(&query).await.is_ok()
        }
        result = socket.recv(&mut buf) => {
          match result {
            Ok(n) => {
              // Response: original dst becomes the source.
              if let Some(pkt) = build_udp_packet(guest_dst, guest_src, &buf[..n]) {
                let _ = device.send(&pkt).await;
              }
              true
            }
            Err(_) => false,
          }
        }
      }
    };
    match tokio::time::timeout(std::time::Duration::from_secs(UDP_IDLE_SECS), event).await {
      Ok(true) => {}
      _ => break,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::classify::{IpPacket, classify_packet};

  fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
  }

  #[test]
  fn udp_packet_roundtrips_through_classify() {
    let src = v4([10, 98, 77, 1], 54321);
    let dst = v4([8, 8, 8, 8], 53);
    let payload = b"QUERY-123";
    let pkt = build_udp_packet(src, dst, payload).unwrap();
    // Header checksum validates (residue zero).
    assert_eq!(ipv4_checksum(&pkt[..20]), 0);
    assert_eq!(
      classify_packet(&pkt),
      IpPacket::Udp {
        src,
        dst,
        payload: payload.to_vec()
      }
    );
    assert!(build_udp_packet(v4([10, 0, 0, 1], 1), v4([10, 0, 0, 2], 2), &vec![0u8; 70000]).is_none());
  }

  #[test]
  fn resolv_conf_first_nameserver_wins() {
    assert_eq!(
      upstream_dns("# comment\nnameserver 9.9.9.9\nnameserver 1.1.1.1\n"),
      v4([9, 9, 9, 9], 53)
    );
    assert_eq!(
      upstream_dns("nameserver 2001:4860:4860::8888\n"),
      SocketAddr::new("2001:4860:4860::8888".parse().unwrap(), 53)
    );
    // Garbage / missing → fallback.
    assert_eq!(upstream_dns(""), v4([1, 1, 1, 1], 53));
    assert_eq!(upstream_dns("# only comments\n"), v4([1, 1, 1, 1], 53));
    assert_eq!(upstream_dns("nameserverbogus\n"), v4([1, 1, 1, 1], 53));
    assert_eq!(upstream_dns("nameserver not-an-ip\n"), v4([1, 1, 1, 1], 53));
  }
}
