//! IPv4 packet classification for TUN ingress (pure, testable).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub(crate) const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;

/// Classified IPv4 packet. Anything else (v6, fragments, ICMP, ...) is `Other`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IpPacket {
  Tcp {
    src: SocketAddr,
    dst: SocketAddr,
    syn: bool,
  },
  Udp {
    src: SocketAddr,
    dst: SocketAddr,
    payload: Vec<u8>,
  },
  Other,
}

/// Parse one TUN packet. Manual header walk: version 4, no fragments,
/// TCP or UDP with complete headers; everything else is `Other`.
pub(crate) fn classify_packet(packet: &[u8]) -> IpPacket {
  if packet.len() < 20 || packet[0] >> 4 != 4 {
    return IpPacket::Other;
  }
  let ihl = (packet[0] & 0x0f) as usize * 4;
  if ihl < 20 || packet.len() < ihl {
    return IpPacket::Other;
  }
  let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
  if packet.len() < total_len || total_len < ihl {
    return IpPacket::Other;
  }
  let flags_frag = u16::from_be_bytes([packet[6], packet[7]]);
  if flags_frag & 0x1fff != 0 || flags_frag & 0x2000 != 0 {
    return IpPacket::Other; // fragments: no reassembly, drop
  }
  let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
  let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
  let payload = &packet[ihl..total_len];
  match packet[9] {
    IP_PROTO_TCP => {
      if payload.len() < 20 {
        return IpPacket::Other;
      }
      let src = SocketAddr::new(IpAddr::V4(src_ip), u16::from_be_bytes([payload[0], payload[1]]));
      let dst = SocketAddr::new(IpAddr::V4(dst_ip), u16::from_be_bytes([payload[2], payload[3]]));
      IpPacket::Tcp {
        src,
        dst,
        // SYN without ACK only: SYN+ACKs are kernel-listener replies, not new guest sockets.
        syn: payload[13] & 0x02 != 0 && payload[13] & 0x10 == 0,
      }
    }
    IP_PROTO_UDP => {
      if payload.len() < 8 {
        return IpPacket::Other;
      }
      let src = SocketAddr::new(IpAddr::V4(src_ip), u16::from_be_bytes([payload[0], payload[1]]));
      let dst = SocketAddr::new(IpAddr::V4(dst_ip), u16::from_be_bytes([payload[2], payload[3]]));
      IpPacket::Udp {
        src,
        dst,
        payload: payload[8..].to_vec(),
      }
    }
    _ => IpPacket::Other,
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn tcp_packet(src: SocketAddr, dst: SocketAddr, syn: bool) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = IP_PROTO_TCP;
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
      panic!("v4 only");
    };
    pkt[12..16].copy_from_slice(&s.octets());
    pkt[16..20].copy_from_slice(&d.octets());
    pkt[20..22].copy_from_slice(&src.port().to_be_bytes());
    pkt[22..24].copy_from_slice(&dst.port().to_be_bytes());
    pkt[33] = if syn { 0x02 } else { 0x10 };
    pkt
  }

  fn v4(ip: [u8; 4], port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
  }

  #[test]
  fn classify_tcp_syn_and_data() {
    let src = v4([10, 0, 0, 2], 12345);
    let dst = v4([140, 82, 121, 6], 443);
    assert_eq!(classify_packet(&tcp_packet(src, dst, true)), IpPacket::Tcp { src, dst, syn: true });
    assert_eq!(
      classify_packet(&tcp_packet(src, dst, false)),
      IpPacket::Tcp { src, dst, syn: false }
    );
    // SYN+ACK is a kernel-listener reply, not a new guest socket.
    let mut syn_ack = tcp_packet(src, dst, true);
    syn_ack[33] = 0x12;
    assert_eq!(classify_packet(&syn_ack), IpPacket::Tcp { src, dst, syn: false });
  }

  #[test]
  fn classify_rejects_fragments_v6_and_garbage() {
    let src = v4([10, 0, 0, 2], 12345);
    let dst = v4([140, 82, 121, 6], 443);
    let mut frag = tcp_packet(src, dst, true);
    frag[6] = 0x20; // more-fragments
    assert_eq!(classify_packet(&frag), IpPacket::Other);
    let mut frag = tcp_packet(src, dst, true);
    frag[6] = 0x00;
    frag[7] = 0x08; // nonzero offset
    assert_eq!(classify_packet(&frag), IpPacket::Other);
    assert_eq!(classify_packet(&[0x60, 0, 0, 0, 0, 0, 0, 0]), IpPacket::Other); // v6
    assert_eq!(classify_packet(b"short"), IpPacket::Other);
    assert_eq!(classify_packet(&[0x45; 10]), IpPacket::Other);
    let mut icmp = tcp_packet(src, dst, true);
    icmp[9] = 1;
    assert_eq!(classify_packet(&icmp), IpPacket::Other);
  }
}
