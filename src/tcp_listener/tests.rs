use super::*;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};

#[test]
fn test_create_syn_ack_packet_ethernet_header() {
    let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    let dst_mac = MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB);
    let src_ip = Ipv4Addr::new(192, 168, 0, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 0, 2);
    let src_port = 12345;
    let dst_port = 80;
    let received_seq_num = 42;

    let packet = create_syn_ack_packet(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        received_seq_num,
    );

    let eth_packet = EthernetPacket::new(&packet).unwrap();
    assert_eq!(eth_packet.get_source(), src_mac);
    assert_eq!(eth_packet.get_destination(), dst_mac);
    assert_eq!(eth_packet.get_ethertype(), EtherTypes::Ipv4);
}

#[test]
fn test_create_syn_ack_packet_ipv4_header() {
    let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    let dst_mac = MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB);
    let src_ip = Ipv4Addr::new(192, 168, 0, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 0, 2);
    let src_port = 12345;
    let dst_port = 80;
    let received_seq_num = 42;

    let packet = create_syn_ack_packet(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        received_seq_num,
    );

    let ipv4_packet = Ipv4Packet::new(&packet[14..34]).unwrap();
    assert_eq!(ipv4_packet.get_source(), src_ip);
    assert_eq!(ipv4_packet.get_destination(), dst_ip);
    assert_eq!(ipv4_packet.get_version(), 4);
    assert_eq!(ipv4_packet.get_header_length(), 5);
    assert_eq!(ipv4_packet.get_total_length(), 40);
    assert_eq!(ipv4_packet.get_ttl(), 64);
    assert_eq!(
        ipv4_packet.get_next_level_protocol(),
        pnet::packet::ip::IpNextHeaderProtocols::Tcp
    );
}

#[test]
fn test_create_syn_ack_packet_tcp_header() {
    let src_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
    let dst_mac = MacAddr::new(0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB);
    let src_ip = Ipv4Addr::new(192, 168, 0, 1);
    let dst_ip = Ipv4Addr::new(192, 168, 0, 2);
    let src_port = 12345;
    let dst_port = 80;
    let received_seq_num = 42;

    let packet = create_syn_ack_packet(
        src_mac,
        dst_mac,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        received_seq_num,
    );

    let tcp_packet = TcpPacket::new(&packet[34..54]).unwrap();
    assert_eq!(tcp_packet.get_source(), src_port);
    assert_eq!(tcp_packet.get_destination(), dst_port);
    assert_eq!(tcp_packet.get_sequence(), 1);
    assert_eq!(tcp_packet.get_acknowledgement(), received_seq_num + 1);
    assert_eq!(tcp_packet.get_data_offset(), 5);
    assert_eq!(tcp_packet.get_flags(), TcpFlags::SYN | TcpFlags::ACK);
    assert_eq!(tcp_packet.get_window(), 1024);
}

fn create_mock_tcp_syn_packet() -> Vec<u8> {
    let mut packet = vec![0u8; 54];
    // Set Ethernet type to IPv4 (0x0800)
    packet[12] = 0x08;
    packet[13] = 0x00;
    // Set IPv4 protocol to TCP (6)
    packet[23] = 0x06;
    // Set TCP flags to SYN
    packet[34 + 13] = 0b0000_0010;
    packet
}

fn create_mock_tcp_syn_ack_packet() -> Vec<u8> {
    let mut packet = create_mock_tcp_syn_packet();
    // Set TCP flags to SYN-ACK
    packet[34 + 13] = 0b0001_0010;
    packet
}

fn create_non_tcp_packet() -> Vec<u8> {
    let mut packet = create_mock_tcp_syn_packet();
    // Set IPv4 protocol to something other than TCP
    packet[23] = 0x11;
    packet
}

fn create_non_ipv4_packet() -> Vec<u8> {
    let mut packet = create_mock_tcp_syn_packet();
    // Set Ethernet type to something other than IPv4
    packet[12] = 0x08;
    packet[13] = 0x06;
    packet
}

#[test]
fn test_validate_tcp_syn_packet_valid_syn() {
    let packet = create_mock_tcp_syn_packet();
    assert!(validate_tcp_syn_packet(&packet));
}

#[test]
fn test_validate_tcp_syn_packet_valid_syn_ack() {
    let packet = create_mock_tcp_syn_ack_packet();
    assert!(!validate_tcp_syn_packet(&packet));
}

#[test]
fn test_validate_tcp_syn_packet_non_tcp() {
    let packet = create_non_tcp_packet();
    assert!(!validate_tcp_syn_packet(&packet));
}

#[test]
fn test_validate_tcp_syn_packet_non_ipv4() {
    let packet = create_non_ipv4_packet();
    assert!(!validate_tcp_syn_packet(&packet));
}

#[test]
fn test_validate_tcp_syn_packet_too_small() {
    let packet = vec![0u8; 40]; // Smaller than the minimum packet size
    assert!(!validate_tcp_syn_packet(&packet));
}

#[test]
fn test_handle_packet_passive_mode() {
    let packet = vec![
        0, 0, 0, 0, 0, 0, // Padding (simulate irrelevant initial data)
        0, 0, 0, 0, 0, 0, // Ethernet header (destination MAC)
        1, 2, 3, 4, 5, 6, // Ethernet header (source MAC)
        0, 0, 0, 0, 0, 0, 0, 0, // Padding to IPv4 header
        192, 168, 0, 1, // Source IP
        192, 168, 0, 2, // Destination IP
        0, 80, // Source port (80)
        0, 42, // Destination port (443)
        0, 0, 0, 42, // Sequence number
    ];

    let result = handle_packet(&packet, "eth0", true);

    assert!(result.is_none());
}
