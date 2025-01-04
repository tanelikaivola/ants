use super::*;
use pnet::packet::arp::{ArpHardwareType, ArpOperation, ArpOperations, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

const ETH_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;
const TOTAL_PACKET_LEN: usize = ETH_HEADER_LEN + ARP_PACKET_LEN;

fn create_ethernet_with_arp(
    hw_type: ArpHardwareType,
    operation: ArpOperation,
    sender_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
) -> EthernetPacket<'static> {
    let mut packet_data = vec![0u8; TOTAL_PACKET_LEN];
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut packet_data).unwrap();
        eth_packet.set_ethertype(EtherTypes::Arp);
        let mut arp_packet = MutableArpPacket::new(&mut packet_data[ETH_HEADER_LEN..]).unwrap();
        arp_packet.set_hardware_type(hw_type);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(operation);
        arp_packet.set_sender_proto_addr(sender_ip);
        arp_packet.set_target_proto_addr(target_ip);
    }
    EthernetPacket::owned(packet_data).unwrap()
}

#[test]
fn test_process_arp_packet_request_below_threshold() {
    let ethernet_packet = create_ethernet_with_arp(
        ArpHardwareType(1),
        ArpOperations::Request,
        Ipv4Addr::new(192, 168, 0, 100),
        Ipv4Addr::new(192, 168, 0, 1),
    );

    let mut arp_request_count = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    let result = process_arp_packet(
        &ethernet_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(result.is_none());
    assert_eq!(
        arp_request_count[&(
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100))
        )]
            .0,
        1
    );
}

#[test]
fn test_process_arp_packet_request_exceed_threshold() {
    let ethernet_packet = create_ethernet_with_arp(
        ArpHardwareType(1),
        ArpOperations::Request,
        Ipv4Addr::new(192, 168, 0, 100),
        Ipv4Addr::new(192, 168, 0, 1),
    );

    let mut arp_request_count = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    // Simulate previous requests
    arp_request_count.insert(
        (
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
        ),
        (2, Instant::now()),
    );

    let result = process_arp_packet(
        &ethernet_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(result.is_some());
}

#[test]
fn test_process_arp_packet_reply() {
    let ethernet_packet = create_ethernet_with_arp(
        ArpHardwareType(1),
        ArpOperations::Reply,
        Ipv4Addr::new(192, 168, 0, 100),
        Ipv4Addr::new(192, 168, 0, 1),
    );

    let mut arp_request_count = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    // Simulate a tracked ARP request
    arp_request_count.insert(
        (
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
        ),
        (2, Instant::now()),
    );

    let result = process_arp_packet(
        &ethernet_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(result.is_none());
    assert!(arp_request_count.is_empty());
}

#[test]
fn test_process_arp_packet_invalid_hardware_type() {
    let ethernet_packet = create_ethernet_with_arp(
        ArpHardwareType(2), // Invalid hardware type
        ArpOperations::Request,
        Ipv4Addr::new(192, 168, 0, 100),
        Ipv4Addr::new(192, 168, 0, 1),
    );

    let mut arp_request_count = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    let result = process_arp_packet(
        &ethernet_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(result.is_none());
    assert!(arp_request_count.is_empty());
}

// Mock implementation of the ArpPacketTrait for testing
struct MockArpPacket {
    target_proto_addr: Ipv4Addr,
    sender_proto_addr: Ipv4Addr,
}

impl MockArpPacket {
    fn new(target_proto_addr: Ipv4Addr, sender_proto_addr: Ipv4Addr) -> Self {
        Self {
            target_proto_addr,
            sender_proto_addr,
        }
    }
}

impl ArpPacketTrait for MockArpPacket {
    fn get_target_proto_addr(&self) -> Ipv4Addr {
        self.target_proto_addr
    }

    fn get_sender_proto_addr(&self) -> Ipv4Addr {
        self.sender_proto_addr
    }
}

#[test]
fn test_track_arp_request_no_threshold_reached() {
    let mock_arp_packet = MockArpPacket::new(
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 0, 100),
    );

    let mut arp_request_count: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    let result = track_arp_request(
        &mock_arp_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(!result);
    assert_eq!(
        arp_request_count[&(
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100))
        )]
            .0,
        1
    );
}

#[test]
fn test_track_arp_request_threshold_reached() {
    let mock_arp_packet = MockArpPacket::new(
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 0, 100),
    );

    let mut arp_request_count: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    // Simulate previous requests
    arp_request_count.insert(
        (
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
        ),
        (2, Instant::now()),
    );

    let result = track_arp_request(
        &mock_arp_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(result);
    assert!(arp_request_count.is_empty());
}

#[test]
#[allow(clippy::unchecked_duration_subtraction)]
fn test_track_arp_request_timeout_resets_count() {
    let mock_arp_packet = MockArpPacket::new(
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(192, 168, 0, 100),
    );

    let mut arp_request_count: HashMap<(IpAddr, IpAddr), (u32, Instant)> = HashMap::new();
    let request_threshold = 3;
    let request_timeout = Duration::from_secs(10);

    arp_request_count.insert(
        (
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100)),
        ),
        (2, Instant::now() - Duration::from_secs(20)),
    );

    let result = track_arp_request(
        &mock_arp_packet,
        &mut arp_request_count,
        request_threshold,
        request_timeout,
    );

    assert!(!result);
    assert_eq!(
        arp_request_count[&(
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 100))
        )]
            .0,
        1
    );
}
