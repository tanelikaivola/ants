extern crate pnet_packet;
extern crate pnet_datalink;

use pnet_datalink::Channel::Ethernet;
use pnet_packet::Packet;
use pnet_packet::arp::{ArpPacket, ArpOperations};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};

pub fn listen_arp() {
    // Get the list of available network interfaces.
    let interfaces = pnet_datalink::interfaces();
    let interface_name = "eth0";
    let interface = interfaces.into_iter()
        .find(|iface| iface.name == interface_name)
        .expect(&format!("No such interface: {}", interface_name));

    // Create a channel to receive packets.
    let (_, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Error creating channel: {}", e),
    };

    println!("Listening for ARP requests on {}", interface.name);

    // Receive and process ARP packets.
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();

                // Check if the packet is an ARP packet
                if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                        match arp_packet.get_operation() {
                            ArpOperations::Request => {
                                println!(
                                    "ARP Request: {} is asking for {}",
                                    arp_packet.get_sender_proto_addr(),
                                    arp_packet.get_target_proto_addr()
                                );
                            }
                            ArpOperations::Reply => {
                                println!(
                                    "ARP Reply: {} is at {}",
                                    arp_packet.get_sender_proto_addr(),
                                    arp_packet.get_sender_hw_addr()
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => {
                println!("An error occurred while reading: {}", e);
            }
        }
    }
}
