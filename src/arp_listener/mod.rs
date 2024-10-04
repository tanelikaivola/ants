extern crate pnet_packet;
extern crate pnet_datalink;
extern crate pnet_base;

use pnet_datalink::Channel::Ethernet;
use pnet_packet::Packet;
use pnet_packet::arp::{ArpPacket, ArpOperations};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Function to log ARP replies to a file
fn log_reply(target_ip: IpAddr) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open("replies.txt")?;

    writeln!(file, "ARP Reply to {}", target_ip)?;
    Ok(())
}

/// Function to reply to an ARP request and log the reply
fn reply(target_ip: IpAddr) {
    // Log the reply indication to the console
    println!("Sending ARP reply for IP address: {}", target_ip);
    
    // Log the reply to the file
    if let Err(e) = log_reply(target_ip) {
        eprintln!("Failed to log reply: {}", e);
    }

    // In a real implementation, you would send the ARP reply packet here
}

pub fn listen_arp() {
    // Get the list of available network interfaces.
    let interfaces = pnet_datalink::interfaces();
    let interface_name = "wlo1";
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

    // A map to track ARP request counts for each target IP address
    let mut arp_request_count: HashMap<IpAddr, (u32, Instant)> = HashMap::new();
    let request_threshold: u32 = 2;
    let request_timeout = Duration::from_secs(5);

    // Receive and process ARP packets.
    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();

                // Check if the packet is an ARP packet
                if ethernet_packet.get_ethertype() == EtherTypes::Arp {
                    if let Some(arp_packet) = ArpPacket::new(ethernet_packet.payload()) {
                        let target_ip = IpAddr::V4(arp_packet.get_target_proto_addr());
                        let sender_ip = IpAddr::V4(arp_packet.get_sender_proto_addr());
                        let sender_hw = arp_packet.get_sender_hw_addr();

                        match arp_packet.get_operation() {
                            ArpOperations::Request => {
                                println!(
                                    "ARP Request: {} is asking for {}",
                                    sender_ip,
                                    target_ip
                                );

                                // Track ARP requests to target IP
                                let now = Instant::now();
                                let entry = arp_request_count.entry(target_ip).or_insert((0, now));

                                // If the entry is older than the timeout, reset the count
                                if now.duration_since(entry.1) > request_timeout {
                                    entry.0 = 0;
                                    entry.1 = now;
                                }

                                // Increment the request count
                                entry.0 += 1;

                                // Check if request count exceeds threshold
                                if entry.0 >= request_threshold {
                                    println!("Detected {} unanswered ARP requests for {}", request_threshold, target_ip);
                                    reply(target_ip); // Use the underlying array from MacAddr directly
                                    entry.0 = 0; // Reset the request count after logging
                                }
                            }
                            ArpOperations::Reply => {
                                println!(
                                    "ARP Reply: {} is at {:?}",
                                    sender_ip,
                                    sender_hw
                                );

                                // If we receive a reply, reset the count for the target IP
                                arp_request_count.remove(&sender_ip);
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
