use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use pnet::util::{checksum, ipv4_checksum};
use pnet_base::MacAddr;
use pnet_packet::ethernet::MutableEthernetPacket;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// start listening to tcp and respond to TCP handshakes in the given interface
pub fn start_tcp_tarpitting(
    interface_name: &str,
    ip_receiver: mpsc::Receiver<Ipv4Addr>,
    passive_mode: bool,
) {
    let interface_name = interface_name.to_string();
    thread::spawn(move || {
        let device = pcap::Device::list()
            .unwrap()
            .into_iter()
            .find(|dev| dev.name == interface_name)
            .unwrap_or_else(|| {
                eprintln!("Could not find device {}", interface_name);
                std::process::exit(1);
            });

        let mut cap = pcap::Capture::from_device(device)
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap();

        println!(
            "Listening for incoming TCP SYN packets on interface {}...",
            interface_name
        );

        let ips_to_tarpit: Arc<Mutex<HashMap<Ipv4Addr, Instant>>> =
            Arc::new(Mutex::new(HashMap::new()));

        while let Ok(packet) = cap.next_packet() {
            while let Ok(ip) = ip_receiver.try_recv() {
                let mut ips = ips_to_tarpit.lock().unwrap();
                ips.insert(ip, Instant::now());
            }

            if validate_tcp_syn_packet(packet.data) {
                let dst_ip = Ipv4Addr::new(
                    packet.data[30],
                    packet.data[31],
                    packet.data[32],
                    packet.data[33],
                );

                {
                    let ips = ips_to_tarpit.lock().unwrap();
                    if !ips.contains_key(&dst_ip) {
                        continue;
                    }
                }

                let packet_data = packet.data.to_vec();
                let interface_name = interface_name.to_string();
                let passive_mode = passive_mode;
                let ips_to_tarpit_clone = Arc::clone(&ips_to_tarpit);

                thread::spawn(move || {
                    if let Some(response_ip) =
                        handle_packet(&packet_data, &interface_name, passive_mode)
                    {
                        if response_ip == dst_ip {
                            let mut ips = ips_to_tarpit_clone.lock().unwrap();
                            ips.insert(dst_ip, Instant::now());
                            println!("Response sent for IP: {}", dst_ip);
                        }
                    }
                });
            }

            {
                let mut ips = ips_to_tarpit.lock().unwrap();
                ips.retain(|_, &mut last_time| last_time.elapsed() < Duration::from_secs(120));
            }
        }
    });
}

fn validate_tcp_syn_packet(packet_data: &[u8]) -> bool {
    // Minimum packet size: Ethernet (14 bytes) + IPv4 (20 bytes) + TCP (20 bytes)
    if packet_data.len() < 54 {
        return false;
    }

    let ethertype = u16::from_be_bytes([packet_data[12], packet_data[13]]);
    if ethertype != 0x0800 {
        return false; // Not an IPv4 packet
    }

    let protocol = packet_data[23];
    if protocol != 6 {
        return false; // Not a TCP packet
    }

    let tcp_offset = 34; // Ethernet (14 bytes) + IPv4 (20 bytes, no options)
    let tcp_flags = packet_data[tcp_offset + 13];

    let syn_flag = tcp_flags & 0b0000_0010 != 0;
    let ack_flag = tcp_flags & 0b0001_0000 != 0;

    syn_flag && !ack_flag
}

fn send_syn_ack(
    interface_name: &str,
    dst_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    received_seq_num: u32,
) {
    let interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Could not find the specified interface");

    let mut eth_buffer = [0u8; 60]; // Ethernet header + IP + TCP

    let mut ethernet_packet = MutableEthernetPacket::new(&mut eth_buffer[..]).unwrap();
    ethernet_packet.set_source(interface.mac.unwrap());
    ethernet_packet.set_destination(dst_mac);
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherType(0x0800));

    {
        let ipv4_buffer = &mut eth_buffer[14..34];
        let mut ipv4_packet = MutableIpv4Packet::new(ipv4_buffer).unwrap();

        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((20 + 20) as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4_packet.set_source(src_ip);
        ipv4_packet.set_destination(dst_ip);
        ipv4_packet.set_checksum(0);

        let ipv4_checksum = checksum(ipv4_packet.packet(), 10);
        ipv4_packet.set_checksum(ipv4_checksum);
    }

    {
        let tcp_buffer = &mut eth_buffer[34..54];
        let mut tcp_packet = MutableTcpPacket::new(tcp_buffer).unwrap();

        tcp_packet.set_sequence(1);
        tcp_packet.set_acknowledgement(received_seq_num + 1);

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN | TcpFlags::ACK);
        tcp_packet.set_window(1024);
        tcp_packet.set_checksum(0);

        let tcp_checksum = ipv4_checksum(
            tcp_packet.packet(),
            28,
            &[],
            &src_ip,
            &dst_ip,
            IpNextHeaderProtocols::Tcp,
        );
        tcp_packet.set_checksum(tcp_checksum);
    }

    match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(mut tx, _)) => {
            let _ = tx.send_to(&eth_buffer, None).unwrap();
            println!("Sent SYN/ACK packet");
        }
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Failed to send packet: {}", e),
    }
}

fn handle_packet(packet: &[u8], interface: &str, passive_mode: bool) -> Option<Ipv4Addr> {
    let src_ip = Ipv4Addr::new(packet[26], packet[27], packet[28], packet[29]);
    let dst_ip = Ipv4Addr::new(packet[30], packet[31], packet[32], packet[33]);

    let src_mac = MacAddr::new(
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
    );

    let src_port = u16::from_be_bytes([packet[34], packet[35]]);
    let dst_port = u16::from_be_bytes([packet[36], packet[37]]);
    let received_seq_num = u32::from_be_bytes([packet[38], packet[39], packet[40], packet[41]]);

    if !passive_mode {
        thread::sleep(Duration::from_millis(500));
        send_syn_ack(
            interface,
            src_mac,
            dst_ip,
            src_ip,
            dst_port,
            src_port,
            received_seq_num,
        );

        return Some(dst_ip);
    }

    None
}
