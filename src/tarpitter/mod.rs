use crate::{arp_listener, tcp_listener};

use std::sync::mpsc;

pub fn start_tarpitting(passive_mode: bool) {
    const INTERFACE_NAME: &str = "wlo1";

    let rx = arp_listener::start_arp_handling(INTERFACE_NAME, passive_mode);

    let (ip_sender, ip_receiver) = mpsc::channel();
    tcp_listener::start_tcp_tarpitting(INTERFACE_NAME, ip_receiver, passive_mode);

    for target_ip in rx {
        println!("Tarpitting IP: {}", target_ip);
        let _ = ip_sender.send(target_ip);
    }
}
