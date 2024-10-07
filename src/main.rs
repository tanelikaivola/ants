mod arp_listener;
mod virtual_interface;

fn main() {
    virtual_interface::create_macvlan_interface("eth0", "macvlan0", "192.168.42.42");
    arp_listener::listen_arp();
    
}
