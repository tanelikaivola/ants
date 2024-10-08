mod arp_listener;
mod virtual_interface;
mod tcp_listener;

fn main() {
    virtual_interface::create_macvlan_interface("eth0", "macvlan0", "192.168.42.42");
    //arp_listener::listen_arp();
    tcp_listener::start_tcp_listener();
}