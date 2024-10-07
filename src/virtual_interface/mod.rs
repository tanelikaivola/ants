extern crate nix;

use std::io;
use std::process::Command;

/// Helper function to run shell commands
fn run_command(command: &str, args: &[&str]) -> io::Result<()> {
    let output = Command::new(command)
        .args(args)
        .output()
        .expect("failed to execute process");

    if !output.status.success() {
        println!(
            "Command `{}` failed with error: {}",
            command,
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        println!("Command `{}` succeeded", command);
    }

    Ok(())
}


/// Function to create a MACVLAN interface and assign an IP address to it
pub fn create_macvlan_interface(physical_iface: &str, virtual_iface: &str, ip_address: &str) -> io::Result<()> {
    // Create a MACVLAN interface using `ip link add`
    run_command("ip", &["link", "add", "link", physical_iface, virtual_iface, "type", "macvlan", "mode", "bridge"])?;

    // Bring up the virtual interface
    run_command("ip", &["link", "set", virtual_iface, "up"])?;

    // Assign an IP address to the new MACVLAN interface
    run_command("ip", &["addr", "add", ip_address, "dev", virtual_iface])?;

    println!("MACVLAN interface {} created on {} with IP address {}", virtual_iface, physical_iface, ip_address);
    Ok(())
}


/// Function to remove a MACVLAN interface
pub fn remove_macvlan_interface(virtual_iface: &str) -> io::Result<()> {
    // Remove the MACVLAN interface using `ip` command
    run_command("ip", &["link", "delete", virtual_iface])?;

    println!("MACVLAN interface {} removed", virtual_iface);
    Ok(())
}
