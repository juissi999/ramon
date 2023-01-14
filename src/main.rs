use std::io;
use std::convert::TryFrom;

mod packet;

fn main() {
    let network_interfaces = pcap::Device::list().unwrap();
    packet::print_network_interfaces_list(&network_interfaces);

    println!("Select network interface to listen (num) >");
    let mut selection = String::new();
    io::stdin().read_line(&mut selection)
        .expect("Failed to read line.");

    let selection_raw: u32 = selection.trim().parse()
        .expect("Please type an integer.");

    let selection: usize = usize::try_from(selection_raw).unwrap();

    if network_interfaces.len() < selection {
        panic!("Selected device does not exist.");
    }

    // get the device from device list according to index
    let device = &network_interfaces[selection];
    let device_name: &str = &device.name;

    println!("Choosing device {}, printing packets..", device_name);
    let capture = pcap::Capture::from_device(device_name).unwrap().open().unwrap();

    packet::listen_and_print_packets(capture);
}
