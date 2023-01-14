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

    // get the device with that indice
    if selection < network_interfaces.len() {
        let dn = String::from(&network_interfaces[selection as usize].name);
        let dn1: &str = &dn;

        println!("Choosing device {}, printing packets..", dn1);
        let mut cap = pcap::Capture::from_device(dn1).unwrap().open().unwrap(); //.open().unwrap();

        // print packets continously
        let mut index: u32 = 1;
        loop {
            // get a packet and print its bytes
            let p = cap.next().unwrap();
            println!("packet {}:", index);
            packet::print_packet(p);
            index += 1;
        }
    }
}
