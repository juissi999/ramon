use std::io;
use std::convert::TryFrom;
use std::thread;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::channel;

mod packet;
mod view;
mod structs;


fn main() {
    // create cross-threads mutex
    let packets = Arc::new(Mutex::new(vec![]));
    let packets_vector_clone = Arc::clone(&packets);

    // create signalling channel between threads
    let (signal_sender, signal_receiver) = channel::<u8>();

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

    // create thread for visualization
    thread::spawn(move || {
        let a = view::display(packets_vector_clone, signal_sender);
        match a {
            Ok(()) => {
                println!("Window was closed");
                // window_visible = false;
            }
            Err(error) => { println!("Error: {}", error);},
        }
    });


    packet::listen_and_print_packets(device_name, packets, signal_receiver);
}
