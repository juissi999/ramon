use pcap::Device;
use std::io;

fn main() {
    // list all devices
    let devices = Device::list().unwrap();

    let mut devindice = 0;

    for device in &devices {
        println!("Device {} {:?}", devindice, device.name);
        devindice+=1;
    }

    println!("Choose device (num) >");
    let mut selection = String::new();
    io::stdin().read_line(&mut selection)
        .expect("Failed to read line.");

    let selection: u32 = selection.trim().parse()
        .expect("Please type a number.");

    if 0 < selection && selection < devindice {
        println!("Choosing device {}", devices[selection as usize].name);
        let mut cap = pcap::Device::lookup().unwrap().open().unwrap();

        loop {
            // get a packet and print its bytes
            println!("{:?}", cap.next());
        }
    }
}
