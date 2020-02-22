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
        .expect("Please type an integer.");

    if selection < devindice {
        // let mut cap = &devices[selection as usize]; //.open().unwrap();
        let dn = String::from(&devices[selection as usize].name);
        let dn1: &str = &dn;
        println!("Choosing device {}", dn1);

        let mut cap = pcap::Capture::from_device(dn1).unwrap().open().unwrap(); //.open().unwrap();

        loop {
            // get a packet and print its bytes
            println!("{:?}", cap.next());
        }
    }
}
