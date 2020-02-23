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

    // read users device choise
    println!("Choose device (num) >");
    let mut selection = String::new();
    io::stdin().read_line(&mut selection)
        .expect("Failed to read line.");

    let selection: u32 = selection.trim().parse()
        .expect("Please type an integer.");

    // get the device with that indice
    if selection < devindice {
        let dn = String::from(&devices[selection as usize].name);
        let dn1: &str = &dn;

        println!("Choosing device {}", dn1);
        let mut cap = pcap::Capture::from_device(dn1).unwrap().open().unwrap(); //.open().unwrap();

        // print packets continously
        let mut index: u32 = 1;
        loop {
            // get a packet and print its bytes
            let p = cap.next().unwrap();
            println!("packet {}:", index);
            println!("{:?}\n{:?}", p.header, p.data);
            index += 1;
        }
    }
}
