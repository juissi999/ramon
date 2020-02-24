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

        println!("Choosing device {}, printing packets..", dn1);
        let mut cap = pcap::Capture::from_device(dn1).unwrap().open().unwrap(); //.open().unwrap();

        // print packets continously
        let mut index: u32 = 1;
        loop {
            // get a packet and print its bytes
            let p = cap.next().unwrap();
            println!("packet {}:", index);
            println!("Eth protocol:{}", eth_protocol(p.data));
            ipv4_fields(&p.data[16..]);
            println!("data:{:?}", p.data);
            index += 1;
        }
    }
}

fn eth_protocol(data: &[u8]) -> String {
    println!("{}", data[14]);

    if data[14]==0x08 && data[15]==0x00 {
        String::from("ipv4")
    } else if data[14]==0x08 && data[15]==0x06 {
        String::from("ARP")
    } else if data[14]==0x86 && data[15]==0xdd {
        String::from("ipv6")
    } else {
        String::from("unknown")
    }
}

fn ipv4_fields(data: &[u8]) {
    println!("IP Protocol: {}", &data[9]);
    println!("source: {:?}", &data[12..16]);
    println!("destination: {:?}", &data[16..20]);
}