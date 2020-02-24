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
            print_packet(p.data);
            index += 1;
        }
    }
}

fn print_packet(pdata: &[u8]) {
    // a function that handles packet printing process
    let ethp:String = eth_protocol(pdata);
    println!("Protocol inside eth:{}", ethp);
    if ethp == "ipv4" {
        ipv4_fields(&pdata[16..]);
    }
    println!("data:{:?}", pdata);
}

fn eth_protocol(data: &[u8]) -> String {
    // analyze ethernet packet content
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
    // analyze ipv4-packet content

    // println!("IP header len:{:x?}", &data[0]);
    println!("IP Protocol: {}", &data[9]);
    println!("source: {}", list_2_ip(&data[12..16]));
    println!("destination: {}", list_2_ip(&data[16..20]));
}

fn list_2_ip(iparray: &[u8]) -> String {
    // generate ip-address type string from array of u8

    let mut ipstr = String::from("");

    for num in iparray {
        ipstr.push_str(&num.to_string());
        ipstr.push('.');
    }

    // remove last unnecessary dot
    ipstr.pop();

    ipstr
}
