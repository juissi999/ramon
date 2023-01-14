use pcap;

pub fn print_network_interfaces_list(network_interfaces: &Vec<pcap::Device>) {
    
    let mut devindice = 0;
    for device in network_interfaces {
        println!("Device {} {:?}", devindice, device.name);
        devindice+=1;
    }
}

// pub fn listen_and_print_packets<T:pcap::Activated>(mut cap: pcap::Capture<T>) {
pub fn listen_and_print_packets(mut capture: pcap::Capture<pcap::Active>) {
    // print packets continously

    let mut index: u32 = 1;
    loop {
        // get a packet and print its bytes
        let packet = capture.next().unwrap();
        println!("packet {}:", index);
        print_packet(packet);
        index += 1;
    }
}

pub fn print_packet(packet: pcap::Packet) {
    // a function that handles packet printing process

    let pdata:&[u8] = packet.data;
    let ethp:String = eth_protocol(pdata);
    println!("Protocol inside eth: {}", ethp);
    if ethp == "ipv4" {
        ipv4_fields(&pdata[16..]);
    }
    println!("header:{:?}", packet.header);
    println!("data:{:?}", pdata);
    let s = String::from_utf8_lossy(pdata);
    println!("{}", s);
}

pub fn eth_protocol(data: &[u8]) -> String {
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

pub fn ip_protocol(data: u8) -> String {
    // analyze ethernet packet content
    if data==0x06{
        String::from("TCP")
    } else if data==0x11{
        String::from("UDP")
    } else if data==0x01{
        String::from("ICMP")
    } else {
        String::from("unknown")
    }
}

pub fn ipv4_fields(data: &[u8]) {
    // analyze ipv4-packet content

    // println!("IP header len:{:x?}", &data[0]);
    println!("Protocol inside IP: {}", ip_protocol(data[9]));
    println!("source IP: {}", list_2_ip(&data[12..16]));
    println!("destination IP: {}", list_2_ip(&data[16..20]));
}

pub fn list_2_ip(iparray: &[u8]) -> String {
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
