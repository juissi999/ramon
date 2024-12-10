use pcap;

use crate::structs::PacketContents;

pub fn print_network_interfaces_list(network_interfaces: &Vec<pcap::Device>) {
    
    let mut devindice = 0;
    for device in network_interfaces {
        println!("Device {} {:?}", devindice, device.name);
        devindice+=1;
    }
}

pub fn listen_and_print_packets(mut capture: pcap::Capture<pcap::Active>, packets: std::sync::Arc<std::sync::Mutex<Vec<PacketContents>>>) {
    // print packets continously

    loop {
        // get a packet and print its bytes
        let packet_result = capture.next_packet();
        match packet_result {
            Ok(packet) => {
                let parsed_packet = parse_packet(packet.clone());
                display_packet(parsed_packet, packets.clone());
            },
            Err(error) => println!("Packet capture error: {error:?}"),
        };
    }
}

pub fn display_packet(packet: PacketContents, packets: std::sync::Arc<std::sync::Mutex<Vec<PacketContents>>>) {
    let mut packet_vector = packets.lock().unwrap();
    packet_vector.push(packet);
}

pub fn parse_packet(packet: pcap::Packet) -> PacketContents{
    // a function that handles packet printing process
    let pdata:&[u8] = packet.data;
    let ethp:String = network_layer_protocol(pdata);
    let mut ipv4_fields: (String, String, String) = (String::new(), String::new(), String::new());
    let mut tcp_udp_fields: (u16, u16) = (0, 0);
    if ethp == "ipv4" {
        ipv4_fields = parse_ipv4_fields(&pdata[14..]);
        if ipv4_fields.0 == "TCP" || ipv4_fields.0 == "UDP" {
            tcp_udp_fields = parse_tcp_udp_fields(&pdata[14+20..]);
        }
    }
    // println!("header:{:?}", packet.header);
    // println!("data:{:?}", pdata);
    
    let parsed_packet = PacketContents{
        network_protocol: ethp,
        transmission_protocol: ipv4_fields.0,
        source_addr: ipv4_fields.1,
        destination_addr: ipv4_fields.2,
        source_port: tcp_udp_fields.0,
        destination_port: tcp_udp_fields.1,
        length: pdata[14+20..].len() as i32,
        data: pdata[14+20..].to_vec()
    };

    parsed_packet
}

pub fn network_layer_protocol(data: &[u8]) -> String {
    // analyze ethernet packet content
    let protocol_bytes: u16 = data[12] as u16 * 256 + data[13] as u16;

    if protocol_bytes == 0x0800 {
        String::from("ipv4")
    } else if protocol_bytes == 0x0806 {
        String::from("ARP")
    } else if protocol_bytes == 0x86dd {
        String::from("ipv6")
    } else {
        String::from("unknown")
    }
}

pub fn transmission_layer_protocol(bytes: u8) -> String {
    // analyze ethernet packet content
    if bytes==0x06 {
        String::from("TCP")
    } else if bytes==0x11 {
        String::from("UDP")
    } else if bytes==0x01 {
        String::from("ICMP")
    } else {
        String::from("unknown")
    }
}

pub fn parse_ipv4_fields(ip_data: &[u8]) -> (String, String, String) {
    // analyze ipv4-packet content
    let tlp = transmission_layer_protocol(ip_data[9]);
    let fields: (String, String, String) = (tlp, list_2_ip(&ip_data[12..16]), list_2_ip(&ip_data[16..20]));

    fields
}

pub fn parse_tcp_udp_fields(tcp_data: &[u8])-> (u16, u16) {
    // analyze tcp or udp-packet content
    let source: u16 = tcp_data[0] as u16 * 256 + tcp_data[1] as u16;
    let destination: u16 = tcp_data[2] as u16 * 256 + tcp_data[3] as u16;

    (source, destination)
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
