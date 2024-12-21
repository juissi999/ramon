use std::sync::mpsc::TryRecvError;

use pcap;

use crate::structs::PacketContents;
use crate::enums;

pub fn print_network_interfaces_list(network_interfaces: &Vec<pcap::Device>) {
    
    let mut devindice = 0;
    for device in network_interfaces {
        let device_clone = device.clone();
        println!("Device {0}: {1}", devindice, device_clone.desc.unwrap_or(String::from("No description")));
        devindice+=1;
    }
}

pub fn listen_and_print_packets(device_name: &str, packets: std::sync::Arc<std::sync::Mutex<Vec<PacketContents>>>, signal_receiver: std::sync::mpsc::Receiver<u8>) {

    let mut capture = pcap::Capture::from_device(device_name).unwrap().open().unwrap().setnonblock().unwrap();

    // print packets continously, until terminated by other thread
    'running_capture: loop {
        // check if quit signal came
        let system_signal = signal_receiver.try_recv();
        match system_signal {
            Ok(msg) => {
                if msg == 1 {
                    // terminate loop
                    break 'running_capture;
                }
            },
            Err(error) => if error==TryRecvError::Disconnected { println!("Signaling error: {error:?}") }
        }
            
        // get a packet and print its bytes
        let packet_result = capture.next_packet();
        match packet_result {
            Ok(packet) => {
                let parsed_packet = parse_packet(packet.clone());
                display_packet(parsed_packet, packets.clone());
            },
            Err(error) => if error !=pcap::Error::TimeoutExpired {println!("Packet capture error: {error:?}")},
        };
    }
}

pub fn display_packet(packet: PacketContents, packets: std::sync::Arc<std::sync::Mutex<Vec<PacketContents>>>) {
    let mut packet_vector = packets.lock().unwrap();
    packet_vector.push(packet);
}

pub fn parse_packet(packet: pcap::Packet) -> PacketContents{
    // a function that handles packet printing process

    // println!("header:{:?}", packet.header);
    // println!("data:{:?}", pdata);

    let pdata:&[u8] = packet.data;
    let ether_type:enums::EtherType = get_ether_type(pdata);
    let mut ip_fields: (enums::IPProtocol, String, String) = (enums::IPProtocol::Other, String::new(), String::new());
    let mut tcp_udp_fields: (u16, u16) = (0, 0);
    if ether_type == enums::EtherType::IPv4 {
        ip_fields = parse_ipv4_fields(&pdata[14..]);
        if ip_fields.0 == enums::IPProtocol::TCP || ip_fields.0 == enums::IPProtocol::UDP {
            tcp_udp_fields = parse_tcp_udp_fields(&pdata[14+20..]);
        }
    } else if ether_type == enums::EtherType::IPv6 {
        ip_fields = parse_ipv6_fields(&pdata[14..]);
        if ip_fields.0 == enums::IPProtocol::TCP || ip_fields.0 == enums::IPProtocol::UDP {
            tcp_udp_fields = parse_tcp_udp_fields(&pdata[14+40..]);
        }
    } else if ether_type == enums::EtherType::ARP {
    }

    let parsed_packet = PacketContents{
        network_protocol: ether_type,
        transmission_protocol: ip_fields.0,
        source_addr: ip_fields.1,
        destination_addr: ip_fields.2,
        source_port: tcp_udp_fields.0,
        destination_port: tcp_udp_fields.1,
        length: pdata[14+20..].len() as u16,
        data: pdata[14+20..].to_vec()
    };
    
    parsed_packet
}

pub fn get_ether_type(data: &[u8]) -> enums::EtherType {
    // analyze ethernet packet content
    let protocol_bytes: u16 = data[12] as u16 * 256 + data[13] as u16;

    if protocol_bytes == 0x0800 {
        enums::EtherType::IPv4
    } else if protocol_bytes == 0x0806 {
        enums::EtherType::ARP
    } else if protocol_bytes == 0x86dd {
        enums::EtherType::IPv6
    } else {
        enums::EtherType::Other
    }
}

pub fn transmission_layer_protocol(bytes: u8) -> enums::IPProtocol {
    // analyze ethernet packet content
    if bytes==0x01 {
        enums::IPProtocol::IPv4ICMP
    } else if bytes==0x02  {
        enums::IPProtocol::IGMP
    } else if bytes==0x06 {
        enums::IPProtocol::TCP
    } else if bytes==0x11 {
        enums::IPProtocol::UDP
    } else if bytes==0x3A {
        enums::IPProtocol::IPv6ICMP
    } else {
        enums::IPProtocol::Other
    }
}

pub fn parse_ipv4_fields(ip_data: &[u8]) -> (enums::IPProtocol, String, String) {
    // analyze ipv4-packet content
    let tlp = transmission_layer_protocol(ip_data[9]);
    let fields: (enums::IPProtocol, String, String) = (tlp, list_2_ip(&ip_data[12..16]), list_2_ip(&ip_data[16..20]));

    fields
}

pub fn parse_ipv6_fields(ip_data: &[u8]) -> (enums::IPProtocol, String, String) {
    // analyze ipv6-packet content
    let tlp = transmission_layer_protocol(ip_data[6]);
    let fields: (enums::IPProtocol, String, String) = (tlp, String::from("not implemented yet"), String::from("not implemented yet"));

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
    let mut ipstr = String::new();

    for num in iparray {
        ipstr.push_str(&num.to_string());
        ipstr.push('.');
    }

    // remove last unnecessary dot
    ipstr.pop();

    ipstr
}
