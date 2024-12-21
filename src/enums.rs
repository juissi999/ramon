#[derive(PartialEq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Other
}

#[derive(PartialEq)]
pub enum IPProtocol {
    TCP,
    UDP,
    IPv4ICMP,
    IPv6ICMP,
    IGMP,
    Other
}
