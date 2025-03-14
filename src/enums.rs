#[derive(PartialEq, Clone, Debug)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Other
}

#[derive(PartialEq, Clone, Debug)]
pub enum IPProtocol {
    TCP,
    UDP,
    IPv4ICMP,
    IPv6ICMP,
    IGMP,
    Other
}
