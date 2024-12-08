pub struct PacketContents {
    pub network_protocol: String,
    pub transmission_protocol: String,
    pub source_addr: String,
    pub destination_addr: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub length: i32,
    pub data: Vec<u8>
}
