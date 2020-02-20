use pcap::Device;

fn main() {
    // list all devices
    let devices = Device::list().unwrap();
    for device in devices {
        println!("Found device {:?}", device.name);
    }
    
}
