use std::time::Instant;
use sdl2::rect::Point;
use crate::enums;

#[derive(Clone, Debug)]
pub struct PacketContents {
    pub network_protocol: enums::EtherType,
    pub transmission_protocol: enums::IPProtocol,
    pub source_addr: String,
    pub destination_addr: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub data: Vec<u8>
}

pub struct TimestampedPacket {
    pub packet: PacketContents,
    pub created: Instant
}

pub struct TimestampedPackets {
    packets: Vec<TimestampedPacket>,
    decay_duration: std::time::Duration
}

#[allow(dead_code)]
impl TimestampedPackets {
    pub fn new(visualization_decay:std::time::Duration) -> Self {
        TimestampedPackets{
            packets: Vec::new(),
            decay_duration: visualization_decay
        }
    }

    pub fn add_point(&mut self, packet: PacketContents, now: Instant) {
        self.packets.push(TimestampedPacket{packet, created:now});
    }

    pub fn len(&mut self) -> usize {
        // get point vector length
        self.packets.len()
    }
    
    pub fn clear_all(&mut self) {
        // remove all points from draw vector
        self.packets.clear();
    }

    pub fn clear_old(&mut self) {
        // remove old points from draw vector
        let mut idx = 0 as usize;

        while idx < self.packets.len() {
            if self.packets[idx].created.elapsed() > self.decay_duration {
                self.packets.remove(idx);
                continue;
            }
            idx = idx + 1;
        };
    }

    pub fn get_points(&self, width_translation: f64, height_translation: f64, max_packet_len_to_display:u16, offset: i32) -> Vec<Point> {
        // return points as vector
        let mut printed_points = Vec::new();
        for timestamped_packet in self.packets.iter() {
            let draw_point = Point::new(
                offset + (timestamped_packet.packet.source_port as f64*width_translation).ceil() as i32,
                offset + ((max_packet_len_to_display as i32 - timestamped_packet.packet.length as i32) as f64*height_translation) as i32
            );

            printed_points.push(draw_point);
        };
        printed_points
    }
}
