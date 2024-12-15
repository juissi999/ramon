use std::time::Instant;
use sdl2::rect::Point;
pub struct PacketContents {
    pub network_protocol: String,
    pub transmission_protocol: String,
    pub source_addr: String,
    pub destination_addr: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub data: Vec<u8>
}

pub struct Coordinate {
    pub x: u16,
    pub y: u16,
    pub created: Instant
}

pub struct Coordinates {
    points: Vec<Coordinate>,
    decay_duration: std::time::Duration
}

impl Coordinates {
    pub fn new(visualization_decay:std::time::Duration) -> Self {
        Coordinates{
            points: Vec::new(),
            decay_duration: visualization_decay
        }
    }

    pub fn add_point(&mut self, x:u16, y:u16, now: Instant) {
        self.points.push(Coordinate{x, y, created:now});
    }

    pub fn clear_all(&mut self) {
        // remove all points from draw vector
        self.points.clear();
    }

    pub fn clear_old(&mut self) {
        // remove old points from draw vector
        let mut idx = 0 as usize;

        while idx < self.points.len() {
            if self.points[idx].created.elapsed() > self.decay_duration {
                self.points.remove(idx);
                continue;
            }
            idx = idx + 1;
        };
    }

    pub fn get_points(&self, width_translation: f64, height_translation: f64, max_packet_len_to_display:u16, offset: i32) -> Vec<Point> {
        // return points as vector
        let mut printed_points = Vec::new();
        for point in self.points.iter() {
            printed_points.push(
                Point::new(
                    offset + (point.x as f64*width_translation) as i32,
                    offset + ((max_packet_len_to_display as i32 - point.y as i32) as f64*height_translation) as i32
                    )
                );
        };
        printed_points
    }
}
