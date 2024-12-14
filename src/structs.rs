use std::time::Instant;
use sdl2::rect::Point;
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

pub struct Coordinate {
    pub x: i32,
    pub y: i32,
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

    pub fn add_point(&mut self, x:i32, y:i32, now: Instant) {
        self.points.push(Coordinate{x, y, created:now});
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

    pub fn get_points(&self) -> Vec<Point> {
        // return points as vector
        let mut printed_points = Vec::new();
        for point in self.points.iter() {
            printed_points.push(Point::new(point.x, point.y));
        };
        printed_points
    }
}
