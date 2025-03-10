extern crate sdl2;
use crate::structs::PacketContents;
use crate::structs::TimestampedPackets;
use crate::enums::IPProtocol;

use std::time::Instant;
use std::time::Duration;

use sdl2::event::Event;
use sdl2::keyboard::Keycode;
use sdl2::pixels::Color;
use sdl2::rect::Point;

static VISUALIZATION_DECAY:std::time::Duration = std::time::Duration::from_secs(10);
static BACKGROUND_COLOR:Color = Color::RGB(51, 51, 51);

fn change_packet_size_boundary(max_packet_len_to_display: u16) -> u16 {
    if max_packet_len_to_display == 1500 {
        65_535
    } else {
        1500
    }
}

fn clear_packets(printed_tcp: &mut TimestampedPackets, printed_udp: &mut TimestampedPackets) -> () {
    // clear previous packets
    printed_tcp.clear_all();
    printed_udp.clear_all();
}

pub fn display(packets: std::sync::Arc<std::sync::Mutex<Vec<PacketContents>>>,
    signal_sender: std::sync::mpsc::Sender<u8>) -> Result<(), String> {
    let mut max_packet_len_to_display: u16 = 65_535;
    let sdl_context = sdl2::init()?;
    let mut canvas = create_window_with_canvas(&sdl_context, BACKGROUND_COLOR)?;
    let mut event_pump = sdl_context.event_pump()?;

    let mut printed_tcp = TimestampedPackets::new(VISUALIZATION_DECAY);
    let mut printed_udp = TimestampedPackets::new(VISUALIZATION_DECAY);
    'running: loop {
        for event in event_pump.poll_iter() {
            match event {
                Event::Quit { .. }
                | Event::KeyDown {
                    keycode: Some(Keycode::Escape),
                    ..
                } => {signal_sender.send(1).unwrap(); break 'running},
                Event::KeyDown {
                    keycode: Some(Keycode::A),
                    ..
                } => max_packet_len_to_display = change_packet_size_boundary(max_packet_len_to_display),
                Event::KeyDown {
                    keycode: Some(Keycode::D),
                    ..
                } => clear_packets(&mut printed_tcp, &mut printed_udp),
                _ => {}
            }
        }

        // get windows currenct size
        let width ;
        let height;
        (width, height) = canvas.window().size();

        // get & iterate packets
        let mut packet_vector = packets.lock().unwrap();
        let now = Instant::now();

        for packet in packet_vector.iter() {
            if packet.transmission_protocol == IPProtocol::TCP {
                printed_tcp.add_point(packet.clone(), now);
            } else if packet.transmission_protocol == IPProtocol::UDP {
                printed_udp.add_point(packet.clone(), now);
            }
        }
        packet_vector.clear();

        // remove old points from draw vector
        printed_tcp.clear_old();
        printed_udp.clear_old();

        canvas.set_draw_color(BACKGROUND_COLOR);
        canvas.clear();

        // get points to draw and perform drawing translations
        let offset: i32 =  20;
        let width_translation = (width - 2*(offset as u32)) as f64 / 65535.0;
        let height_translation =  (height - 2*offset as u32) as f64 / max_packet_len_to_display as f64;

        canvas.set_draw_color(Color::RGB(70, 70, 70));
        canvas.draw_line(Point::new(offset,height as i32 - offset), Point::new(width as i32 - offset, height as i32 - offset)).unwrap();
        canvas.draw_line(Point::new(offset, height as i32 - offset), Point::new(offset, offset)).unwrap();

        canvas.set_draw_color(Color::RGB(124, 248, 124));
        canvas.draw_points(printed_tcp.get_port_length_plane_points(width_translation, height_translation, max_packet_len_to_display, offset).as_slice()).unwrap();
        canvas.set_draw_color(Color::RGB(104, 122, 254));
        canvas.draw_points(printed_udp.get_port_length_plane_points(width_translation, height_translation, max_packet_len_to_display, offset).as_slice()).unwrap();
        
        canvas.present();

        ::std::thread::sleep(Duration::new(0, 1_000_000_000u32 / 10));
    }

    Ok(())
}

fn create_window_with_canvas(sdl_context: &sdl2::Sdl, background_color: Color) -> Result<sdl2::render::Canvas<sdl2::video::Window>, String> {
    let video_subsystem = sdl_context.video()?;
    let initial_win_width: u32 = 800;
    let initial_win_height: u32 = 600;
    let window = video_subsystem
        .window("ramon", initial_win_width, initial_win_height)
        .resizable()
        .position_centered()
        .opengl()
        .build()
        .map_err(|e| e.to_string())?;
    let mut canvas = window.into_canvas().build().map_err(|e| e.to_string())?;
    canvas.set_draw_color(background_color);
    canvas.clear();
    canvas.present();
    
    Ok(canvas)
}
