extern crate sdl2;
use crate::structs::PacketContents;
use crate::structs::Coordinates;

use std::time::Instant;
use sdl2::event::Event;
use sdl2::keyboard::Keycode;
use sdl2::pixels::Color;

use std::time::Duration;

static VISUALIZATION_DECAY:std::time::Duration = std::time::Duration::from_secs(10);

pub fn display(packets: std::sync::Arc<std::sync::Mutex<Vec<PacketContents>>>) -> Result<(), String> {
    let sdl_context = sdl2::init()?;
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

    canvas.set_draw_color(Color::RGB(51, 51, 51));
    canvas.clear();
    canvas.present();
    let mut event_pump = sdl_context.event_pump()?;

    let mut printed_tcp = Coordinates::new(VISUALIZATION_DECAY);
    let mut printed_udp = Coordinates::new(VISUALIZATION_DECAY);
    'running: loop {
        for event in event_pump.poll_iter() {
            match event {
                Event::Quit { .. }
                | Event::KeyDown {
                    keycode: Some(Keycode::Escape),
                    ..
                } => break 'running,
                // Event::KeyDown {
                //     keycode: Some(Keycode::A),
                //     ..
                // } => printit(&mut canvas, win_width, win_height),
                _ => {}
            }
        }
        // get windows currenct size
        let width ;
        let height;
        (width, height) = canvas.window().size();

        let mut packet_vector = packets.lock().unwrap();
        println!("len packets:{}", packet_vector.len());

        let now = Instant::now();

        for packet in packet_vector.iter() {
            if packet.transmission_protocol == "TCP" {
                printed_tcp.add_point(packet.source_port, packet.length, now);
            } else if packet.transmission_protocol == "UDP" {
                printed_udp.add_point(packet.source_port, packet.length, now);
            }
            //println!("Received packet.");
        }
        packet_vector.clear();

        // remove old points from draw vector
        printed_tcp.clear_old();
        printed_udp.clear_old();

        canvas.set_draw_color(Color::RGB(51, 51, 51));
        canvas.clear();

        ::std::thread::sleep(Duration::new(0, 1_000_000_000u32 / 10));

        let width_translation = width as f64 / 65535.0;
        let height_translation =  height as f64 / 1500.0;

        canvas.set_draw_color(Color::RGB(255, 182, 193));
        canvas.draw_points(printed_tcp.get_points(width_translation, height_translation).as_slice()).unwrap();
        canvas.set_draw_color(Color::RGB(144, 238, 144));
        canvas.draw_points(printed_udp.get_points(width_translation, height_translation).as_slice()).unwrap();
        canvas.present();
        // The rest of the game loop goes here...
    }

    Ok(())
}
