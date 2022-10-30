use core::time;
use std::io::{self, Write};
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;
use crate::args::Args;
use crate::lib::sniffer::{sniffer::Sniffer};
use clap::Parser;
use crossterm::style::Stylize;
use crossterm::{cursor, terminal, queue, style};

mod lib;
mod args;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

use crossterm::{
    event::{
        read, Event, KeyCode,
    },
    execute,
    Result,
};

const HELP: &str = r#"
 - Hit "p" to pause;
 - Hit "r" to resume;
 - Use Esc or hit "q" to quit;
"#;


fn main() {
    let mut out = io::stdout();
    let args = Args::parse();
    let broken = false;

    setup_terminal();
    print_help().ok();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    if args.devices {
        let str = "Available devices:";
        println!("\r{}", str);
        for d in Sniffer::printable_devices() {
            println!("\n\r{}", d);
        }
        return;
    }

    let device = match &args.name {
        Some(name) => String::from(name),
        None => {
            let devices = Sniffer::devices();
            let dev = match args.id {
                Some(id) => if id < devices.len() {
                    String::from(&devices[id].name)
                } else {
                    let error_msg = "\rInvalid ID! Falling back to default device...";
                    println!("{}", error_msg.magenta());
                    String::new()
                },
                None => String::new()
            };
            dev
        }
    };

    let sniffer = match Sniffer::builder().device(String::from(&device)).interval(3).capture() {
        Ok(s) => s,
        Err(e) => {
            println!("\r{}", e.to_string().red());
            cleanup_terminal();
            return;
        }
    };

    println!("\rUsing device {}", sniffer.device());

    if let Err(e) = print_events(sniffer) {
        println!("\rError: {:?}\r", e);
    }

    cleanup_terminal();
}



fn show_capture() -> Sender<bool> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let duration = time::Duration::from_millis(1000);
        let mut out = io::stdout();
        let mut show = true;
        'a:loop {
            if pause(&rx) { 
                break 'a; 
            }

            queue!(out, style::SetForegroundColor(style::Color::Green), cursor::MoveToColumn(1)).ok();
            queue!(out, style::Print("Capturing"), style::SetForegroundColor(style::Color::Green)).unwrap();
            out.flush().ok();

            if show == true {
                for _ in 0..3 {
                    if pause(&rx) { 
                        break 'a; 
                    }
                    thread::sleep(time::Duration::from_millis(300));
                    execute!(out, style::Print("."), style::SetForegroundColor(style::Color::Green)).unwrap();
                }
                thread::sleep(duration / 2);
            } else {
                queue!(out, terminal::Clear(terminal::ClearType::CurrentLine)).unwrap();
                thread::sleep(duration / 2);
            }
            
            show = !show;
        }
    });

    tx
}

fn pause(rx: &Receiver<bool>) -> bool {
    let mut out = io::stdout();
    match rx.try_recv() {
        Ok(_) => {
            queue!(out, terminal::Clear(terminal::ClearType::CurrentLine)).unwrap();
            queue!(out, style::SetForegroundColor(style::Color::DarkYellow), cursor::MoveToColumn(1)).ok();
            queue!(out, style::Print("Paused"), style::SetForegroundColor(style::Color::DarkYellow)).unwrap();
            out.flush().ok();
            true
        },
        Err(_) => false
    }
}

fn print_events(sniffer: Sniffer) -> Result<()> {
    let mut capturing = show_capture();

    loop {
        // Blocking read
        let event = read()?;

        if event == Event::Key(KeyCode::Char('p').into()) {
            sniffer.pause();
            capturing.send(true).ok();
        }

        if event == Event::Key(KeyCode::Char('r').into()) {
            sniffer.resume();
            capturing = show_capture();
        }

        if event == Event::Key(KeyCode::Char('q').into()) || event == Event::Key(KeyCode::Esc.into()) {
            sniffer.stop();
            capturing.send(true).ok();
            break;
        }
    }

    Ok(())
}

fn print_help() -> Result<()> {
    let mut out = io::stdout();
    for line in HELP.split(';') {
        queue!(out, style::Print(line), cursor::MoveToNextLine(1))?;
    }
    out.flush()?;

    Ok(())
}

fn setup_terminal() {
	let mut stdout = io::stdout();

	execute!(stdout, cursor::Hide).unwrap();
	execute!(stdout, terminal::Clear(terminal::ClearType::All)).unwrap();
    execute!(stdout, cursor::MoveToRow(0)).ok();

	terminal::enable_raw_mode().unwrap();
}

fn cleanup_terminal() {
	let mut stdout = io::stdout();

    execute!(stdout, style::ResetColor, cursor::MoveToColumn(0)).ok();
    stdout.flush().unwrap();

    terminal::disable_raw_mode().unwrap();

    println!("\n\nBye bye\n");
    execute!(stdout, cursor::Show).unwrap();
}