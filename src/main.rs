use core::time;
use args::Args;
use std::thread;
use clap::Parser;
use std::io::{self, Write};
use crossterm::style::Stylize;
use std::sync::mpsc::{self, Sender, Receiver};
use crossterm::{cursor, terminal, queue, style};
use snifferlib::Sniffer;

mod args;

use crossterm::{
    event::{
        read, Event, KeyCode,
    },
    execute,
    Result,
};

#[doc(hidden)]
const HELP: &str = r#"
 - Hit "p" to pause;
 - Hit "r" to resume;
 - Hit Esc or "q" to quit;
"#;

#[doc(hidden)]
fn main() {
    let args = Args::parse();

    setup_terminal();
    print_help().ok();

    if args.list_devices {
        println!("\rAvailable devices:");

        match Sniffer::printable_devices() {
            Ok(devices) => {
                for d in devices {
                    println!("\n\r{}", d);
                }
            },
            Err(e) => eprintln!("{}", e)
        }

        cleanup_terminal();
        return;
    }

    // First, look for a device name and, if missing, then look
    // for a device ID
    let device = match &args.device {
        Some(name) => String::from(name),
        None => {
            let devices = match Sniffer::devices() {
                Ok(devs) => devs,
                Err(e) => {
                    err_and_clean(e.to_string()); 
                    return; 
                }
            };

            let dev = match args.id {
                Some(id) => if id < devices.len() {
                    String::from(&devices[id].name)
                } else {
                    let error_msg = "\rInvalid ID! Falling back to default device...";
                    eprintln!("{}", error_msg.magenta());
                    String::new()
                },
                None => String::new()
            };
            dev
        }
    };

    let out = match &args.output {
        Some(o) => Some(o.to_string()),
        None => None
    };

    let sort = match &args.sort {
        Some(s) => Some(s.to_string()),
        None => None
    };

    let interval = match &args.time_interval {
        Some(s) => *s,
        None => 3
    };

    let filter = match &args.filter {
        Some(f) => Some(f.to_string()),
        None => None
    };

    let sniffer = match Sniffer::builder().device(String::from(&device)).out(out).filter(filter).sort(sort).interval(interval).capture() {
        Ok(s) => s,
        Err(e) => {
            err_and_clean(e.to_string());
            return;
        }
    };

    println!("\rUsing device {}", sniffer.device());

    if let Err(e) = print_events(sniffer) {
        eprintln!("\n\rError: {:?}\r", e);
    }

    cleanup_terminal();
}


#[doc(hidden)]
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

#[doc(hidden)]
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

#[doc(hidden)]
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

#[doc(hidden)]
fn print_help() -> Result<()> {
    let mut out = io::stdout();
    for line in HELP.split(';') {
        queue!(out, style::Print(line), cursor::MoveToNextLine(1))?;
    }
    out.flush()?;

    Ok(())
}

#[doc(hidden)]
fn setup_terminal() {
	let mut stdout = io::stdout();

	execute!(stdout, cursor::Hide).unwrap();
	execute!(stdout, terminal::Clear(terminal::ClearType::All)).unwrap();
    execute!(stdout, cursor::MoveToRow(0)).ok();

	terminal::enable_raw_mode().unwrap();
}

#[doc(hidden)]
fn cleanup_terminal() {
	let mut stdout = io::stdout();

    execute!(stdout, style::ResetColor, cursor::MoveToColumn(0)).ok();
    stdout.flush().unwrap();

    terminal::disable_raw_mode().unwrap();

    println!("\n\nExiting...\n");
    execute!(stdout, cursor::Show).unwrap();
}

#[doc(hidden)]
fn err_and_clean(err: String) {
    eprintln!("\n\rAn error occurred: {}", err);
    cleanup_terminal();
}