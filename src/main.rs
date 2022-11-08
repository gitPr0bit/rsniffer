use core::time;
use args::Args;
use std::thread;
use clap::Parser;
use snifferlib::Sniffer;
use std::io::{self, Write};
use crossterm::style::Stylize;
use std::sync::mpsc::{self, Sender, Receiver};

use crossterm::{cursor, terminal, queue, style};
use crossterm::event::{read, Event, KeyCode};
use crossterm::{execute, Result};

use crate::args::GREETINGS;

mod args;

enum AppState {
    Running,
    Paused,
    Stopped
}

#[doc(hidden)]
fn main() {
    let args = Args::parse();

    setup_terminal();
    
    // Print app's greetings
    println!("{}", GREETINGS);

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

    // Print device name and commands hints
    println!("\n\n\rUsing device {} for capture.", sniffer.device());
    print_help().ok();

    if let Err(e) = print_events(sniffer) {
        eprintln!("\n\rError: {:?}\r", e);
    }

    cleanup_terminal();
    println!("\n\nBye bye!\n");
}


#[doc(hidden)]
fn show_capture() -> Sender<AppState> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let duration = time::Duration::from_millis(1000);
        let mut out = io::stdout();
        let mut show = true;
        'a:loop {
            if pause_or_stop(&rx) { 
                break 'a; 
            }

            queue!(out, style::SetForegroundColor(style::Color::Green), cursor::MoveToColumn(1)).ok();
            queue!(out, style::Print("Capturing"), style::SetForegroundColor(style::Color::Green)).unwrap();
            out.flush().ok();

            if show == true {
                for _ in 0..3 {
                    if pause_or_stop(&rx) { 
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
fn pause_or_stop(rx: &Receiver<AppState>) -> bool {
    let mut out = io::stdout();
    match rx.try_recv() {
        Ok(state) => {
            queue!(out, terminal::Clear(terminal::ClearType::CurrentLine)).unwrap();
            match state {
                AppState::Paused => {
                    queue!(out, style::SetForegroundColor(style::Color::DarkYellow), cursor::MoveToColumn(1)).ok();
                    queue!(out, style::Print("Paused")).unwrap(); 
                },
                AppState::Stopped => { show_quitting(); },
                _ => {}
            }
            
            out.flush().ok();
            true
        },
        Err(_) => false
    }
}

#[doc(hidden)]
fn show_quitting() {
    thread::spawn(|| {
        let duration = time::Duration::from_millis(1000);
        let mut out = io::stdout();

        loop {
            queue!(out, terminal::Clear(terminal::ClearType::CurrentLine)).unwrap();
            queue!(out, style::SetForegroundColor(style::Color::Magenta), cursor::MoveToColumn(1)).ok();
                queue!(out, style::Print("Stopped. Quitting"), style::SetForegroundColor(style::Color::Magenta)).unwrap();
                out.flush().ok();
    
            for _ in 0..3 {
                thread::sleep(time::Duration::from_millis(300));
                execute!(out, style::Print("."), style::SetForegroundColor(style::Color::Magenta)).unwrap();
            }
            thread::sleep(duration / 2);
        }
    });
}

#[doc(hidden)]
fn print_events(sniffer: Sniffer) -> Result<()> {
    let mut capturing = show_capture();
    let mut app_state = AppState::Running;

    loop {
        // Blocking read
        let event = read()?;

        if event == Event::Key(KeyCode::Char('p').into()) {
            app_state = AppState::Paused;

            sniffer.pause();
            capturing.send(AppState::Paused).ok();
        }

        if event == Event::Key(KeyCode::Char('r').into()) {
            app_state = AppState::Running;

            sniffer.resume();
            capturing = show_capture();
        }

        if event == Event::Key(KeyCode::Char('q').into()) || event == Event::Key(KeyCode::Esc.into()) {
            match app_state {
                AppState::Running => { capturing.send(AppState::Stopped).ok(); },
                AppState::Paused | AppState::Stopped => { show_quitting(); }
            }

            sniffer.stop();
            break;
        }
    }

    Ok(())
}

#[doc(hidden)]
fn print_help() -> Result<()> {
    print!("\rHit {} to {}, ", "p".yellow(), "Pause".yellow());
    print!("{} to {}, ", "r".green(), "Resume".green());
    println!("{} or {} to {}\n", "Esc".magenta(), "q".magenta(), "Quit".magenta());

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
    execute!(stdout, cursor::Show).unwrap();
}

#[doc(hidden)]
fn err_and_clean(err: String) {
    eprintln!("\n\r{}", "An error occurred!".red());
    eprintln!("\r{}", err);
    cleanup_terminal();
}