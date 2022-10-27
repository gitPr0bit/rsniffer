use core::time;
use std::io::{self, Write};
use std::sync::Arc;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread::{JoinHandle, self};
use crate::args::args::{Args, Commands};
use crate::lib::capture::capture::CaptureWrapper;
use crate::lib::sniffer::{sniffer::Sniffer};
use clap::Parser;
use crossterm::{cursor, terminal, queue, style};
use pcap::Device;

mod lib;
mod args;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

use std::io::stdout;

use crossterm::event::{
    poll,
};
use crossterm::{
    event::{
        read, Event, KeyCode,
    },
    execute,
    Result,
};
use std::time::Duration;

const HELP: &str = r#"
 - Hit "p" to pause;
 - Hit "r" to resume;
 - Use Esc or hit "q" to quit;
"#;


fn main() {
    let args = Args::parse();

    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd
    match &args.list {
        Commands::List => {
            for d in Sniffer::devices() {
                println!("{}\n", d);
            }
            return;
        }
    }

    let device = match &args.name {
        Some(name) => String::from(name),
        None => String::new()
    };

    let sniffer = Sniffer::builder()
        .device(String::from(&device))
        .interval(3)
        .capture();

    setup_terminal();
    print_help().ok();
    println!("Using device {}", sniffer.device());
    println!("{:?}", args);
    println!("\n\n");

    // let mut stdout = stdout();
    // execute!(
    //     stdout,
    //     EnableBracketedPaste,
    //     EnableFocusChange,
    //     EnableMouseCapture,
    //     PushKeyboardEnhancementFlags(
    //         KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
    //             | KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES
    //             | KeyboardEnhancementFlags::REPORT_EVENT_TYPES
    //     )
    // )?;

    if let Err(e) = print_events(sniffer) {
        println!("Error: {:?}\r", e);
    }

    // execute!(
    //     stdout,
    //     DisableBracketedPaste,
    //     PopKeyboardEnhancementFlags,
    //     DisableFocusChange,
    //     DisableMouseCapture
    // )?;

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

// Resize events can occur in batches.
// With a simple loop they can be flushed.
// This function will keep the first and last resize event.
fn flush_resize_events(first_resize: (u16, u16)) -> ((u16, u16), (u16, u16)) {
    let mut last_resize = first_resize;
    while let Ok(true) = poll(Duration::from_millis(50)) {
        if let Ok(Event::Resize(x, y)) = read() {
            last_resize = (x, y);
        }
    }

    return (first_resize, last_resize);
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

	execute!(stdout, terminal::EnterAlternateScreen).unwrap();
	execute!(stdout, cursor::Hide).unwrap();

	// Needed for when ytop is run in a TTY since TTYs don't actually have an alternate screen.
	// Must be executed after attempting to enter the alternate screen so that it only clears the
	// 		primary screen if we are running in a TTY.
	// If not running in a TTY, then we just end up clearing the alternate screen which should have
	// 		no effect.
	execute!(stdout, terminal::Clear(terminal::ClearType::All)).unwrap();
    execute!(stdout, cursor::MoveToRow(0)).ok();

	terminal::enable_raw_mode().unwrap();
}

fn cleanup_terminal() {
	let mut stdout = io::stdout();

	// Needed for when ytop is run in a TTY since TTYs don't actually have an alternate screen.
	// Must be executed before attempting to leave the alternate screen so that it only modifies the
	// 		primary screen if we are running in a TTY.
	// If not running in a TTY, then we just end up modifying the alternate screen which should have
	// 		no effect.
	execute!(stdout, cursor::MoveTo(0, 0)).unwrap();
	execute!(stdout, terminal::Clear(terminal::ClearType::All)).unwrap();

	execute!(stdout, terminal::LeaveAlternateScreen).unwrap();
	execute!(stdout, cursor::Show).unwrap();

	terminal::disable_raw_mode().unwrap();
}