use core::time;
use std::{io, sync::{Arc, Mutex}, thread, cell::RefCell};
use crate::lib::{report::report::TrafficReport, parser::parser::*, state_handler::state_handler::{StateHandler, State}, capture::capture::*};
use pcap::{Capture, Device};

mod lib;

fn main() {
    let devices = Device::list().expect("Cannot retrieve devices list");
    let mut device = Device::lookup().expect("device lookup failed");

    for d in devices {
        println!("{:?}", d);

        if d.name == "eth0" { device = d }
    }

    // // get the default Device
    // let device = Device::lookup()
    //     .expect("device lookup failed");//        .expect("no device available");
    println!("Using device {}", device.name);
    let addr = &device.addresses;
    print!("Addresses: {:?}", addr);

    // Setup Capture
    // let mut cap = Capture::from_device(device)
    //     .unwrap()
    //     .promisc(true)
    //     .immediate_mode(true)
    //     .open()
    //     .unwrap();


    // let mut test = RefCell::new(String::from("pippo"));
    // let mut str = test.borrow_mut();
    // drop(str);

    // test = RefCell::new(String::from("pluto"));
    // let str2 = test.borrow();
    // println!("{}", str2);



    let mut capture = CaptureWrapper::new(device);


    // println!("Links: {:?}", capture.list_datalinks());

    let report_handler = Arc::new(Mutex::new(TrafficReport::default()));
    let report = Arc::clone(&report_handler);

    let state_handler = Arc::new(StateHandler::new());
    let sh_capture = Arc::clone(&state_handler);
    let sh_report = Arc::clone(&state_handler);

    let capture_thread = thread::spawn(move || {
        loop {
            match state_handler.state() {
                State::Running => capture.start_capture(),
                State::Pausing | State::Paused => {
                    capture.stop_capture();
                    state_handler.set_state(State::Paused);
                },
                State::Stopped => {
                    capture.stop_capture();
                    break
                }
            }

            if capture.active() {
                if let Ok(packet) = capture.next() { // handle errors
                    let parsed = parse(&packet);
                    let mut rh = report.lock().unwrap();
                    rh.new_detail(parsed);
                }
            }
        }

        println!("F**ck! I screwed up")
    });

    // Start thread that writes report to files
    // TODO: move this to a lib's module
    let report_thread = thread::spawn(move || {
        let duration = time::Duration::from_secs(5);

        loop {
            match sh_report.state() {
                State::Pausing | State::Paused => sh_report.set_state(State::Paused),
                State::Stopped => break,
                _ => {}
            }

            thread::sleep(duration);
            let mut rh = report_handler.lock().unwrap();

            println!("\nWriting report to file...");
            rh.write();
        }

        println!("Leaving report loop :D");
    });

    println!("Capture started. Press 's' to stop");
    let mut input_string = String::new();

    while input_string.trim() != "s" {
        input_string.clear();
        io::stdin().read_line(&mut input_string).unwrap();

        match input_string.trim() {
            "p" => {
                sh_capture.set_state(State::Pausing);
                println!("Paused. Press 'r' to resume...");
            },
            "r" => {
                sh_capture.set_state(State::Running);
                println!("Resumed. Press 'p' to pause...");
            },
            "s" => {
                sh_capture.set_state(State::Stopped);
                println!("Stopped");
            },
            &_ => println!("")
        }
    }

    capture_thread.join();
    report_thread.join();
}


// use rayon;
// use std::thread;
// use std::time::Duration;

// fn main() {
//     println!("Il thread principale ha id {:?}", thread::current().id());
//     //Il thread pool racchiude al proprio interno i thread usati per l'elaborazione
//     let tp = rayon::ThreadPoolBuilder::new().build().unwrap();
//     println!("Il numero dei thread nel thread pool è {}", rayon::current_num_threads());
//     //uno scope delimita un gruppo di task: lo scope termina quando tutti i task creati al suo
//     //interno saranno finiti
//     rayon::scope(|s| {
//         println!("Lo scope è eseguito nel thread con id {:?}", thread::current().id());
//         //esempio di dati da elaborare
//         let v = vec!["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p"];
//         for msg in v.into_iter() {
//             //creo un nuovo task che sarà eseguito nel thread pool
//             s.spawn(move|_|{
//                 let id = thread::current().id();
//                 println!("Elaboro il messaggio {} nel thread {:?}",msg,id);
//                 //simulo un'attività lunga
//                 thread::sleep(Duration::from_secs(1));
//             });
//         }
//     });
//     println!("Done");
// }