use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, collections::HashMap, io, sync::{Arc, Mutex, mpsc}, thread, path::Path, fs::File};
use crate::lib::{report::{report::{TrafficDetail, TrafficReport}, self}, parser::parser::*, state_handler::state_handler::{self, StateHandler}};
use pcap::{Capture, Device, Address};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, self},
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet, arp::ArpPacket, PacketSize,
};

#[macro_use] extern crate prettytable;
use prettytable::{Table, Row, format};

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

    let mut capture = match Capture::from_device(device) {
        Ok(cap) => match cap.promisc(true).immediate_mode(true).open() {
            Ok(active_cap) => active_cap,
            Err(e) => panic!("Error activating capture: {:?}", e)
        },
        Err(e) => panic!("Error opening capture: {:?}", e)
    };


    println!("Links: {:?}", capture.list_datalinks());

    let report_handler = Arc::new(Mutex::new(TrafficReport::default()));
    let report = Arc::clone(&report_handler);

    let state_handler = Arc::new(StateHandler::new());
    let sh = Arc::clone(&state_handler);
    
    let (tx, rx) = mpsc::channel();

    let capture_thread = thread::spawn(move || {
        let mut cap = match capture.setnonblock() {
            Ok(nb_capture) => nb_capture,
            Err(e) => panic!("Error opening capture: {:?}", e)
        };

        loop {
            match rx.try_recv() {
                Ok(str) => {
                    match str {
                        "p" => state_handler.pause(),
                        "s" => {
                            println!("Ok, should stop...");
                            break
                        },
                        _ => {}
                    }
                },
                Err(_) => {}
            };

            if let Ok(packet) = cap.next() { // handle errors
                let parsed = parse(&packet);
                let mut rh = report.lock().unwrap();
                rh.new_detail(parsed);
            }
        }

        println!("F**ck! I screwed up")
    });

    println!("Capture started. Press 's' to stop");
    let mut input_string = String::new();

    while input_string.trim() != "s" {
        input_string.clear();
        io::stdin().read_line(&mut input_string).unwrap();

        match input_string.trim() {
            "p" => {
                match tx.send("p") {
                    Ok(_) => println!("Paused. Press 'r' to resume..."),
                    Err(err) => println!("{:?}", err)
                }
                
            },
            "r" => {
                sh.run();
                println!("Resumed. Press 'p' to pause...");
            },
            "s" => {
                sh.run();
                match tx.send("s") {
                    Ok(_) => println!("Stopped"),
                    Err(err) => println!("{:?}", err)
                }
            },
            &_ => println!("")
        }
    }
    capture_thread.join();
    
    println!("Writing report to file...");
    let mut rh = report_handler.lock().unwrap();
    rh.write();
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