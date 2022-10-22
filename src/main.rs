use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, collections::HashMap, io, sync::{Arc, Mutex, mpsc}, thread, path::Path, fs::File};
use crate::lib::{report::report::TrafficDetail, parser::parser::*, state_handler::state_handler::{self, StateHandler}};
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
    let mut traffic: Arc<Mutex<HashMap<String, TrafficDetail>>> = Arc::new(Mutex::new(HashMap::new()));
    let traffic_t = traffic.clone();

    let state_handler = Arc::new(StateHandler::new());
    let sh = Arc::clone(&state_handler);
    
    let (tx, rx) = mpsc::channel();

    let capture_thread = thread::spawn(move || {
        while let Ok(packet) = capture.next() { // handle errors
            match rx.try_recv() {
                Ok(str) => {
                    match str {
                        "p" => state_handler.pause(),
                        "s" => break,
                        _ => {}
                    }
                },
                Err(_) => {}
            };

            let parsed = parse(&packet);
            if parsed.handled == true {
                let mut traffic = traffic_t.lock().unwrap();
                traffic.entry(parsed.key())
                        .and_modify(|detail| {
                            println!("Adding {} bytes to {}", parsed.bytes, parsed.key()); 
                            detail.bytes += parsed.bytes;
                            detail.npackets += 1;
                        })
                        .or_insert( parsed );
            }
        }
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
    println!("See you later!");


    let mut table = Table::new();
    let format = format::FormatBuilder::new()
        .column_separator('|')
        .borders('|')
        .separators(&[format::LinePosition::Top, format::LinePosition::Bottom, format::LinePosition::Title],
                      format::LineSeparator::new('-', '+', '+', '+'))
        .padding(1, 1)
        .build();
    table.set_format(format);
    table.set_titles(row!["SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "TRANSPORT", "BYTES", "PACKETS #"]);

    let traffic_report = traffic.lock().unwrap();
    for detail in traffic_report.iter() {
        table.add_row(row![detail.1.src_ip, detail.1.dst_ip, detail.1.src_port, detail.1.dst_port, detail.1.protocol, detail.1.bytes, detail.1.npackets]);
        // print!("{:?}", detail);
    }

    // Try printing to file
    let path = Path::new("sniff_report.txt");
    let display = path.display();

    // Open a file in write-only mode, returns `io::Result<File>`
    let mut file = match File::create(&path) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(file) => file,
    };

    match table.print(&mut file) {
        Err(why) => panic!("couldn't create {}: {}", display, why),
        Ok(_lines) => {},
    }
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