use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, collections::HashMap};
use crate::lib::{report::report::TrafficDetail, parser::parser::*};
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

    let device_addresses = device.addresses.clone();

    let mut capture = match Capture::from_device(device) {
        Ok(cap) => match cap.promisc(true).immediate_mode(true).open() {
            Ok(active_cap) => active_cap,
            Err(e) => panic!("Error activating capture: {:?}", e)
        },
        Err(e) => panic!("Error opening capture: {:?}", e)
    }; 


    println!("Links: {:?}", capture.list_datalinks());
    let mut traffic: HashMap<String, TrafficDetail> = HashMap::new();

    // get 10 packets
    let mut count = 0;
    loop {
        let packet = capture.next().unwrap(); // handle errors


        let parsed = parse(&packet);
        if parsed.handled == true {
            count += 1;
            traffic.entry(parsed.key())
                    .and_modify(|detail| {
                        println!("Adding {} bytes to {}", parsed.bytes, parsed.key()); 
                        detail.bytes += parsed.bytes;
                        detail.npackets += 1;
                    })
                    .or_insert( parsed );
        }

        if count == 10 { break; }

        // println!("Packet: {:02x?}", packet);
        // //print!("Dst addr: {}", format!("{:02x?}", &packet.unwrap().data[0..6]));
        // print!("Dst addr: {}", format!("{:02x?}", String::from_utf8(packet.data[0..6].to_vec())));
        // println!("Datalink: {}", capture.get_datalink().0);

        // println!("Dst MAC: {}", &packet.unwrap().data[0..6].into_iter().map(|b| { format!("{:02x}", b) }));
    }


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

    for detail in traffic.iter() {
        table.add_row(row![detail.1.src_ip, detail.1.dst_ip, detail.1.src_port, detail.1.dst_port, detail.1.protocol, detail.1.bytes, detail.1.npackets]);
        // print!("{:?}", detail);
    }

    table.printstd();

    // let stats = capture.stats().unwrap();
    // println!(
    //     "Received: {}, dropped: {}, if_dropped: {}",
    //     stats.received, stats.dropped, stats.if_dropped
    // );
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