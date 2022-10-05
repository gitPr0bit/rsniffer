use std::{net::{IpAddr, Ipv4Addr, Ipv6Addr}, collections::HashMap};

use pcap::{Capture, Device, Address};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Packet, self},
    udp::UdpPacket,
    tcp::TcpPacket,
    Packet, arp::ArpPacket, PacketSize,
};


struct TrafficDetail {
    address: String,
    port: String,
    bytes: usize
}

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

        if handle_packet(&packet, &device_addresses, &mut traffic) == true {
            count += 1;
        }

        if count == 10 { break; }

        // println!("Packet: {:02x?}", packet);
        // //print!("Dst addr: {}", format!("{:02x?}", &packet.unwrap().data[0..6]));
        // print!("Dst addr: {}", format!("{:02x?}", String::from_utf8(packet.data[0..6].to_vec())));
        // println!("Datalink: {}", capture.get_datalink().0);

        // println!("Dst MAC: {}", &packet.unwrap().data[0..6].into_iter().map(|b| { format!("{:02x}", b) }));
    }


    println!("***************** TRAFFIC *********************");
    for detail in traffic.iter() {
        println!("Key: {}, Address: {}, Port: {}, Bytes: {}", detail.0, detail.1.address, detail.1.port, detail.1.bytes);
    }

    // let stats = capture.stats().unwrap();
    // println!(
    //     "Received: {}, dropped: {}, if_dropped: {}",
    //     stats.received, stats.dropped, stats.if_dropped
    // );
}


fn handle_packet(packet: &pcap::Packet, addresses: &Vec<Address>, traffic: &mut HashMap<String, TrafficDetail>) -> bool {
    let ethernet = EthernetPacket::new(packet.data).unwrap();
    let resolve_all_resource_records = true;
    let mut outgoing = true;

    // *************************** move outside handle_packet *************************** //
    // get ip addr of current device
    let mut ipv4_addr = Ipv4Addr::UNSPECIFIED;
    let mut ipv6_addr = Ipv6Addr::UNSPECIFIED;

    for n in 0..addresses.len() {
        // println!("This is {} in vector: {:?}", n, addresses[n].addr);

        match addresses[n].addr {
            IpAddr::V4(ipv4) => ipv4_addr = ipv4,
            IpAddr::V6(ipv6) => ipv6_addr = ipv6
        };

        if ipv4_addr != Ipv4Addr::UNSPECIFIED && ipv6_addr != Ipv6Addr::UNSPECIFIED {
            break;
        }
    };
    // *********************************************************************************** //

    match ethernet.get_ethertype() {
        // Is distinction of Arp traffic meaningful?
        // EtherTypes::Arp => {
        //     let arp_packet = ArpPacket::new(ethernet.payload()).unwrap();
        //     println!("arp - Src: {}\t Dst: {}", arp_packet.get_sender_hw_addr(), arp_packet.get_target_hw_addr());
        // },
        EtherTypes::Ipv4 => {
            let address: String;
            let ipv4_packet = Ipv4Packet::new(ethernet.payload()).unwrap();
            // println!("ipv4 - Src: {}\t Dst: {}", ipv4_packet.get_source(), ipv4_packet.get_destination());

            if ipv4_addr == ipv4_packet.get_destination() {
                outgoing = false;
                address = ipv4_packet.get_source().to_string();
            } else {
                address = ipv4_packet.get_destination().to_string();
            }

            // print!("DEBUG_LOG - Ipv4Address: {:?}   -   ", ipv4_addr);
            // print!("DEBUG_LOG - Address: {}   -   ", address);

            if let IpNextHeaderProtocols::Udp = ipv4_packet.get_next_level_protocol() {
                let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
                // let (rest, dns_message) = dnslogger::parse::dns_message(
                //     udp_packet.payload(),
                //     resolve_all_resource_records
                // ).unwrap();
                // println!("{:?}", dns_message);
                // println!("{:02x?}", rest);

                // Populate statistics
                let port = if outgoing == true { // mi interessa la mia porta, non quella dall'altra parte
                    format!("{}", udp_packet.get_source())
                } else { 
                    format!("{}", udp_packet.get_destination()) 
                };
                let key = format!("{}:{}", address, port);

                println!("UDP - {} - {}", key, usize::from(udp_packet.payload().len()));
                traffic.entry(key).and_modify(|detail| detail.bytes += usize::from(udp_packet.payload().len())).or_insert( TrafficDetail {address: address.clone(), port: port, bytes: usize::from(udp_packet.payload().len())});

                return true;
            }

            if let IpNextHeaderProtocols::Tcp = ipv4_packet.get_next_level_protocol() {
                let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                let src = format!("{}", tcp_packet.get_source());
                let dst = format!("{}", tcp_packet.get_destination());

                let port = if outgoing == true { // mi interessa la mia porta, non quella dall'altra parte
                    src
                } else {
                    dst
                };

                let key = format!("{}:{}", address, port);
                println!("TCP - {} - {}", key, usize::from(tcp_packet.payload().len()));
                traffic.entry(key).and_modify(|detail| detail.bytes += usize::from(tcp_packet.payload().len())).or_insert( TrafficDetail {address: address, port: port, bytes: usize::from(tcp_packet.payload().len())});

                return true;
            }
            
            // if let IpNextHeaderProtocols::Tcp = ipv4_packet.get_next_level_protocol() {
            //     let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                // println!("TCP - Src: {}\t Dst: {}", tcp_packet.get, ipv4_packet.get_destination());
            // }
        },
        _ => println!("unhandled packet: {:?}", ethernet)
    }

    return false;
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