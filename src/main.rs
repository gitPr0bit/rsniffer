
fn main() {
    let devices = pcap::Device::list().expect("Cannot retrieve devices list");
    let mut device = pcap::Device::lookup().expect("device lookup failed");

    for d in devices {
        println!("{:?}", d);

        if d.name == "wlxdc4ef4086754" { device = d }
    }

    // // get the default Device
    // let device = pcap::Device::lookup()
    //     .expect("device lookup failed");//        .expect("no device available");
    println!("Using device {}", device.name);

    // Setup Capture
    // let mut cap = pcap::Capture::from_device(device)
    //     .unwrap()
    //     .promisc(true)
    //     .immediate_mode(true)
    //     .open()
    //     .unwrap();

    let mut capture = match pcap::Capture::from_device(device) {
        Ok(cap) => match cap.promisc(true).immediate_mode(true).open() {
            Ok(active_cap) => active_cap,
            Err(e) => panic!("Error activating capture: {:?}", e)
        },
        Err(e) => panic!("Error opening capture: {:?}", e)
    };


    println!("Links: {:?}", capture.list_datalinks());

    // get 10 packets
    for _ in 0..10 {
        let packet = capture.next().ok();
        println!("Packet: {:02x?}", packet);
        //print!("Dst addr: {}", format!("{:02x?}", &packet.unwrap().data[0..6]));
        print!("Dst addr: {}", format!("{:02x?}", String::from_utf8(packet.unwrap().data[0..6].to_vec())));
        println!("Datalink: {}", capture.get_datalink().0);

        // println!("Dst MAC: {}", &packet.unwrap().data[0..6].into_iter().map(|b| { format!("{:02x}", b) }));
    }

    let stats = capture.stats().unwrap();
    println!(
        "Received: {}, dropped: {}, if_dropped: {}",
        stats.received, stats.dropped, stats.if_dropped
    );
}