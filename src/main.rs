use std::io;
use crate::lib::sniffer::{sniffer::Sniffer, self};
use pcap::Device;

mod lib;

fn main() {
    // let devices = Device::list().expect("Cannot retrieve devices list");
    let device = Device::lookup().expect("device lookup failed");
    println!("Using device {}", device.name);

    let sniffer = Sniffer::builder().device(device.name).interval(3).capture();

    println!("Capture started. Press 's' to stop");
    let mut input_string = String::new();

    while input_string.trim() != "s" {
        input_string.clear();
        io::stdin().read_line(&mut input_string).unwrap();

        match input_string.trim() {
            "p" => {
                sniffer.pause();
                println!("Paused. Press 'r' to resume...");
            },
            "r" => {
                sniffer.resume();
                println!("Resumed. Press 'p' to pause...");
            },
            "s" => {
                sniffer.stop();
                println!("Stopped");
            },
            &_ => println!("")
        }
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