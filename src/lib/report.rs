pub mod report {
    use std::{collections::HashMap, fs::File, path::Path, sync::{Mutex, Arc}};

    use prettytable::{Table, format};

    #[derive(Debug)]
    pub struct TrafficDetail {
        pub src_ip: String,
        pub dst_ip: String,
        pub src_port: String,
        pub dst_port: String,
        pub protocol: String,
        pub bytes: usize,
        pub npackets: usize,
        pub handled: bool
    }

    impl TrafficDetail {
        pub fn new() -> Self {
            Self {
                src_ip: String::new(),
                dst_ip: String::new(),
                src_port: String::new(),
                dst_port: String::new(),
                protocol: String::new(),
                bytes: 0,
                npackets: 1,
                handled: true
            }
        }

        pub fn key(&self) -> String {
            
            format!("{}:{}:{}:{}", self.src_ip, self.dst_ip, self.src_port, self.dst_port)
        }
    }

    struct TrafficReport {
        traffic: Arc<Mutex<HashMap<String, TrafficDetail>>>,
        file: File
    }

    impl Default for TrafficReport {
        fn default() -> Self {
            let default_path = String::from("sniff_report.txt");
            TrafficReport::new(default_path)
        }
    }

    impl TrafficReport {
        pub fn new(file_path: String) -> Self {
            let path = Path::new(&file_path);
            let display = path.display();

            // Open a file in write-only mode, returns `io::Result<File>`
            let mut file = match File::create(&path) {
                Err(why) => panic!("couldn't create {}: {}", display, why),
                Ok(file) => file,
            };

            Self {
                traffic: Arc::new(Mutex::new(HashMap::new())),
                file
            }
        }

        pub fn write(&self) {
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

            let traffic_report = self.traffic.lock().unwrap();
            for detail in traffic_report.iter() {
                table.add_row(row![detail.1.src_ip, detail.1.dst_ip, detail.1.src_port, detail.1.dst_port, detail.1.protocol, detail.1.bytes, detail.1.npackets]);
                // print!("{:?}", detail);
            }
        }
    }

}