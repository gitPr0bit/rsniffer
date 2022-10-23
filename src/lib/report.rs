pub mod report {
    use std::{collections::HashMap, fs::File, path::Path};
    use prettytable::{Table, format, row};

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

    pub struct TrafficReport {
        traffic: HashMap<String, TrafficDetail>,
        file_path: String
    }

    impl Default for TrafficReport {
        fn default() -> Self {
            let default_path = String::from("sniff_report.txt");
            TrafficReport::new(default_path)
        }
    }

    impl TrafficReport {
        pub fn new(file_path: String) -> Self {
            Self {
                traffic: HashMap::new(),
                file_path
            }
        }

        pub fn write(&mut self) {
            if self.traffic.len() == 0 {
                // Nothing to print
                return;
            }

            let path = Path::new(&self.file_path);
            let display = path.display();

            // Open a file in write-only mode, returns `io::Result<File>`
            let mut file = match File::create(&path) {
                Err(why) => panic!("couldn't create {}: {}", display, why),
                Ok(file) => file,
            };

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

            for detail in self.traffic.iter() {
                table.add_row(row![detail.1.src_ip, detail.1.dst_ip, detail.1.src_port, detail.1.dst_port, detail.1.protocol, detail.1.bytes, detail.1.npackets]);
                // print!("{:?}", detail);
            }

            match table.print(&mut file) {
                Err(why) => panic!("Couldn't print report table to destination file. {}", why),
                Ok(_lines) => { }
            }
        }

        pub fn new_detail(&mut self, ndetail: TrafficDetail) {
            if ndetail.handled == true {
                self.traffic.entry(ndetail.key())
                        .and_modify(|detail| {
                            // println!("Adding {} bytes to {}", ndetail.bytes, ndetail.key()); 
                            detail.bytes += ndetail.bytes;
                            detail.npackets += 1;
                        })
                        .or_insert( ndetail );
            }
        }
    }

}