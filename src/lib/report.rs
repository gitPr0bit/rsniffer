pub mod report {
    use std::{collections::HashMap, fs::File, path::Path};
    use prettytable::{Table, format, row};

    /// bytes size for 1 kilobyte
    const KB: usize = 1_000;
    const _KB: usize = KB - 1; 
    /// bytes size for 1 megabyte
    const MB: usize = 1_000_000;
    const _MB: usize = MB - 1;
    /// bytes size for 1 gigabyte
    const GB: usize = 1_000_000_000;
    const _GB: usize = GB - 1;

    #[derive(Debug)]
    pub struct TrafficDetail {
        pub src_ip: String,
        pub dst_ip: String,
        pub src_port: String,
        pub dst_port: String,
        pub protocol: String,
        pub bytes: usize,
        pub npackets: usize,
        pub first_ts: String,
        pub last_ts: String,
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
                first_ts: String::new(),
                last_ts: String::new(),
                handled: true
            }
        }

        pub fn key(&self) -> String {
            
            format!("{}:{}:{}:{}", self.src_ip, self.dst_ip, self.src_port, self.dst_port)
        }

        pub fn bytes(&self) -> String {
            let unit: &str;
            let bytes: usize;

            match self.bytes {
                0..=_KB => { unit = " B"; bytes = self.bytes},
                KB..=_MB => { unit = " KB"; bytes = self.bytes / KB},
                MB..=_GB => { unit = " MB"; bytes = self.bytes / MB},
                _ => { unit = " GB"; bytes = self.bytes / GB}
            };

            format!("{:>5}{:>2}", bytes, unit)
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
            table.set_titles(row!["SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "TRANSPORT", "BYTES", "PACKETS #", "FIRST TIMESTAMP", "LAST TIMESTAMP"]);


            // TODO: implement sorting for every field of the table
            let mut sorted: Vec<_> = self.traffic.iter().collect();
            sorted.sort_by(|a, b| a.1.bytes.cmp(&b.1.bytes));

            for detail in sorted {
                table.add_row(row![detail.1.src_ip, detail.1.dst_ip, detail.1.src_port, detail.1.dst_port, 
                    detail.1.protocol, detail.1.bytes(), detail.1.npackets, detail.1.first_ts, detail.1.last_ts]);
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
                            if ndetail.first_ts < detail.first_ts { detail.first_ts = String::from(&ndetail.first_ts); }
                            if ndetail.last_ts > detail.last_ts { detail.last_ts = String::from(&ndetail.last_ts); }

                            detail.bytes += ndetail.bytes;
                            detail.npackets += 1;
                        })
                        .or_insert( ndetail );
            }
        }
    }

}