pub mod report {
    use std::{collections::HashMap, fs::File, path::Path, io::Error, io::Write};
    use chrono::Utc;
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

    pub const NFIELDS: u32 = 9;
    pub const WPERIOD: u64 = 5;
    pub const DEFAULT_OUT: &str = "rsniffer_report.txt";

    #[derive(Debug)]
    pub struct TrafficDetail {
        pub src_ip: String,
        pub dst_ip: String,
        pub src_port: String,
        pub dst_port: String,
        pub protocols: String,
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
                protocols: String::new(),
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
        file_path: String,
        sorting: Option<String>
    }

    impl Default for TrafficReport {
        fn default() -> Self {
            let default_path = String::from(DEFAULT_OUT);
            TrafficReport::new(default_path)
        }
    }

    impl TrafficReport {
        pub fn new(file_path: String) -> Self {
            Self {
                traffic: HashMap::new(),
                file_path,
                sorting: None
            }
        }

        pub fn write(&mut self) -> Result<(), Error> {
            let path = Path::new(&self.file_path);

            // Open a file in write-only mode, returns `io::Result<File>`
            let mut file = match File::create(&path) {
                Err(why) => { return Err(why); },
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
            table.set_titles(row!["SRC_IP", "DST_IP", "SRC_PORT", "DST_PORT", "PROTOCOLS", "BYTES", "PACKETS #", "FIRST TIMESTAMP", "LAST TIMESTAMP"]);
            

            if self.traffic.len() > 0 {
                let sorted = self.sort();
                for detail in sorted {
                    table.add_row(row![detail.1.src_ip, detail.1.dst_ip, detail.1.src_port, detail.1.dst_port, 
                        detail.1.protocols, detail.1.bytes(), detail.1.npackets, detail.1.first_ts, detail.1.last_ts]);
                }
            } else {
                table.add_row(row!["", "", "", "", "", "", "", "", ""]);
            }

            match table.print(&mut file) {
                Err(why) => panic!("Couldn't print report table to destination file. {}", why),
                Ok(_lines) => { }
            }


            let dt = Utc::now();
            // let time_stamp = format!("\n\rLast update: {}", dt);
            write!(&mut file, "\n\rLast update: {}", dt).ok();
            std::io::stdout().flush().unwrap();

            Ok(())
        }

        pub fn new_detail(&mut self, ndetail: TrafficDetail) {
            if ndetail.handled == true {
                self.traffic.entry(ndetail.key())
                        .and_modify(|detail| {
                            if ndetail.first_ts < detail.first_ts { detail.first_ts = String::from(&ndetail.first_ts); }
                            if ndetail.last_ts > detail.last_ts { detail.last_ts = String::from(&ndetail.last_ts); }

                            if !detail.protocols.contains(&ndetail.protocols) {
                                detail.protocols.push_str(&format!(", {}", ndetail.protocols));
                            }

                            detail.bytes += ndetail.bytes;
                            detail.npackets += 1;
                        })
                        .or_insert( ndetail );
            }
        }

        pub fn set_sorting(&mut self, sort: Option<String>) -> bool {
            let str = match sort {
                Some(s) => s,
                None => { return false; }
            };

            if str.len() != 2 { return false };

            let field = str.chars().nth(0).unwrap().to_digit(10).unwrap_or_default();
            if field >= NFIELDS { return false; }

            let direction = str.chars().nth(1).unwrap();
            if direction != 'L' && direction != 'G' { return false; }

            self.sorting = Some(str);
            return true;
        }

        fn sort(&self) -> Vec<(&std::string::String, &TrafficDetail)> {
            let sort = match &self.sorting {
                Some(s) => String::from(s),
                None => { return self.traffic.iter().collect(); }
            };

            let field = sort.chars().nth(0).unwrap();
            let direction = sort.chars().nth(1).unwrap();

            let mut sorted: Vec<_> = self.traffic.iter().collect();
            match field {
                '0' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.src_ip.cmp(&b.1.src_ip)),
                    'G' => sorted.sort_by(|a, b| b.1.src_ip.cmp(&a.1.src_ip)),
                    _ => {}
                },
                '1' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.dst_ip.cmp(&b.1.dst_ip)),
                    'G' => sorted.sort_by(|a, b| b.1.dst_ip.cmp(&a.1.dst_ip)),
                    _ => {}
                },
                '2' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.src_port.cmp(&b.1.src_port)),
                    'G' => sorted.sort_by(|a, b| b.1.src_port.cmp(&a.1.src_port)),
                    _ => {}
                },
                '3' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.dst_port.cmp(&b.1.dst_port)),
                    'G' => sorted.sort_by(|a, b| b.1.dst_port.cmp(&a.1.dst_port)),
                    _ => {}
                },
                '4' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.protocols.cmp(&b.1.protocols)),
                    'G' => sorted.sort_by(|a, b| b.1.protocols.cmp(&a.1.protocols)),
                    _ => {}
                },
                '5' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.bytes.cmp(&b.1.bytes)),
                    'G' => sorted.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes)),
                    _ => {}
                },
                '6' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.npackets.cmp(&b.1.npackets)),
                    'G' => sorted.sort_by(|a, b| b.1.npackets.cmp(&a.1.npackets)),
                    _ => {}
                },
                '7' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.first_ts.cmp(&b.1.first_ts)),
                    'G' => sorted.sort_by(|a, b| b.1.first_ts.cmp(&a.1.first_ts)),
                    _ => {}
                },
                '8' => match direction {
                    'L' => sorted.sort_by(|a, b| a.1.last_ts.cmp(&b.1.last_ts)),
                    'G' => sorted.sort_by(|a, b| b.1.last_ts.cmp(&a.1.last_ts)),
                    _ => {}
                },
                _ => {}
            }
            
            sorted
        }
    }

}