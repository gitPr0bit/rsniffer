pub mod report {
    use std::{collections::HashMap, hash::Hash};

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
        traffic: HashMap<String, TrafficDetail>
    }

    impl TrafficReport {
        pub fn new() -> Self {
            Self {
                traffic: HashMap::new()
            }
        }
    }

    // let mut traffic: HashMap<String, TrafficDetail> = HashMap::new();


}