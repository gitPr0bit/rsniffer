pub mod report {
    use std::{collections::HashMap, hash::Hash};

    #[derive(Debug)]
    pub struct TrafficDetail {
        pub src_ip: String,
        pub dst_ip: String,
        pub src_port: String,
        pub dst_port: String,
        pub bytes: usize
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