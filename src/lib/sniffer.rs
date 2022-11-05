pub mod sniffer {
    use core::time;
    use pcap::{Device, Error};
    use std::{sync::{Arc, Mutex}, thread, io::Error as IOError};
    use crate::lib::{capture::capture::CaptureWrapper, report::report::{TrafficReport, TIME_INTERVAL, DEFAULT_OUT}, state_handler::state_handler::{State, StateHandler}, parser::parser::{parse, parse_device}};

    pub struct SnifferBuilder {
        device: String,
        out: Option<String>,
        filter: Option<String>,
        interval: u64,
        sorting: Option<String>
    }

    impl SnifferBuilder {
        pub fn device(mut self, dev: String) -> SnifferBuilder {
            // Set the device on the builder itself, and return the builder by value.
            self.device = if dev.is_empty() { CaptureWrapper::default_device() } else { dev };
            self
        }

        pub fn interval(mut self, interval: u64) -> SnifferBuilder {
            // Set the interval on the builder itself, and return the builder by value.
            self.interval = interval;
            self
        }

        pub fn out(mut self, out_path: Option<String>) -> SnifferBuilder {
            // Set the output file on the builder itself, and return the builder by value.
            self.out = out_path;
            self
        }

        pub fn filter(mut self, filter: Option<String>) -> SnifferBuilder {
            // Set the name on the builder itself, and return the builder by value.
            self.filter = filter;
            self
        }

        pub fn sort(mut self, sort: Option<String>) -> SnifferBuilder {
            // Set the name on the builder itself, and return the builder by value.
            self.sorting = sort;
            self
        }

        pub fn capture(self) -> Result<Sniffer, CustomError> {
            let mut report =  match &self.out {
                Some(file_path) => TrafficReport::new(String::from(file_path)),
                None => TrafficReport::default()
            };

            // Set sorting criteria for report
            if self.sorting.is_some() && report.set_sorting(self.sorting) == false {
                panic!("Invalid sorting criteria");
            }

            let sniffer = Sniffer {
                device: self.device,
                interval: self.interval,
                filter: self.filter,
                report: Arc::new(Mutex::new(report)), 
                state: Arc::new(StateHandler::new())
            };

            if let Err(e) = sniffer.start_capture() {
                return Err(CustomError::new(e.to_string()));
            }

            if let Err(_) = sniffer.start_report() {
                let out = match &self.out {
                    Some(out_file) => String::from(out_file),
                    None => format!(" {}", DEFAULT_OUT)
                };
                let message = format!("Something went wrong trying to write the report to{}. \
                    Please check that a valid path was specified and that you have write permissions for the target directory.", out);
                return Err(CustomError::new(message)); 
            }
            
            Ok(sniffer)
        }
    }
    
    pub struct Sniffer {
        device: String,
        report: Arc<Mutex<TrafficReport>>,
        state: Arc<StateHandler>,
        interval: u64,
        filter: Option<String>
    }

    impl Sniffer {
        pub fn builder() -> SnifferBuilder {
            SnifferBuilder {
                device: String::new(),
                filter: None,
                interval: TIME_INTERVAL,
                sorting: None,
                out: None
            }
        }

        pub fn devices() -> Vec<Device> {
            match Device::list() {
                Ok(devices) => devices,
                Err(e) => vec![]
            }
        }

        pub fn printable_devices() -> Vec<String> {
            match Device::list() {
                Ok(devices) => devices.iter().enumerate()
                .map(|d| parse_device(d.1, Some(d.0))).collect(),
                Err(e) => vec![e.to_string()]
            }
        }


        fn start_capture(&self) -> Result<(), Error> {
            let sh_capture = Arc::clone(&self.state);
            let rh_capture = Arc::clone(&self.report);

            // Create filter that can be moved
            let filter = match &self.filter {
                Some(f) => Some(String::from(f)),
                None => None
            };

            let mut capture = CaptureWrapper::new(String::from(&self.device), filter);
            match capture.start_capture() {
                Ok(_) => {},
                Err(e) => {return Err(e);}
            }

            thread::spawn(move || {
                let _raii = StateRAII{ state: Arc::clone(&sh_capture) };
                loop {
                    match sh_capture.state() {
                        State::Running => match capture.start_capture() {
                            Ok(_) => {},
                            Err(e) => { 
                                // sh_capture.set_state(State::Stopped);
                                println!("{:?}", e);
                                break;
                             }
                        },
                        State::Pausing | State::Paused => {
                            capture.stop_capture();
                            sh_capture.set_state(State::Paused);
                        },
                        State::Stopped | State::Dead => {
                            capture.stop_capture();
                            break
                        }
                    }
        
                    if capture.active() {
                        if let Ok(packet) = capture.next() { // handle errors
                            let parsed = parse(&packet);
                            let mut rh = rh_capture.lock().unwrap();
                            rh.new_detail(parsed);
                        }
                    }
                }
            });

            Ok(())
        }

        fn start_report(&self) -> Result<(), IOError> {
            let sh_report = Arc::clone(&self.state);
            let rh_report = Arc::clone(&self.report);
            let interval = self.interval;

            let res = self.report.lock().unwrap().write();
            if res.is_err() {
                return res;
            }
            
            thread::spawn(move || {
                let duration = time::Duration::from_secs(interval);
        
                loop {
                    match sh_report.state() {
                        State::Pausing | State::Paused => sh_report.set_state(State::Paused),
                        State::Stopped | State::Dead => break,
                        _ => {}
                    }
        
                    thread::sleep(duration);
                    let mut rh = rh_report.lock().unwrap();
        
                    rh.write();
                }
            });

            Ok(())
        }

        pub fn device(&self) -> String {
            String::from(&self.device)
        }

        pub fn resume(&self) {
            self.state.set_state(State::Running);
        }
        
        pub fn pause(&self) {
            self.state.set_state(State::Pausing);
        }

        pub fn stop(&self) {
            self.state.set_state(State::Stopped);
        }

        pub fn dead(&self) -> bool {
            match self.state.state() {
                State::Dead => true,
                _ => false
            }
        }
    }

    struct StateRAII {
        state: Arc<StateHandler>
    }

    impl Drop for StateRAII {
        fn drop(&mut self) {
            self.state.set_state(State::Dead);
        }
    }
    
    #[derive(Debug)]
    pub struct CustomError {
        msg: String
    }

    impl CustomError {
        pub fn new(str: String) -> Self {
            Self {
                msg: str
            }
        }

        pub fn to_string(&self) -> String {
            String::from(&self.msg)
        }
    }
}