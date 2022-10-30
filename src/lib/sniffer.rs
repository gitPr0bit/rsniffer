pub mod sniffer {
    use core::time;
    use pcap::{Device, Error};
    use std::{sync::{Arc, Mutex}, thread};
    use crate::lib::{capture::capture::CaptureWrapper, report::report::TrafficReport, state_handler::state_handler::{State, StateHandler}, parser::parser::{parse, parse_device}};

    const DEFAULT_INTERVAL: u64 = 5;

    pub struct SnifferBuilder {
        device: String,
        filter: String,
        interval: u64
    }

    impl SnifferBuilder {
        pub fn device(mut self, dev: String) -> SnifferBuilder {
            // Set the name on the builder itself, and return the builder by value.
            self.device = if dev.is_empty() { CaptureWrapper::default_device() } else { dev };
            self
        }

        pub fn interval(mut self, interval: u64) -> SnifferBuilder {
            // Set the name on the builder itself, and return the builder by value.
            self.interval = interval;
            self
        }

        pub fn filter(mut self, filter: String) -> SnifferBuilder {
            // Set the name on the builder itself, and return the builder by value.
            self.filter = filter;
            self
        }

        pub fn capture(self) -> Result<Sniffer, Error> {
            let sniffer = Sniffer {
                device: self.device,
                interval: self.interval,
                report: Arc::new(Mutex::new(TrafficReport::default())), 
                state: Arc::new(StateHandler::new())
            };

            match sniffer.start_capture() {
                Ok(_) => {},
                Err(e) => { return Err(Error::from(e)); }
            }
            sniffer.start_report();
            
            Ok(sniffer)
        }
    }
    
    pub struct Sniffer {
        device: String,
        report: Arc<Mutex<TrafficReport>>,
        state: Arc<StateHandler>,
        interval: u64
    }

    impl Sniffer {
        pub fn builder() -> SnifferBuilder {
            SnifferBuilder {
                device: String::new(),
                filter: String::new(),
                interval: DEFAULT_INTERVAL
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
            let mut capture = CaptureWrapper::new(String::from(&self.device));
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

        fn start_report(&self) {
            let sh_report = Arc::clone(&self.state);
            let rh_report = Arc::clone(&self.report);
            let interval = self.interval;
            
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
        
                    // println!("\nWriting report to file...");
                    rh.write();
                }
            });
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
}