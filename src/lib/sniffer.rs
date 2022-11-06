use super::capture::CaptureWrapper;
use super::parser::{parse, parse_device};
use super::state_handler::{State, StateHandler};
use super::report::{TrafficReport, DEFAULT_INTERVAL, DEFAULT_OUT};

use core::time;
use pcap::{Device, Error};
use std::{sync::{Arc, Mutex}, thread, io::Error as IOError};

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

        // Give to report details about capture configuration
        let filter = match &self.filter {
            Some(f) => Some(String::from(f)),
            None => None
        };
        report.set_filter(filter);
        report.set_interval(self.interval);

        for (i, d) in Sniffer::devices().iter().enumerate() {
            if d.name == self.device {
                report.set_device((i, String::from(&d.name)))
            }
        }

        let mut sniffer = Sniffer {
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
            interval: DEFAULT_INTERVAL,
            sorting: None,
            out: None
        }
    }

    pub fn devices() -> Vec<Device> {
        match Device::list() {
            Ok(devices) => devices,
            Err(_) => vec![]
        }
    }

    pub fn printable_devices() -> Vec<String> {
        match Device::list() {
            Ok(devices) => devices.iter().enumerate()
            .map(|d| parse_device(d.1, Some(d.0))).collect(),
            Err(e) => vec![e.to_string()]
        }
    }


    fn start_capture(&mut self) -> Result<(), Error> {
        let sh_capture = Arc::clone(&self.state);
        let rh_capture = Arc::clone(&self.report);

        // Create filter that can be moved
        let filter = match &self.filter {
            Some(f) => Some(String::from(f)),
            None => None
        };

        let mut capture = CaptureWrapper::new(String::from(&self.device), filter);
        match capture.start_capture() {
            Ok(_) => { if capture.filter().is_none() { self.filter = None; } },
            Err(e) => {return Err(e);}
        }

        // Update filter in report
        let mut report_handler = rh_capture.lock().unwrap();
        report_handler.set_filter(capture.filter());
        drop(report_handler);

        thread::spawn(move || {
            loop {
                match sh_capture.state() {
                    State::Running => match capture.start_capture() {
                        Ok(_) => {},
                        Err(e) => { 
                            // sh_capture.set_state(State::Stopped);
                            eprintln!("{:?}", e);
                            break;
                        }
                    },
                    State::Pausing | State::Paused => {
                        capture.stop_capture();
                        sh_capture.set_state(State::Paused);
                    },
                    State::Stopped => {
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
                    State::Stopped => break,
                    _ => {}
                }
    
                let mut rh = rh_report.lock().unwrap();
                rh.write().ok();

                thread::sleep(duration);
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