//! This crate is aimed at generating a textual report of the network traffic
//! captured by a chosen device (in promiscuous mode), with chosen capture criteria,
//! to a file of choice. The library also gives the ability to pause, resume or stop
//! the capture at any time.

#[doc(hidden)]
mod report;

#[doc(hidden)]
mod parser;

#[doc(hidden)]
mod capture;

#[doc(hidden)]
mod state_handler;

use capture::CaptureWrapper;
use parser::{parse, parse_device};
use state_handler::{State, StateHandler};
use report::{TrafficReport, DEFAULT_INTERVAL, DEFAULT_OUT};

use core::time;
use pcap::{Device, Error};
use std::{sync::{Arc, Mutex}, thread::{self, JoinHandle}, io::Error as IOError, fmt};

/// Builder used to configure, build and start a Sniffer
pub struct SnifferBuilder {
    device: String,
    out: Option<String>,
    filter: Option<String>,
    interval: u64,
    sorting: Option<String>
}

impl SnifferBuilder {
    /// Sets the device name on the builder itself, and returns the builder by value.
    /// If an empty String is given, relies on pcap to set default device for the capture.
    /// 
    /// #Examples
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut device_name = String::from("eth0");
    /// 
    /// let mut builder = Sniffer::builder();
    /// builder = builder.device(device_name);
    /// ```
    /// 
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut devices = match Sniffer::devices() {
    ///     Ok(devs) => devs,
    ///     Err(e) => vec![]
    /// };
    /// 
    /// // Try to start capturing with device having ID 1
    /// if devices.len() > 1 {
    ///     let dev = String::from(&devices[1].name);
    ///     let sniffer = Sniffer::builder().device(dev).capture();
    ///     assert!(sniffer.is_ok(), "Capture started successfully!");
    /// }
    /// ```
    pub fn device(mut self, dev: String) -> SnifferBuilder {
        self.device = if dev.is_empty() { CaptureWrapper::default_device() } else { dev };
        self
    }

    /// Sets the time interval on the builder itself, and returns the builder by value.
    /// 
    /// #Example
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut builder = Sniffer::builder();
    /// builder = builder.interval(5);
    /// ```
    pub fn interval(mut self, interval: u64) -> SnifferBuilder {
        self.interval = interval;
        self
    }

    /// Sets the output file name on the builder itself, and returns the builder by value.
    ///  
    /// #Example
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut file = Some(String::from("report.txt"));
    /// 
    /// let mut builder = Sniffer::builder();
    /// builder = builder.out(file);
    /// ```
    pub fn out(mut self, out_path: Option<String>) -> SnifferBuilder {
        self.out = out_path;
        self
    }

    /// Sets the filter on the builder itself, and returns the builder by value.
    ///  
    /// #Example
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut file = Some(String::from("tcp dst port 443"));
    /// 
    /// let mut builder = Sniffer::builder();
    /// builder = builder.out(file);
    /// ```
    pub fn filter(mut self, filter: Option<String>) -> SnifferBuilder {
        self.filter = filter;
        self
    }

    /// Sets the sorting criteria on the builder itself, and returns the builder by value.
    ///  
    /// #Example
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut sorting = Some(String::from("5L"));
    /// 
    /// let mut builder = Sniffer::builder();
    /// builder = builder.sort(sorting);
    /// ```
    /// 
    pub fn sort(mut self, sort: Option<String>) -> SnifferBuilder {
        self.sorting = sort;
        self
    }

    /// Builds the Sniffer as previously configured, starts the capture, and returns a
    /// Result containing either the Sniffer or a SnifferError (in case something goes
    /// wrong while creating the sniffer or starting the capture)
    /// 
    /// #Examples
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// // Get a sniffer with default configuration
    /// let mut sniffer = match Sniffer::builder().capture() {
    ///     Ok(s) => s,
    ///     Err(e) => { 
    ///         eprintln!("Something went wrong... {}", e.to_string());
    ///         return;
    ///     }
    /// };
    /// ```
    /// 
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut sorting = Some(String::from("5L"));
    /// 
    /// let mut sniffer = Sniffer::builder().sort(sorting)
    ///                                     .interval(10)
    ///                                     .capture();
    /// assert!(sniffer.is_ok(), "Capture started successfully!");
    /// ```
    /// 
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut device = String::from("fake_device");
    /// 
    /// let sniffer = Sniffer::builder().device(device)
    ///                                 .interval(10)
    ///                                 .capture();
    /// assert!(sniffer.is_err(), "Device does not exist!");
    /// ```
    pub fn capture(self) -> Result<Sniffer, SnifferError> {
        let mut report =  match &self.out {
            Some(file_path) => TrafficReport::new(String::from(file_path)),
            None => TrafficReport::default()
        };

        // Set sorting criteria for report
        if self.sorting.is_some() && report.set_sorting(self.sorting) == false {
            let msg = String::from("Invalid sorting criteria.");
            return Err(SnifferError::new(msg));
        }

        // Give to report details about capture configuration
        let filter = match &self.filter {
            Some(f) => Some(String::from(f)),
            None => None
        };
        report.set_filter(filter);
        report.set_interval(self.interval);

        match Sniffer::devices() {
            Ok(devs) => {
                for (i, d) in devs.iter().enumerate() {
                    if d.name == self.device {
                        report.set_device((i, String::from(&d.name)))
                    }
                }
            },
            Err(e) => { return Err(SnifferError::new(e.to_string())); }
        };

        let mut sniffer = Sniffer {
            device: self.device,
            interval: self.interval,
            filter: self.filter,
            report: Arc::new(Mutex::new(report)), 
            state: Arc::new(StateHandler::new()),
            report_thread: None,
            capture_thread: None
        };

        if let Err(e) = sniffer.start_capture() {
            return Err(SnifferError::new(e.to_string()));
        }

        if let Err(_) = sniffer.start_report() {
            let out = match &self.out {
                Some(out_file) => String::from(out_file),
                None => format!(" {}", DEFAULT_OUT)
            };
            let message = format!("Something went wrong trying to write the report to {}. \
                Please check that a valid path was specified and that you have write permissions for the target directory.", out);
            return Err(SnifferError::new(message)); 
        }
        
        Ok(sniffer)
    }
}

/// Handles traffic capture and report writing
pub struct Sniffer {
    interval: u64,
    device: String,
    filter: Option<String>,
    state: Arc<StateHandler>,
    report: Arc<Mutex<TrafficReport>>,
    report_thread: Option<JoinHandle<()>>,
    capture_thread: Option<JoinHandle<()>>
}

impl Sniffer {
    /// Returns a SnifferBuilder, used to setup Sniffer's configuration,
    /// then build the Sniffer and start it capturing and reporting 
    /// 
    /// #Example
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// let mut sniffer = Sniffer::builder().interval(10)
    ///                                     .capture();
    /// assert!(sniffer.is_ok(), "Capture started successfully!");
    /// ```
    pub fn builder() -> SnifferBuilder {
        SnifferBuilder {
            device: String::new(),
            filter: None,
            interval: DEFAULT_INTERVAL,
            sorting: None,
            out: None
        }
    }

    /// Returns a Vec with all the devices available for
    /// the capture
    pub fn devices() -> Result<Vec<Device>, SnifferError> {
        match Device::list() {
            Ok(devices) => Ok(devices),
            Err(e) => Err(SnifferError::new(e.to_string()))
        }
    }

    /// Returns a Vec with the names of all the devices
    /// available for the capture
    pub fn printable_devices() -> Result<Vec<String>, SnifferError> {
        match Device::list() {
            Ok(devices) => Ok(devices.iter().enumerate()
                        .map(|d| parse_device(d.1, Some(d.0))).collect()),
            Err(e) => Err(SnifferError::new(e.to_string()))
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

        self.capture_thread = Some(thread::spawn(move || {
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
        }));

        Ok(())
    }

    fn start_report(&mut self) -> Result<(), IOError> {
        let sh_report = Arc::clone(&self.state);
        let rh_report = Arc::clone(&self.report);
        let interval = self.interval;

        let res = self.report.lock().unwrap().write();
        if res.is_err() {
            return res;
        }
        
        self.report_thread = Some(thread::spawn(move || {
            let duration = time::Duration::from_secs(interval);
    
            loop {
                thread::sleep(duration);

                match sh_report.state() {
                    State::Pausing | State::Paused => sh_report.set_state(State::Paused),
                    State::Stopped => break,
                    _ => {}
                }
    
                let mut rh = rh_report.lock().unwrap();
                rh.write().ok();
            }
        }));

        Ok(())
    }

    /// Returns the name of the device used for capture
    pub fn device(&self) -> String {
        String::from(&self.device)
    }

    /// Resumes Sniffer (capturing and reporting)
    pub fn resume(&self) {
        self.state.set_state(State::Running);
    }
    
    /// Pauses Sniffer (capturing and reporting)
    pub fn pause(&self) {
        self.state.set_state(State::Pausing);
    }

    /// Stops Sniffer (capturing and reporting) and consumes it.
    /// After stop, nothing else can be done with the Sniffer.
    /// 
    /// #Example
    /// ```
    /// use snifferlib::Sniffer;
    /// 
    /// if let Ok(sniffer) = Sniffer::builder().interval(10)
    ///                                        .capture() {
    ///     // Stop the sniffer when you are done
    ///     sniffer.stop();
    /// 
    ///     // Uncommenting the following line lets the borrow checker prevent compilation
    ///     // sniffer.resume();
    /// }
    /// ```
    pub fn stop(self) {
        self.state.set_state(State::Stopped);
        
        // wait for capture and report threads
        if let Some(report_thread) = self.report_thread {
            report_thread.join().ok();
        }

        if let Some(capture_thread) = self.capture_thread {
            capture_thread.join().ok();
        }
    }
}

#[derive(Debug)]
pub struct SnifferError {
    msg: String
}

impl fmt::Display for SnifferError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl SnifferError {
    pub fn new(str: String) -> Self {
        Self {
            msg: str
        }
    }
}