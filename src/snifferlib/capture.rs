use pcap::{Capture, Device, Active, Packet, Error};

pub struct CaptureWrapper {
    device: String,
    filter: Option<String>,
    acapture: Option<Capture<Active>>,
    running: bool
}

impl CaptureWrapper {
    pub fn new(dev: String, filter: Option<String>) -> Self {
        Self { 
            device: Self::sanitize_device(dev),
            filter: filter,
            acapture: None,
            running: false
        }
    }
    

    pub fn start_capture(&mut self) -> Result<(), Error> {
        if self.running == true  {
            return Ok(());
        }

        let mut capture = match Capture::from_device(self.device.as_str()) {
            Ok(cap) => match cap.promisc(true).immediate_mode(true).open() {
                Ok(active_cap) => match active_cap.setnonblock() {
                    Ok(acap) => acap,
                    Err(e) => { return Err(e); }
                },
                Err(e) => { return Err(e); }
            },
            Err(e) => { return Err(e); }
        };

        if self.filter.is_some() {
            let filter = String::from(self.filter.as_ref().unwrap());
            if capture.filter(&filter, true).is_err() {
                self.filter = Some(format!("{} [{}]", filter, "ignored because invalid"));
            };
        }

        self.acapture = Some(capture);
        self.running = true;

        Ok(())
    }


    pub fn stop_capture(&mut self) {
        if self.running == false {
            return;
        }

        self.running = false;
        match &self.acapture {
            Some(cap) => {
                drop(cap);
                self.acapture = None;
            }
            None => {}
        }
    }


    pub fn next(&mut self) -> Result<Packet, Error> {
        match &mut self.acapture {
            Some(cap) => cap.next_packet(),
            None => panic!("There's no active capture!")
        }
    }

    pub fn active(&self) -> bool {
        self.running
    }

    pub fn default_device() -> String {
        Device::lookup().unwrap().unwrap().name
    }

    pub fn filter(&self) -> Option<String> {
        match &self.filter {
            Some(f) => Some(String::from(f)),
            None => None
        }
    }

    fn sanitize_device(dev: String) -> String {
        if dev.is_empty() { 
            Device::lookup().unwrap().unwrap().name
        } else { 
            dev 
        }
    }
}