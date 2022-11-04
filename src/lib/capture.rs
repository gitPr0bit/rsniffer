pub mod capture {
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
                    Ok(active_cap) => match active_cap.setnonblock() { // TODO: try directly replacing open() with setnonblock() to see if it opens too
                        Ok(acap) => acap,
                        Err(e) => { return Err(e); }
                    },
                    Err(e) => { return Err(e); }
                },
                Err(e) => { return Err(e); }
            };

            if self.filter.is_some() {
                let filter = String::from(self.filter.as_ref().unwrap());
                capture.filter(&filter, true).ok(); // TODO: handle possible errors
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

        fn sanitize_device(dev: String) -> String {
            if dev.is_empty() { 
                Device::lookup().unwrap().unwrap().name
            } else { 
                dev 
            }
        }
    }
}