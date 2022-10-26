pub mod capture {
    use pcap::{Capture, Device, Active, Packet, Error};

    pub struct CaptureWrapper {
        device: String,
        acapture: Option<Capture<Active>>,
        running: bool
    }

    impl CaptureWrapper {
        pub fn new(dev: String) -> Self {
            Self { 
                device: Self::sanitize_device(dev),
                acapture: None,
                running: false
            }
        }
        

        pub fn start_capture(&mut self) {
            if self.running == true  {
                return;
            }

            let capture = match Capture::from_device(self.device.as_str()) {
                Ok(cap) => match cap.promisc(true).immediate_mode(true).open() {
                    Ok(active_cap) => match active_cap.setnonblock() { // TODO: try directly replacing open() with setnonblock() to see if it opens too
                        Ok(acap) => acap,
                        Err(e) => panic!("Error activating capture: {:?}", e)
                    },
                    Err(e) => panic!("Error activating capture: {:?}", e)
                },
                Err(e) => panic!("Error opening capture: {:?}", e)
            };

            self.acapture = Some(capture);
            self.running = true;
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

        fn sanitize_device(dev: String) -> String {
            if dev.is_empty() { 
                Device::lookup().unwrap().unwrap().name
            } else { 
                dev 
            }
        }
    }
}