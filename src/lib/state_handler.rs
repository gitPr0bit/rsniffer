pub mod state_handler {
    use std::sync::{Condvar, Mutex};

    pub struct StateHandler {
        mtx: Mutex<State>,
        cnd_var: Condvar
    }

    enum State {
        Running,
        Paused,
        Stopped
    }

    impl StateHandler {
        pub fn new() -> Self {
            StateHandler {
                mtx: Mutex::new(State::Paused),
                cnd_var: Condvar::new()
            }
        }

        pub fn run(&self) {
            let mut state = self.mtx.lock().unwrap();

            *state = State::Running;
            self.cnd_var.notify_all();
        }

        pub fn pause(&self) {
            let mut state = self.mtx.lock().unwrap();

            *state = State::Paused;
            self.wait();
        }

        pub fn wait(&self) {
            let mut _state = self.mtx.lock().unwrap();

            _state = self.cnd_var.wait_while( _state, |s| {
                match *s {
                    State::Paused => true,
                    _ => false
                }
            }).unwrap();

            println!("Done waiting")
        }
    }
}