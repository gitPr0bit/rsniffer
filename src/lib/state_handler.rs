pub mod state_handler {
    use std::sync::{Condvar, Mutex};

    pub struct StateHandler {
        mtx: Mutex<State>,
        cnd_var: Condvar
    }

    pub enum State {
        Running,
        Pausing,
        Paused,
        Stopped
    }

    impl StateHandler {
        pub fn new() -> Self {
            StateHandler {
                mtx: Mutex::new(State::Running),
                cnd_var: Condvar::new()
            }
        }

        fn run(&self) {
            // println!("state_handler::run");

            let mut state = self.mtx.lock().unwrap();
            // println!("state_handler::run - lock acquired");

            *state = State::Running;
            self.cnd_var.notify_all();
        }

        fn pause(&self) {
            // println!("state_handler::pause");

            let mut state = self.mtx.lock().unwrap();
            // println!("state_handler::pause - lock acquired");
            *state = State::Paused;

            let _res = self.cnd_var.wait_while( state, |s| {
                match *s {
                    State::Paused => true,
                    _ => false
                }
            });

            // println!("Done waiting")
        }

        fn stop(&self) {
            // println!("state_handler::stop");

            let mut state = self.mtx.lock().unwrap();
            // println!("state_handler::stop - lock acquired");

            *state = State::Stopped;
            self.cnd_var.notify_all();
        }

        pub fn state(&self) -> State {
            // println!("state_handler::state");

            let state = self.mtx.lock().unwrap();
            // println!("state_handler::state - lock acquired");

            match *state {
                State::Running => State::Running,
                State::Pausing => State::Pausing,
                State::Paused => State::Paused,
                State::Stopped => State::Stopped
            }
        }

        pub fn set_state(&self, nstate: State) {
            // println!("state_handler::set_state");

            match nstate {
                State::Running => self.run(),
                State::Pausing => {
                    let mut state = self.mtx.lock().unwrap();
                    // println!("state_handler::set_state - lock acquired");
                    *state = State::Pausing
                },
                State::Paused => self.pause(),
                State::Stopped => self.stop()
            }
        }
    }
}