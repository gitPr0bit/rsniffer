pub mod state_handler {
    use std::sync::{Condvar, Mutex};

    pub struct StateHandler {
        mtx: Mutex<State>,
        cnd_var: Condvar
    }

    enum State {
        Running,
        Paused
    }

    impl StateHandler {
        pub fn new() -> Self {
            StateHandler {
                mtx: Mutex::new(State::Running),
                cnd_var: Condvar::new()
            }
        }

        pub fn run(&self) {
            println!("Run");
            let mut state = self.mtx.lock().unwrap();
            println!("Run:: lock acquired");

            *state = State::Running;
            println!("Run::State running");
            self.cnd_var.notify_all();
        }

        pub fn pause(&self) {
            let mut state = self.mtx.lock().unwrap();
            println!("Pause:: lock acquired");
            *state = State::Paused;

            let _res = self.cnd_var.wait_while( state, |s| {
                match *s {
                    State::Paused => {
                        println!("--- Still paused ---");
                        true
                    },
                    _ => false
                }
            });

            println!("Done waiting")
        }
    }
}