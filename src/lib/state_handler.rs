use std::sync::{Condvar, Mutex};

pub struct StateHandler {
    mtx: Mutex<State>,
    cnd_var: Condvar
}

pub enum State {
    Running,
    Pausing,
    Paused,
    Stopped,
    Dead
}

impl StateHandler {
    pub fn new() -> Self {
        StateHandler {
            mtx: Mutex::new(State::Running),
            cnd_var: Condvar::new()
        }
    }

    fn run(&self) {
        let mut state = self.mtx.lock().unwrap();

        *state = State::Running;
        self.cnd_var.notify_all();
    }

    fn pause(&self) {
        let mut state = self.mtx.lock().unwrap();
        
        *state = State::Paused;
        
        // Wait while paused
        let _res = self.cnd_var.wait_while( state, |s| {
            match *s {
                State::Paused => true,
                _ => false
            }
        });
    }

    fn stop(&self) {
        let mut state = self.mtx.lock().unwrap();

        *state = State::Stopped;
        self.cnd_var.notify_all();
    }

    pub fn state(&self) -> State {
        let state = self.mtx.lock().unwrap();

        match *state {
            State::Running => State::Running,
            State::Pausing => State::Pausing,
            State::Paused => State::Paused,
            State::Stopped => State::Stopped,
            State::Dead => State::Dead // TODO: check if really useful
        }
    }

    pub fn set_state(&self, nstate: State) {
        match nstate {
            State::Running => self.run(),
            State::Pausing => {
                let mut state = self.mtx.lock().unwrap();
                *state = State::Pausing
            },
            State::Paused => self.pause(),
            State::Stopped => self.stop(),
            State::Dead => { 
                let mut state = self.mtx.lock().unwrap();
                *state = State::Dead 
            }
        }
    }
}