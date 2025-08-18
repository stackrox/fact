#![allow(dead_code)]

use aya::Pod;
use libc::memcpy;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl path_cfg_t {
    pub fn new() -> Self {
        path_cfg_t {
            path: [0; 4096],
            len: 0,
        }
    }

    pub fn set(&mut self, path: &str) {
        let len = path.len();
        unsafe {
            memcpy(
                self.path.as_mut_ptr() as *mut _,
                path.as_ptr() as *const _,
                len,
            );
        }

        self.len = len as u16;
    }
}

impl Default for path_cfg_t {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl Pod for path_cfg_t {}
