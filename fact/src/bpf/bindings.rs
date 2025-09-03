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

impl metrics_t {
    pub fn accumulate(&self, other: &metrics_t) -> metrics_t {
        let mut m = metrics_t {
            file_open: self.file_open,
        };

        m.file_open.total += other.file_open.total;
        m.file_open.added += other.file_open.added;
        m.file_open.dropped += other.file_open.dropped;
        m.file_open.ignored += other.file_open.ignored;

        m
    }
}

impl Default for metrics_t {
    fn default() -> Self {
        metrics_t {
            file_open: metrics_by_type_t {
                total: 0,
                added: 0,
                dropped: 0,
                ignored: 0,
            },
        }
    }
}

unsafe impl Pod for metrics_t {}
