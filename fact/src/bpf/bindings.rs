#![allow(dead_code)]

use aya::Pod;
use libc::memcpy;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl path_cfg_t {
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

unsafe impl Pod for path_cfg_t {}

impl metrics_by_hook_t {
    fn accumulate(&self, other: &metrics_by_hook_t) -> metrics_by_hook_t {
        let mut m = metrics_by_hook_t { ..*self };

        m.total += other.total;
        m.added += other.added;
        m.dropped += other.dropped;
        m.ignored += other.ignored;

        m
    }
}

impl metrics_t {
    pub fn accumulate(&self, other: &metrics_t) -> metrics_t {
        let mut m = metrics_t { ..*self };
        m.file_open = m.file_open.accumulate(&other.file_open);
        m
    }
}

unsafe impl Pod for metrics_t {}
