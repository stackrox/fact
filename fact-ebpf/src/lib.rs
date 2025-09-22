#![allow(dead_code, non_camel_case_types, non_upper_case_globals)]

use std::{ffi::c_char, path::PathBuf};

use aya::{maps::lpm_trie, Pod};
use libc::memcpy;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl From<&PathBuf> for path_prefix_t {
    fn from(value: &PathBuf) -> Self {
        let filename = value.to_str().unwrap();
        let len = if filename.len() > LPM_SIZE_MAX as usize {
            LPM_SIZE_MAX as usize
        } else {
            filename.len()
        };

        unsafe {
            let mut cfg: path_prefix_t = std::mem::zeroed();
            memcpy(
                cfg.path.as_mut_ptr() as *mut _,
                filename.as_ptr() as *const _,
                len,
            );
            cfg.bit_len = (len * 8) as u32;
            cfg
        }
    }
}

impl From<path_prefix_t> for lpm_trie::Key<[c_char; LPM_SIZE_MAX as usize]> {
    fn from(value: path_prefix_t) -> Self {
        lpm_trie::Key::new(value.bit_len, value.path)
    }
}

unsafe impl Pod for path_prefix_t {}

impl metrics_by_hook_t {
    fn accumulate(&self, other: &metrics_by_hook_t) -> metrics_by_hook_t {
        let mut m = metrics_by_hook_t { ..*self };

        m.total += other.total;
        m.added += other.added;
        m.error += other.error;
        m.ignored += other.ignored;
        m.ringbuffer_full += other.ringbuffer_full;

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

pub const EBPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/main.o"));
