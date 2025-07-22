use std::sync::LazyLock;

use libc::{clockid_t, timespec, CLOCK_BOOTTIME, CLOCK_REALTIME};

fn get_clock(clockid: clockid_t) -> u64 {
    let mut tp = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let tp_ptr: *mut timespec = &mut tp;
    let res = unsafe { libc::clock_gettime(clockid, tp_ptr) };
    if res != 0 {
        panic!("Failed to get CLOCK_BOOTTIME: {res}");
    }

    (tp.tv_sec as u64 * 1_000_000_000) + tp.tv_nsec as u64
}

pub fn get_boot_time() -> u64 {
    static BOOT_TIME: LazyLock<u64> =
        LazyLock::new(|| get_clock(CLOCK_REALTIME) - get_clock(CLOCK_BOOTTIME));
    *BOOT_TIME
}
