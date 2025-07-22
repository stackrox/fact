use std::{env, fs::read_to_string, path::PathBuf, sync::LazyLock};

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

pub fn get_hostname() -> &'static str {
    static HOSTNAME: LazyLock<String> = LazyLock::new(|| {
        let host_mount: PathBuf = env::var("FACT_HOST_MOUNT").unwrap_or_default().into();
        let hostname_paths = ["/etc/hostname", "/proc/sys/kernel/hostname"];
        for p in hostname_paths {
            let p = host_mount.join(p);
            if p.exists() {
                return read_to_string(p).unwrap().trim().to_owned();
            }
        }
        String::new()
    });

    &HOSTNAME
}
