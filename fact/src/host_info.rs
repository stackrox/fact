use std::{collections::HashMap, env, fs::read_to_string, path::PathBuf, sync::LazyLock};

use libc::{clockid_t, timespec, CLOCK_BOOTTIME, CLOCK_REALTIME};

fn get_host_mount() -> &'static PathBuf {
    static HOST_MOUNT: LazyLock<PathBuf> =
        LazyLock::new(|| env::var("FACT_HOST_MOUNT").unwrap_or("/".into()).into());
    &HOST_MOUNT
}

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
        let hostname_paths = ["etc/hostname", "proc/sys/kernel/hostname"];
        for p in hostname_paths {
            let p = get_host_mount().join(p);
            if p.exists() {
                return read_to_string(p).unwrap().trim().to_owned();
            }
        }
        String::new()
    });

    &HOSTNAME
}

pub fn get_username(uid: u32) -> &'static str {
    static USER_MAP: LazyLock<HashMap<u32, String>> = LazyLock::new(|| {
        let passwd_file = get_host_mount().join("etc/passwd");
        let passwd = read_to_string(passwd_file).unwrap_or_default();
        passwd
            .lines()
            .map(|line| {
                let mut parts = line.split(":");
                let name = parts.next().unwrap_or_default().to_owned();
                let uid = parts.nth(1).unwrap_or_default();
                let uid = uid.parse::<u32>().unwrap_or_default();

                (uid, name)
            })
            .collect()
    });
    match USER_MAP.get(&uid) {
        Some(u) => u.as_str(),
        None => "",
    }
}
