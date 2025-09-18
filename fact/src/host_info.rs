use log::{debug, warn};
use std::{
    collections::HashMap,
    env,
    ffi::{c_char, CStr, CString},
    fs::{read_to_string, File},
    io::{BufRead, BufReader},
    mem,
    path::PathBuf,
    sync::LazyLock,
};

use libc::{
    clockid_t, statx, timespec, uname, AT_FDCWD, AT_NO_AUTOMOUNT, AT_STATX_SYNC_AS_STAT,
    CLOCK_BOOTTIME, CLOCK_REALTIME, STATX_INO,
};

pub fn get_host_mount() -> &'static PathBuf {
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

pub fn get_mount_ns(pid: &str) -> u64 {
    let mut file_stats = unsafe { mem::zeroed() };
    let path = PathBuf::from("/proc").join(pid).join("ns/mnt");
    let path = CString::new(path.to_str().unwrap()).unwrap();
    let path: *const c_char = path.as_ptr().cast();
    let ret = unsafe {
        statx(
            AT_FDCWD,
            path,
            AT_STATX_SYNC_AS_STAT | AT_NO_AUTOMOUNT,
            STATX_INO,
            &mut file_stats,
        )
    };

    if ret == 0 {
        debug!("Host mount namespace {}", file_stats.stx_ino);
    } else {
        panic!("Failed to get host mount namespace: {ret}");
    }

    file_stats.stx_ino
}

// get_host_mount_ns
//
// Returns a mount namespace of the host. Since we're running as a privileged
// process, it's equivalent to our mount namespace, thus extract it as an inode
// of /proc/self/ns/mnt. We should get the same result if we try to use
// /proc/1/ns/mnt .
pub fn get_host_mount_ns() -> u64 {
    get_mount_ns("self")
}

/// Get the pretty printed OS distribution name
///
/// This value is retrieved from the os-release file on the running
/// system. If the value is not found, then `Linux` is used as a generic
/// fallback.
///
/// This function is only called once, so it does not need lazy loading.
/// Please make sure to update the function if repeated calls are needed.
pub fn get_distro() -> String {
    const PRETTY_NAME: &str = "PRETTY_NAME=";
    let paths = ["etc/os-release", "usr/lib/os-release"];
    for p in paths {
        let p = get_host_mount().join(p);
        let Ok(file) = File::open(&p) else {
            debug!("Failed to open {}", p.display());
            continue;
        };
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    warn!("Failed to read line from {}: {e}", p.display());
                    break;
                }
            };

            if let Some(distro) = line.strip_prefix(PRETTY_NAME) {
                return distro.trim_matches('"').to_owned();
            }
        }
    }

    String::from("Linux")
}

const RELEASE: &str = "release";
const MACHINE: &str = "machine";

/// Retrieve information about the kernel
///
/// The kernel information is retrieved by lazily calling `uname` and
/// storing the information we care about in a hash map. This is not
/// ideal, since the LazyLock<HashMap> will live for the entirety of
/// the program's life, but the stored data is hopefully small enough
/// that not calling `uname` repeatedly makes up for it.
fn get_kernel_value(key: &str) -> Option<&String> {
    static KERNEL_DATA: LazyLock<HashMap<&str, String>> = LazyLock::new(|| {
        let mut map = HashMap::new();
        let kernel_data = unsafe {
            let mut info = mem::zeroed();
            let res = uname(&mut info);
            if res != 0 {
                warn!("Failed to execute uname: {res}");
                return map;
            }
            info
        };

        let release = unsafe { CStr::from_ptr(kernel_data.release.as_ptr()).to_str() };
        if let Ok(release) = release {
            map.insert(RELEASE, release.to_owned());
        }
        let machine = unsafe { CStr::from_ptr(kernel_data.machine.as_ptr()).to_str() };
        if let Ok(machine) = machine {
            map.insert(MACHINE, machine.to_owned());
        }

        map
    });

    KERNEL_DATA.get(key)
}

/// Same as `uname -r`
pub fn get_kernel_version() -> &'static str {
    get_kernel_value(RELEASE).map_or("", |s| s.as_str())
}

/// Same as `uname -m`
pub fn get_architecture() -> &'static str {
    get_kernel_value(MACHINE).map_or("", |s| s.as_str())
}
