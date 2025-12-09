use anyhow::bail;
use log::{debug, warn};
use std::{
    collections::HashMap,
    env,
    ffi::{c_char, CStr, CString},
    fs::{read_to_string, File},
    io::{BufRead, BufReader},
    mem,
    path::{Path, PathBuf},
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

pub fn prepend_host_mount(path: &Path) -> PathBuf {
    let path = if path.has_root() {
        path.strip_prefix(Path::new("/")).unwrap()
    } else {
        path
    };
    get_host_mount().join(path)
}

pub fn remove_host_mount(path: &Path) -> PathBuf {
    let host_mount = get_host_mount();
    if path.starts_with(host_mount) {
        let path = path.strip_prefix(host_mount).unwrap();
        Path::new("/").join(path)
    } else {
        path.to_path_buf()
    }
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
                match read_to_string(&p) {
                    Ok(hostname) => return hostname.trim().to_owned(),
                    Err(e) => warn!("Failed to read {}: {e}", p.display()),
                }
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

pub struct SystemInfo {
    pub kernel: String,
    pub arch: String,
}

impl SystemInfo {
    pub fn new() -> anyhow::Result<Self> {
        let system_info = unsafe {
            let mut info = mem::zeroed();
            let res = uname(&mut info);
            if res != 0 {
                bail!(
                    "Failed to execute uname: {}",
                    std::io::Error::last_os_error()
                );
            }
            info
        };

        let kernel = unsafe { CStr::from_ptr(system_info.release.as_ptr()) }
            .to_string_lossy()
            .to_string();
        let arch = unsafe { CStr::from_ptr(system_info.machine.as_ptr()) }
            .to_string_lossy()
            .to_string();

        Ok(SystemInfo { kernel, arch })
    }
}
