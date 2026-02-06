use std::{ffi::CStr, path::PathBuf};

use fact_ebpf::{lineage_t, process_t};
use serde::Serialize;
use uuid::Uuid;

use crate::host_info;

use super::{sanitize_d_path, slice_to_string};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Lineage {
    uid: u32,
    exe_path: PathBuf,
}

impl TryFrom<&lineage_t> for Lineage {
    type Error = anyhow::Error;

    fn try_from(value: &lineage_t) -> Result<Self, Self::Error> {
        let lineage_t { uid, exe_path } = value;
        let exe_path = sanitize_d_path(exe_path);

        Ok(Lineage {
            uid: *uid,
            exe_path,
        })
    }
}

impl From<Lineage> for fact_api::process_signal::LineageInfo {
    fn from(value: Lineage) -> Self {
        let Lineage { uid, exe_path } = value;
        Self {
            parent_uid: uid,
            parent_exec_file_path: exe_path.to_string_lossy().to_string(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Process {
    comm: String,
    args: Vec<String>,
    exe_path: PathBuf,
    container_id: Option<String>,
    uid: u32,
    username: &'static str,
    gid: u32,
    login_uid: u32,
    pid: u32,
    in_root_mount_ns: bool,
    lineage: Vec<Lineage>,
}

impl Process {
    /// Create a representation of the current process as best as
    /// possible.
    #[cfg(test)]
    pub fn current() -> Self {
        use crate::host_info::{get_host_mount_ns, get_mount_ns};

        let exe_path = std::env::current_exe().expect("Failed to get current exe");
        let args = std::env::args().collect::<Vec<_>>();
        let cgroup = std::fs::read_to_string("/proc/self/cgroup").expect("Failed to read cgroup");
        let container_id = Process::extract_container_id(&cgroup);
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let pid = std::process::id();
        let login_uid = std::fs::read_to_string("/proc/self/loginuid")
            .expect("Failed to read loginuid")
            .parse()
            .expect("Failed to parse login_uid");

        let in_root_mount_ns = get_host_mount_ns() == get_mount_ns(&pid.to_string(), false);

        Self {
            comm: "".to_string(),
            args,
            exe_path,
            container_id,
            uid,
            username: "",
            gid,
            login_uid,
            pid,
            in_root_mount_ns,
            lineage: vec![],
        }
    }

    fn extract_container_id(cgroup: &str) -> Option<String> {
        let cgroup = if let Some(i) = cgroup.rfind(".scope") {
            cgroup.split_at(i).0
        } else {
            cgroup
        };

        if cgroup.is_empty() || cgroup.len() < 65 {
            return None;
        }

        let cgroup = cgroup.split_at(cgroup.len() - 65).1;
        let (c, cgroup) = cgroup.split_at(1);
        if c != "/" && c != "-" {
            return None;
        }

        if cgroup.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(cgroup.split_at(12).0.to_owned())
        } else {
            None
        }
    }
}

#[cfg(test)]
impl PartialEq for Process {
    fn eq(&self, other: &Self) -> bool {
        self.uid == other.uid
            && self.login_uid == other.login_uid
            && self.gid == other.gid
            && self.exe_path == other.exe_path
            && self.args == other.args
            && self.container_id == other.container_id
            && self.in_root_mount_ns == other.in_root_mount_ns
    }
}

impl TryFrom<process_t> for Process {
    type Error = anyhow::Error;

    fn try_from(value: process_t) -> Result<Self, Self::Error> {
        let comm = slice_to_string(value.comm.as_slice())?;
        let exe_path = sanitize_d_path(value.exe_path.as_slice());
        let memory_cgroup = unsafe { CStr::from_ptr(value.memory_cgroup.as_ptr()) }.to_str()?;
        let container_id = Process::extract_container_id(memory_cgroup);
        let in_root_mount_ns = value.in_root_mount_ns != 0;

        let lineage = value.lineage[..value.lineage_len as usize]
            .iter()
            .map(Lineage::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut converted_args = Vec::new();
        let args_len = value.args_len as usize;
        let mut offset = 0;
        while offset < args_len {
            let arg = unsafe { CStr::from_ptr(value.args.as_ptr().add(offset)) }
                .to_str()?
                .to_owned();
            if arg.is_empty() {
                break;
            }
            offset += arg.len() + 1;
            converted_args.push(arg);
        }

        let username = host_info::get_username(value.uid);

        Ok(Process {
            comm,
            args: converted_args,
            exe_path,
            container_id,
            uid: value.uid,
            username,
            gid: value.gid,
            login_uid: value.login_uid,
            pid: value.pid,
            in_root_mount_ns,
            lineage,
        })
    }
}

impl From<Process> for fact_api::ProcessSignal {
    fn from(value: Process) -> Self {
        let Process {
            comm,
            args,
            exe_path,
            container_id,
            uid,
            username,
            gid,
            login_uid,
            pid,
            in_root_mount_ns,
            lineage,
        } = value;

        let container_id = container_id.unwrap_or("".to_string());

        let args = args
            .into_iter()
            .reduce(|acc, i| acc + " " + &i)
            .unwrap_or("".to_owned());

        Self {
            id: Uuid::new_v4().to_string(),
            container_id,
            creation_time: None,
            name: comm,
            args,
            exec_file_path: exe_path.to_string_lossy().to_string(),
            pid,
            uid,
            gid,
            scraped: false,
            lineage_info: lineage
                .into_iter()
                .map(fact_api::process_signal::LineageInfo::from)
                .collect(),
            login_uid,
            username: username.to_owned(),
            in_root_mount_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::test_utils::*;
    use std::os::raw::c_char;

    /// Helper to create a default process_t for testing
    fn default_process_t() -> process_t {
        process_t {
            comm: string_to_c_char_array::<16>("test"),
            args: string_to_c_char_array::<4096>("arg1\0arg2\0"),
            args_len: 10,
            exe_path: string_to_c_char_array::<4096>("/usr/bin/test"),
            memory_cgroup: string_to_c_char_array::<4096>("init.scope"),
            uid: 1000,
            gid: 1000,
            login_uid: 1000,
            pid: 12345,
            lineage: [lineage_t {
                uid: 1000,
                exe_path: string_to_c_char_array::<4096>("/bin/bash"),
            }; 2],
            lineage_len: 0,
            in_root_mount_ns: 1,
        }
    }

    #[test]
    fn extract_container_id() {
        let tests = [
            ("", None),
            ("init.scope", None),
            (
                "/docker/951e643e3c241b225b6284ef2b79a37c13fc64cbf65b5d46bda95fcb98fe63a4",
                Some("951e643e3c24".to_string()),
            ),
            (
                "/kubepods/kubepods/besteffort/pod690705f9-df6e-11e9-8dc5-025000000001/c3bfd81b7da0be97190a74a7d459f4dfa18f57c88765cde2613af112020a1c4b",
                Some("c3bfd81b7da0".to_string()),
            ),
            (
                "/kubepods/burstable/pod7cd3dba6-e475-11e9-8f99-42010a8a00d2/2bc55a8cae1704a733ba5d785d146bbed9610483380507cbf00c96b32bb637e1",
                Some("2bc55a8cae17".to_string()),
            ),
            (
              "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podce705797_e47e_11e9_bd71_42010a000002.slice/docker-6525e65814a99d431b6978e8f8c895013176c6c58173b56639d4b020c14e6022.scope",
              Some("6525e65814a9".to_string()),
            ),
            (
                "/machine.slice/libpod-b6e375cfe46efa5cd90d095603dec2de888c28b203285819233040b5cf1212ac.scope/container",
                Some("b6e375cfe46e".to_string()),
            ),
            (
              "/machine.slice/libpod-cbdfa0f1f08763b1963c30d98e11e1f052cb67f1e9b7c0ab8a6ca6c70cbcad69.scope/container/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod6eab3b7b_f0a6_4bb8_bff2_d5bc9017c04b.slice/cri-containerd-5ebf11e02dbde102cda4b76bc0e3849a65f9edac7a12bdabfd34db01b9556101.scope",
              Some("5ebf11e02dbd".to_string()),
            ),
        ];

        for (input, expected) in tests {
            let id = Process::extract_container_id(input);
            assert_eq!(id, expected);
        }
    }

    #[test]
    fn process_conversion_valid_utf8_comm() {
        let tests = [
            ("test", "ASCII"),
            ("тест", "Cyrillic"),
            ("测试", "Chinese"),
            ("app🚀", "emoji"),
        ];

        for (comm, description) in tests {
            let mut proc = default_process_t();
            proc.comm = string_to_c_char_array::<16>(comm);
            let result = Process::try_from(proc);
            assert!(result.is_ok(), "Failed for {}", description);
            assert_eq!(result.unwrap().comm, comm, "Failed for {}", description);
        }
    }

    #[test]
    fn process_conversion_invalid_utf8_comm() {
        let tests: &[(&[u8], &str)] = &[
            (&[b't', b'e', b's', b't', 0xFF, 0xFE], "invalid bytes"),
            (
                &[b'a', b'p', b'p', 0xE2, 0x80],
                "truncated multi-byte sequence",
            ),
        ];

        for (bytes, description) in tests {
            let mut proc = default_process_t();
            proc.comm = bytes_to_c_char_array::<16>(bytes);
            let result = Process::try_from(proc);
            assert!(result.is_err(), "Should fail for {}", description);
        }
    }

    #[test]
    fn process_conversion_valid_utf8_exe_path() {
        let tests = [
            ("/usr/bin/test", "ASCII"),
            ("/usr/bin/тест", "Cyrillic"),
            ("/opt/应用/测试", "Chinese"),
            ("/home/user/🚀app", "emoji"),
            ("/var/app-данные-数据/bin", "mixed UTF-8"),
        ];

        for (path, description) in tests {
            let mut proc = default_process_t();
            proc.exe_path = string_to_c_char_array::<4096>(path);
            let result = Process::try_from(proc);
            assert!(result.is_ok(), "Failed for {}", description);
            assert_eq!(
                result.unwrap().exe_path,
                PathBuf::from(path),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn process_conversion_invalid_utf8_exe_path() {
        let mut proc = default_process_t();
        proc.exe_path = bytes_to_c_char_array::<4096>(&[
            b'/', b'u', b's', b'r', b'/', b'b', b'i', b'n', b'/', 0xFF, 0xFE,
        ]);
        let result = Process::try_from(proc);
        assert!(result.is_ok());
        let exe_path = result.unwrap().exe_path;
        assert!(exe_path.to_string_lossy().contains("/usr/bin/"));
        assert!(exe_path.to_string_lossy().contains('\u{FFFD}'));
    }

    #[test]
    fn process_conversion_valid_utf8_args() {
        let tests: &[(&str, Vec<&str>, &str)] = &[
            ("arg1\0arg2\0arg3\0", vec!["arg1", "arg2", "arg3"], "ASCII"),
            ("файл\0данные\0", vec!["файл", "данные"], "Cyrillic"),
            (
                "测试\0文件\0数据\0",
                vec!["测试", "文件", "数据"],
                "Chinese",
            ),
            (
                "app\0🚀file\0📁data\0",
                vec!["app", "🚀file", "📁data"],
                "emoji",
            ),
            (
                "test\0файл\0测试\0🚀\0",
                vec!["test", "файл", "测试", "🚀"],
                "mixed UTF-8",
            ),
        ];

        for (args_str, expected, description) in tests {
            let mut proc = default_process_t();
            proc.args = string_to_c_char_array::<4096>(args_str);
            proc.args_len = args_str.len() as u32;
            let result = Process::try_from(proc);
            assert!(result.is_ok(), "Failed for {}", description);
            assert_eq!(
                result.unwrap().args,
                *expected,
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn process_conversion_invalid_utf8_args() {
        let tests: &[(&[u8], u32, &str)] = &[
            (
                &[b'a', b'r', b'g', b'1', 0, 0xFF, 0xFE, b'a', b'r', b'g', 0],
                11,
                "invalid bytes",
            ),
            (
                &[b't', b'e', b's', b't', 0, 0xE2, 0x80, 0],
                8,
                "truncated multi-byte sequence",
            ),
        ];

        for (bytes, args_len, description) in tests {
            let mut proc = default_process_t();
            proc.args = bytes_to_c_char_array::<4096>(bytes);
            proc.args_len = *args_len;
            let result = Process::try_from(proc);
            assert!(result.is_err(), "Should fail for {}", description);
        }
    }

    #[test]
    fn process_conversion_valid_utf8_memory_cgroup() {
        let tests = [
            ("init.scope", None, "ASCII init.scope"),
            (
                "/docker/951e643e3c241b225b6284ef2b79a37c13fc64cbf65b5d46bda95fcb98fe63a4",
                Some("951e643e3c24"),
                "container ID",
            ),
        ];

        for (cgroup, expected_id, description) in tests {
            let mut proc = default_process_t();
            proc.memory_cgroup = string_to_c_char_array::<4096>(cgroup);
            let result = Process::try_from(proc);
            assert!(result.is_ok(), "Failed for {}", description);
            assert_eq!(
                result.unwrap().container_id,
                expected_id.map(|s| s.to_string()),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn process_conversion_invalid_utf8_memory_cgroup() {
        let mut proc = default_process_t();
        proc.memory_cgroup = bytes_to_c_char_array::<4096>(&[
            b'/', b'd', b'o', b'c', b'k', b'e', b'r', b'/', 0xFF, 0xFE,
        ]);
        let result = Process::try_from(proc);
        assert!(result.is_err());
    }

    #[test]
    fn process_conversion_valid_utf8_lineage() {
        let tests = [
            ("/bin/bash", "ASCII"),
            ("/usr/bin/тест", "Cyrillic"),
            ("/opt/应用", "Chinese"),
        ];

        for (path, description) in tests {
            let mut proc = default_process_t();
            proc.lineage[0] = lineage_t {
                uid: 1000,
                exe_path: string_to_c_char_array::<4096>(path),
            };
            proc.lineage_len = 1;
            let result = Process::try_from(proc);
            assert!(result.is_ok(), "Failed for {}", description);
            let lineage = result.unwrap().lineage;
            assert_eq!(lineage.len(), 1);
            assert_eq!(
                lineage[0].exe_path,
                PathBuf::from(path),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn process_conversion_invalid_utf8_lineage() {
        let mut proc = default_process_t();
        proc.lineage[0] = lineage_t {
            uid: 1000,
            exe_path: bytes_to_c_char_array::<4096>(&[b'/', b'b', b'i', b'n', b'/', 0xFF, 0xFE]),
        };
        proc.lineage_len = 1;
        let result = Process::try_from(proc);
        assert!(result.is_ok());
        let lineage = result.unwrap().lineage;
        assert!(lineage[0].exe_path.to_string_lossy().contains("/bin/"));
        assert!(lineage[0].exe_path.to_string_lossy().contains('\u{FFFD}'));
    }
}
