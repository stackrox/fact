use std::ffi::CStr;

use fact_ebpf::{lineage_t, process_t};
use serde::Serialize;
use uuid::Uuid;

use crate::host_info;

use super::slice_to_string;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Lineage {
    uid: u32,
    exe_path: String,
}

impl Lineage {
    fn new(uid: u32, exe_path: &str) -> Self {
        Lineage {
            uid,
            exe_path: exe_path.to_owned(),
        }
    }
}

impl TryFrom<&lineage_t> for Lineage {
    type Error = anyhow::Error;

    fn try_from(value: &lineage_t) -> Result<Self, Self::Error> {
        let lineage_t { uid, exe_path } = value;
        let exe_path = unsafe { CStr::from_ptr(exe_path.as_ptr()) }.to_str()?;

        Ok(Lineage::new(*uid, exe_path))
    }
}

impl From<Lineage> for fact_api::storage::process_signal::LineageInfo {
    fn from(value: Lineage) -> Self {
        let Lineage { uid, exe_path } = value;
        Self {
            parent_uid: uid,
            parent_exec_file_path: exe_path,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Process {
    comm: String,
    args: Vec<String>,
    exe_path: String,
    pub container_id: Option<String>,
    uid: u32,
    pub username: &'static str,
    gid: u32,
    pub login_uid: u32,
    pid: u32,
    pub in_root_mount_ns: bool,
    lineage: Vec<Lineage>,
}

impl Process {
    /// Create a representation of the current process as best as
    /// possible.
    #[cfg(test)]
    pub fn current() -> Self {
        use crate::host_info::{get_host_mount_ns, get_mount_ns};

        let exe_path = std::env::current_exe()
            .expect("Failed to get current exe")
            .into_os_string()
            .into_string()
            .unwrap();
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

        let in_root_mount_ns = get_host_mount_ns() == get_mount_ns(&pid.to_string());

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
        let exe_path = slice_to_string(value.exe_path.as_slice())?;
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

impl From<Process> for fact_api::storage::ProcessSignal {
    fn from(value: Process) -> Self {
        let Process {
            comm,
            args,
            exe_path,
            container_id,
            uid,
            username: _,
            gid,
            login_uid: _,
            pid,
            in_root_mount_ns: _,
            lineage,
        } = value;

        let container_id = container_id.unwrap_or("".to_string());

        let args = args
            .into_iter()
            .reduce(|acc, i| acc + " " + &i)
            .unwrap_or("".to_owned());

        #[allow(deprecated)]
        Self {
            id: Uuid::new_v4().to_string(),
            container_id,
            time: None,
            name: comm,
            args,
            exec_file_path: exe_path,
            pid,
            uid,
            gid,
            scraped: false,
            lineage: vec![],
            lineage_info: lineage
                .into_iter()
                .map(fact_api::storage::process_signal::LineageInfo::from)
                .collect(),
        }
    }
}
