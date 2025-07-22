use std::ffi::CStr;

use crate::{
    bpf::bindings::{event_t, lineage_t, process_t},
    host_info,
};

#[allow(dead_code)]
#[derive(Debug, Default)]
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

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct Process {
    comm: String,
    args: Vec<String>,
    exe_path: String,
    container_id: Option<String>,
    uid: u32,
    gid: u32,
    login_uid: u32,
    lineage: Vec<Lineage>,
}

impl Process {
    fn extract_container_id(cgroup: &str) -> Option<String> {
        let cgroup = if let Some(i) = cgroup.rfind(".scope") {
            let (cgroup, _) = cgroup.split_at(i);
            cgroup
        } else {
            cgroup
        };

        if cgroup.is_empty() || cgroup.len() < 65 {
            return None;
        }

        let (_, cgroup) = cgroup.split_at(cgroup.len() - 65);
        let (c, cgroup) = cgroup.split_at(1);
        if c != "/" && c != "-" {
            return None;
        }

        if cgroup.chars().all(|c| c.is_ascii_hexdigit()) {
            let (cgroup, _) = cgroup.split_at(12);
            Some(cgroup.to_owned())
        } else {
            None
        }
    }
}

impl TryFrom<&process_t> for Process {
    type Error = anyhow::Error;

    fn try_from(value: &process_t) -> Result<Self, Self::Error> {
        let process_t {
            comm,
            args,
            exe_path,
            cpu_cgroup,
            uid,
            gid,
            login_uid,
            lineage,
            lineage_len,
        } = value;
        let comm = unsafe { CStr::from_ptr(comm.as_ptr()) }
            .to_str()?
            .to_owned();
        let exe_path = unsafe { CStr::from_ptr(exe_path.as_ptr()) }
            .to_str()?
            .to_owned();
        let cpu_cgroup = unsafe { CStr::from_ptr(cpu_cgroup.as_ptr()) }.to_str()?;
        let container_id = Process::extract_container_id(cpu_cgroup);

        let lineage = lineage[..*lineage_len as usize]
            .iter()
            .map(Lineage::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut converted_args = Vec::new();
        let mut offset = 0;
        while offset < 4096 {
            let arg = unsafe { CStr::from_ptr(args.as_ptr().add(offset)) }
                .to_str()?
                .to_owned();
            if arg.is_empty() {
                break;
            }
            offset += arg.len() + 1;
            converted_args.push(arg);
        }

        Ok(Process {
            comm,
            args: converted_args,
            exe_path,
            container_id,
            uid: *uid,
            gid: *gid,
            login_uid: *login_uid,
            lineage,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Event {
    timestamp: u64,
    hostname: &'static str,
    process: Process,
    is_external_mount: bool,
    filename: String,
    host_file: String,
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let event_t {
            timestamp,
            process,
            is_external_mount,
            filename,
            host_file,
        } = value;
        let timestamp = host_info::get_boot_time() + timestamp;
        let filename = unsafe { CStr::from_ptr(filename.as_ptr()) }
            .to_str()?
            .to_owned();
        let host_file = unsafe { CStr::from_ptr(host_file.as_ptr()) }
            .to_str()?
            .to_owned();

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process: process.try_into()?,
            is_external_mount: *is_external_mount != 0,
            filename,
            host_file,
        })
    }
}
