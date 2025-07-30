use std::{ffi::CStr, path::PathBuf};

use uuid::Uuid;

use crate::{
    bpf::bindings::{event_t, lineage_t, process_t},
    host_info,
};

fn slice_to_string(s: &[i8]) -> anyhow::Result<String> {
    Ok(unsafe { CStr::from_ptr(s.as_ptr()) }.to_str()?.to_owned())
}

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

impl From<Lineage> for fact_api::process_signal::LineageInfo {
    fn from(value: Lineage) -> Self {
        let Lineage { uid, exe_path } = value;
        Self {
            parent_uid: uid,
            parent_exec_file_path: exe_path,
        }
    }
}

#[derive(Debug, Default)]
pub struct Process {
    comm: String,
    args: Vec<String>,
    exe_path: String,
    container_id: Option<String>,
    uid: u32,
    username: &'static str,
    gid: u32,
    login_uid: u32,
    pid: u32,
    lineage: Vec<Lineage>,
}

impl Process {
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

impl TryFrom<process_t> for Process {
    type Error = anyhow::Error;

    fn try_from(value: process_t) -> Result<Self, Self::Error> {
        let comm = slice_to_string(value.comm.as_slice())?;
        let exe_path = slice_to_string(value.exe_path.as_slice())?;
        let cpu_cgroup = unsafe { CStr::from_ptr(value.cpu_cgroup.as_ptr()) }.to_str()?;
        let container_id = Process::extract_container_id(cpu_cgroup);

        let lineage = value.lineage[..value.lineage_len as usize]
            .iter()
            .map(Lineage::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut converted_args = Vec::new();
        let mut offset = 0;
        while offset < 4096 {
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
            exec_file_path: exe_path,
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
        }
    }
}

#[derive(Debug)]
pub struct Event {
    timestamp: u64,
    #[allow(dead_code)]
    hostname: &'static str,
    process: Process,
    is_external_mount: bool,
    pub filename: PathBuf,
    host_file: PathBuf,
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let timestamp = host_info::get_boot_time() + value.timestamp;
        let filename = slice_to_string(value.filename.as_slice())?.into();
        let host_file = slice_to_string(value.host_file.as_slice())?.into();
        let process = value.process.try_into()?;
        let is_external_mount = value.is_external_mount != 0;

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            is_external_mount,
            filename,
            host_file,
        })
    }
}

impl From<Event> for fact_api::FileActivity {
    fn from(value: Event) -> Self {
        let Event {
            timestamp,
            hostname: _,
            process,
            is_external_mount,
            filename,
            host_file,
        } = value;
        let activity = fact_api::FileActivityBase {
            path: filename.into_os_string().into_string().unwrap(),
            host_path: host_file.into_os_string().into_string().unwrap(),
            is_external_mount,
        };
        let f_act = fact_api::FileOpen {
            activity: Some(activity),
        };

        let f_act = fact_api::file_activity::File::Open(f_act);

        let seconds = (timestamp / 1_000_000_000) as i64;
        let nanos = (timestamp % 1_000_000_000) as i32;
        let timestamp = prost_types::Timestamp { seconds, nanos };

        Self {
            timestamp: Some(timestamp),
            process: Some(process.into()),
            file: Some(f_act),
        }
    }
}
