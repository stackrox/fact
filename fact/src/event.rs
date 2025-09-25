#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::CStr, os::raw::c_char, path::PathBuf, sync::Arc};

use fact_api::FileActivity;
use serde::Serialize;
use uuid::Uuid;

use fact_ebpf::{event_t, file_activity_type_t, lineage_t, process_t};

use crate::{cgroup::ContainerIdCache, host_info};

fn slice_to_string(s: &[c_char]) -> anyhow::Result<String> {
    Ok(unsafe { CStr::from_ptr(s.as_ptr()) }.to_str()?.to_owned())
}

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

impl From<Lineage> for fact_api::process_signal::LineageInfo {
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
    container_id: Option<Arc<String>>,
    uid: u32,
    username: &'static str,
    gid: u32,
    login_uid: u32,
    pid: u32,
    in_root_mount_ns: bool,
    lineage: Vec<Lineage>,
}

impl Process {
    async fn new(proc: &process_t, cid_cache: &ContainerIdCache) -> anyhow::Result<Self> {
        let comm = slice_to_string(proc.comm.as_slice())?;
        let exe_path = slice_to_string(proc.exe_path.as_slice())?;
        let container_id = cid_cache.get_container_id(proc.cgroup_id).await;
        let in_root_mount_ns = proc.in_root_mount_ns != 0;

        let lineage = proc.lineage[..proc.lineage_len as usize]
            .iter()
            .map(Lineage::try_from)
            .collect::<Result<Vec<_>, _>>()?;

        let mut converted_args = Vec::new();
        let args_len = proc.args_len as usize;
        let mut offset = 0;
        while offset < args_len {
            let arg = unsafe { CStr::from_ptr(proc.args.as_ptr().add(offset)) }
                .to_str()?
                .to_owned();
            if arg.is_empty() {
                break;
            }
            offset += arg.len() + 1;
            converted_args.push(arg);
        }

        let username = host_info::get_username(proc.uid);

        Ok(Process {
            comm,
            args: converted_args,
            exe_path,
            container_id,
            uid: proc.uid,
            username,
            gid: proc.gid,
            login_uid: proc.login_uid,
            pid: proc.pid,
            in_root_mount_ns,
            lineage,
        })
    }

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
        let container_id = ContainerIdCache::extract_container_id(&cgroup).map(Arc::new);
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

        let container_id = container_id
            .map(Arc::unwrap_or_clone)
            .unwrap_or("".to_string());

        Self {
            id: Uuid::new_v4().to_string(),
            container_id,
            creation_time: None,
            name: comm,
            args: args.join(" "),
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
            in_root_mount_ns,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum Event {
    Open(EventOpen),
    Creation(EventCreation),
}

impl Event {
    pub async fn new(event: &event_t, cid_cache: &ContainerIdCache) -> anyhow::Result<Self> {
        match event.type_ {
            file_activity_type_t::FILE_ACTIVITY_OPEN => {
                Ok(EventOpen::new(event, cid_cache).await?.into())
            }
            file_activity_type_t::FILE_ACTIVITY_CREATION => {
                Ok(EventCreation::new(event, cid_cache).await?.into())
            }
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        }
    }

    #[cfg(test)]
    #[allow(non_upper_case_globals)]
    pub fn from_raw_parts(
        event_type: file_activity_type_t,
        hostname: &'static str,
        filename: PathBuf,
        host_file: PathBuf,
        process: Process,
    ) -> Self {
        match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => {
                EventOpen::from_raw_parts(hostname, filename, host_file, process).into()
            }
            file_activity_type_t::FILE_ACTIVITY_CREATION => {
                EventCreation::from_raw_parts(hostname, filename, host_file, process).into()
            }
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        }
    }
}

impl From<Event> for FileActivity {
    fn from(value: Event) -> Self {
        match value {
            Event::Open(event) => event.into(),
            Event::Creation(event) => event.into(),
        }
    }
}

#[cfg(test)]
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Event::Open(this), Event::Open(other)) => this == other,
            (Event::Creation(this), Event::Creation(other)) => this == other,
            _ => false,
        }
    }
}

macro_rules! basic_file_event {
    ($event_type:tt) => {
        #[derive(Debug, Clone, Serialize)]
        pub struct $event_type {
            timestamp: u64,
            hostname: &'static str,
            process: Process,
            pub filename: PathBuf,
            host_file: PathBuf,
        }

        impl $event_type {
            async fn new(event: &event_t, cid_cache: &ContainerIdCache) -> anyhow::Result<Self> {
                let timestamp = host_info::get_boot_time() + event.timestamp;
                let filename = slice_to_string(event.filename.as_slice())?.into();
                let host_file = slice_to_string(event.host_file.as_slice())?.into();
                let process = Process::new(&event.process, cid_cache).await?;

                Ok($event_type {
                    timestamp,
                    hostname: host_info::get_hostname(),
                    process,
                    filename,
                    host_file,
                })
            }

            #[cfg(test)]
            pub fn from_raw_parts(
                hostname: &'static str,
                filename: PathBuf,
                host_file: PathBuf,
                process: Process,
            ) -> Self {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos() as _;
                $event_type {
                    timestamp,
                    hostname,
                    process,
                    filename,
                    host_file,
                }
            }
        }

        #[cfg(test)]
        impl PartialEq for $event_type {
            fn eq(&self, other: &Self) -> bool {
                self.hostname == other.hostname
                    && self.filename == other.filename
                    && self.host_file == other.host_file
                    && self.process == other.process
            }
        }
    };
}

macro_rules! file_activity_from_basic_event {
    ($event_type:ty, $api_wrapper:path, $api_variant:path) => {
        impl From<$event_type> for fact_api::FileActivity {
            fn from(value: $event_type) -> Self {
                use $api_wrapper as api_wrapper;

                let activity = fact_api::FileActivityBase {
                    path: value.filename.into_os_string().into_string().unwrap(),
                    host_path: value.host_file.into_os_string().into_string().unwrap(),
                };
                let f_act = api_wrapper {
                    activity: Some(activity),
                };
                let f_act = $api_variant(f_act);

                let seconds = (value.timestamp / 1_000_000_000) as i64;
                let nanos = (value.timestamp % 1_000_000_000) as i32;
                let timestamp = prost_types::Timestamp { seconds, nanos };

                Self {
                    timestamp: Some(timestamp),
                    process: Some(value.process.into()),
                    file: Some(f_act),
                }
            }
        }
    };
}

macro_rules! event_from_basic_event {
    ($event_type:ty, $variant:path) => {
        impl From<$event_type> for Event {
            fn from(value: $event_type) -> Self {
                $variant(value)
            }
        }
    };
}

macro_rules! file_event {
    ($name:tt, $wrapper:path, $api_wrapper:path, $api_variant:path) => {
        basic_file_event!($name);
        file_activity_from_basic_event!($name, $api_wrapper, $api_variant);
        event_from_basic_event!($name, $wrapper);
    };
}

file_event!(
    EventOpen,
    Event::Open,
    fact_api::FileOpen,
    fact_api::file_activity::File::Open
);
file_event!(
    EventCreation,
    Event::Creation,
    fact_api::FileCreation,
    fact_api::file_activity::File::Creation
);
