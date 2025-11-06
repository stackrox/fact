#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::CStr, os::raw::c_char, path::PathBuf};

use serde::Serialize;

use fact_ebpf::{event_t, file_activity_type_t, PATH_MAX};

use crate::host_info;
use process::Process;

pub(crate) mod process;

fn slice_to_string(s: &[c_char]) -> anyhow::Result<String> {
    Ok(unsafe { CStr::from_ptr(s.as_ptr()) }.to_str()?.to_owned())
}

fn timestamp_to_proto(ts: u64) -> prost_types::Timestamp {
    let seconds = (ts / 1_000_000_000) as i64;
    let nanos = (ts % 1_000_000_000) as i32;
    prost_types::Timestamp { seconds, nanos }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum ProcessActivity {
    Exec,
}

#[derive(Debug, Clone, Serialize)]
pub enum Activity {
    File(FileData),
    Process(ProcessActivity),
}

#[cfg(test)]
impl PartialEq for Activity {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(l), Self::File(r)) => l == r,
            (Self::Process(l), Self::Process(r)) => l == r,
            _ => false,
        }
    }
}

impl Activity {
    pub fn new(
        event_type: file_activity_type_t,
        filename: [c_char; PATH_MAX as usize],
        host_file: [c_char; PATH_MAX as usize],
    ) -> anyhow::Result<Self> {
        let activity = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN
            | file_activity_type_t::FILE_ACTIVITY_CREATION
            | file_activity_type_t::FILE_ACTIVITY_UNLINK => {
                Activity::File(FileData::new(event_type, filename, host_file)?)
            }
            file_activity_type_t::PROCESS_ACTIVITY_EXEC => Activity::Process(ProcessActivity::Exec),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(activity)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    timestamp: u64,
    hostname: &'static str,
    process: Process,
    pub activity: Activity,
}

impl Event {
    #[cfg(test)]
    pub fn new(
        event_type: file_activity_type_t,
        hostname: &'static str,
        filename: PathBuf,
        host_file: PathBuf,
        process: Process,
    ) -> anyhow::Result<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as _;
        let inner = BaseFileData {
            filename,
            host_file,
        };
        let activity = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => Activity::File(FileData::Open(inner)),
            file_activity_type_t::FILE_ACTIVITY_CREATION => {
                Activity::File(FileData::Creation(inner))
            }
            file_activity_type_t::FILE_ACTIVITY_UNLINK => Activity::File(FileData::Unlink(inner)),
            file_activity_type_t::PROCESS_ACTIVITY_EXEC => Activity::Process(ProcessActivity::Exec),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(Event {
            timestamp,
            hostname,
            process,
            activity,
        })
    }
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let process = Process::try_from(value.process)?;
        let timestamp = host_info::get_boot_time() + value.timestamp;
        let activity = Activity::new(value.type_, value.filename, value.host_file)?;

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            activity,
        })
    }
}

impl From<Event> for fact_api::v1::Signal {
    fn from(value: Event) -> Self {
        let process_signal = fact_api::storage::ProcessSignal::from(value.process);
        fact_api::v1::Signal {
            signal: Some(fact_api::v1::signal::Signal::ProcessSignal(process_signal)),
        }
    }
}

impl From<Event> for fact_api::sensor::FileActivity {
    fn from(value: Event) -> Self {
        let file = match value.activity {
            Activity::File(file) => Some(fact_api::sensor::file_activity::File::from(file)),
            Activity::Process(_) => None,
        };
        let timestamp = timestamp_to_proto(value.timestamp);
        let process_signal = fact_api::storage::ProcessSignal::from(value.process.clone());
        let process = fact_api::sensor::ProcessSignal {
            id: process_signal.id,
            container_id: process_signal.container_id,
            creation_time: process_signal.time,
            name: process_signal.name,
            args: process_signal.args,
            exec_file_path: process_signal.exec_file_path,
            pid: process_signal.pid,
            gid: process_signal.gid,
            uid: process_signal.uid,
            username: value.process.username.to_string(),
            login_uid: value.process.login_uid,
            in_root_mount_ns: value.process.in_root_mount_ns,
            scraped: process_signal.scraped,
            lineage_info: process_signal
                .lineage_info
                .into_iter()
                .map(|l| fact_api::sensor::process_signal::LineageInfo {
                    parent_uid: l.parent_uid,
                    parent_exec_file_path: l.parent_exec_file_path,
                })
                .collect(),
        };

        Self {
            file,
            timestamp: Some(timestamp),
            process: Some(process),
        }
    }
}

#[cfg(test)]
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname
            && self.process == other.process
            && self.activity == other.activity
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum FileData {
    Open(BaseFileData),
    Creation(BaseFileData),
    Unlink(BaseFileData),
}

impl FileData {
    pub fn new(
        event_type: file_activity_type_t,
        filename: [c_char; PATH_MAX as usize],
        host_file: [c_char; PATH_MAX as usize],
    ) -> anyhow::Result<Self> {
        let inner = BaseFileData::new(filename, host_file)?;
        let file = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            file_activity_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => FileData::Unlink(inner),
            invalid => unreachable!("Invalid file event type: {invalid:?}"),
        };

        Ok(file)
    }
}

impl From<FileData> for fact_api::sensor::file_activity::File {
    fn from(event: FileData) -> Self {
        match event {
            FileData::Open(event) => {
                let activity = Some(fact_api::sensor::FileActivityBase::from(event));
                let f_act = fact_api::sensor::FileOpen { activity };
                fact_api::sensor::file_activity::File::Open(f_act)
            }
            FileData::Creation(event) => {
                let activity = Some(fact_api::sensor::FileActivityBase::from(event));
                let f_act = fact_api::sensor::FileCreation { activity };
                fact_api::sensor::file_activity::File::Creation(f_act)
            }
            FileData::Unlink(event) => {
                let activity = Some(fact_api::sensor::FileActivityBase::from(event));
                let f_act = fact_api::sensor::FileUnlink { activity };
                fact_api::sensor::file_activity::File::Unlink(f_act)
            }
        }
    }
}

#[cfg(test)]
impl PartialEq for FileData {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (FileData::Open(this), FileData::Open(other)) => this == other,
            (FileData::Creation(this), FileData::Creation(other)) => this == other,
            (FileData::Unlink(this), FileData::Unlink(other)) => this == other,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseFileData {
    pub filename: PathBuf,
    host_file: PathBuf,
}

impl BaseFileData {
    pub fn new(
        filename: [c_char; PATH_MAX as usize],
        host_file: [c_char; PATH_MAX as usize],
    ) -> anyhow::Result<Self> {
        let filename = slice_to_string(&filename)?.into();
        let host_file = slice_to_string(&host_file)?.into();

        Ok(BaseFileData {
            filename,
            host_file,
        })
    }
}

#[cfg(test)]
impl PartialEq for BaseFileData {
    fn eq(&self, other: &Self) -> bool {
        self.filename == other.filename && self.host_file == other.host_file
    }
}

impl From<BaseFileData> for fact_api::sensor::FileActivityBase {
    fn from(value: BaseFileData) -> Self {
        fact_api::sensor::FileActivityBase {
            path: value.filename.to_string_lossy().to_string(),
            host_path: value.host_file.to_string_lossy().to_string(),
        }
    }
}
