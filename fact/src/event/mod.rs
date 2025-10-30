#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::CStr, os::raw::c_char, path::PathBuf};

use serde::Serialize;

use fact_ebpf::{event_t, file_activity_type_t, metadata_t, PATH_MAX};

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

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    timestamp: u64,
    hostname: &'static str,
    process: Process,
    file: FileData,
    metadata: Metadata,
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
        let file = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            file_activity_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => FileData::Unlink(inner),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };
        let metadata = Metadata::default();

        Ok(Event {
            timestamp,
            hostname,
            process,
            file,
            metadata,
        })
    }
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let process = Process::try_from(value.process)?;
        let timestamp = host_info::get_boot_time() + value.timestamp;
        let file = FileData::new(value.type_, value.filename, value.host_file)?;
        let metadata = Metadata::from(value.metadata);

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            file,
            metadata,
        })
    }
}

impl From<Event> for fact_api::FileActivity {
    fn from(value: Event) -> Self {
        let file = fact_api::file_activity::File::from(value.file);
        let timestamp = timestamp_to_proto(value.timestamp);
        let process = fact_api::ProcessSignal::from(value.process);

        Self {
            file: Some(file),
            timestamp: Some(timestamp),
            process: Some(process),
        }
    }
}

#[cfg(test)]
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname && self.process == other.process && self.file == other.file
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
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(file)
    }
}

impl From<FileData> for fact_api::file_activity::File {
    fn from(event: FileData) -> Self {
        match event {
            FileData::Open(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileOpen { activity };
                fact_api::file_activity::File::Open(f_act)
            }
            FileData::Creation(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileCreation { activity };
                fact_api::file_activity::File::Creation(f_act)
            }
            FileData::Unlink(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileUnlink { activity };
                fact_api::file_activity::File::Unlink(f_act)
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

impl From<BaseFileData> for fact_api::FileActivityBase {
    fn from(value: BaseFileData) -> Self {
        fact_api::FileActivityBase {
            path: value.filename.to_string_lossy().to_string(),
            host_path: value.host_file.to_string_lossy().to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
struct Metadata {
    mode: u16,
    uid: u32,
    gid: u32,
    size: i64,
}

impl From<metadata_t> for Metadata {
    fn from(value: metadata_t) -> Self {
        let metadata_t {
            mode,
            uid,
            gid,
            size,
        } = value;
        Metadata {
            mode,
            uid,
            gid,
            size,
        }
    }
}
