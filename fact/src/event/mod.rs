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

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    timestamp: u64,
    hostname: &'static str,
    data: EventData,
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
        let data = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN
            | file_activity_type_t::FILE_ACTIVITY_CREATION
            | file_activity_type_t::FILE_ACTIVITY_UNLINK => {
                Event::new_file_event(event_type, filename, host_file, process)
            }
            file_activity_type_t::PROCESS_EXEC => EventData::ProcessData(process),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(Event {
            timestamp,
            hostname,
            data,
        })
    }

    pub fn is_file_event(&self) -> bool {
        matches!(self.data, EventData::FileData { .. })
    }

    pub fn is_from_container(&self) -> bool {
        let p = match &self.data {
            EventData::FileData { process, .. } => process,
            EventData::ProcessData(process) => process,
        };
        p.is_from_container()
    }

    #[cfg(test)]
    fn new_file_event(
        event_type: file_activity_type_t,
        filename: PathBuf,
        host_file: PathBuf,
        process: Process,
    ) -> EventData {
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
        EventData::FileData { process, file }
    }
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let process = Process::try_from(value.process)?;
        let timestamp = host_info::get_boot_time() + value.timestamp;

        let data = match value.type_ {
            file_activity_type_t::FILE_ACTIVITY_OPEN
            | file_activity_type_t::FILE_ACTIVITY_CREATION
            | file_activity_type_t::FILE_ACTIVITY_UNLINK => {
                let file = FileData::new(value.type_, value.filename, value.host_file)?;
                EventData::FileData { process, file }
            }
            file_activity_type_t::PROCESS_EXEC => EventData::ProcessData(process),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            data,
        })
    }
}

impl TryFrom<Event> for fact_api::sensor::FileActivity {
    type Error = anyhow::Error;

    fn try_from(value: Event) -> Result<Self, Self::Error> {
        let (process, file) = match value.data {
            EventData::FileData { process, file } => (process, file),
            EventData::ProcessData(_) => anyhow::bail!("Unexpected process event on file pipeline"),
        };
        let file = fact_api::sensor::file_activity::File::from(file);
        let timestamp = timestamp_to_proto(value.timestamp);
        let process = fact_api::sensor::ProcessSignal::from(process);

        Ok(Self {
            file: Some(file),
            timestamp: Some(timestamp),
            process: Some(process),
        })
    }
}

impl TryFrom<Event> for fact_api::sensor::SignalStreamMessage {
    type Error = anyhow::Error;

    fn try_from(value: Event) -> Result<Self, Self::Error> {
        let process = match value.data {
            EventData::FileData { .. } => {
                anyhow::bail!("Unexpected file event on process pipeline")
            }
            EventData::ProcessData(p) => p,
        };
        let signal = fact_api::storage::ProcessSignal::from(process);
        let signal = fact_api::v1::signal::Signal::ProcessSignal(signal);
        let signal = fact_api::v1::Signal {
            signal: Some(signal),
        };
        let msg = fact_api::sensor::signal_stream_message::Msg::Signal(signal);

        Ok(Self { msg: Some(msg) })
    }
}

#[cfg(test)]
impl PartialEq for Event {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname && self.data == other.data
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum EventData {
    FileData { process: Process, file: FileData },
    ProcessData(Process),
}

#[cfg(test)]
impl PartialEq for EventData {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                EventData::FileData {
                    process: s_proc,
                    file: s_file,
                },
                EventData::FileData {
                    process: o_proc,
                    file: o_file,
                },
            ) => s_proc == o_proc && s_file == o_file,
            (EventData::ProcessData(s_proc), EventData::ProcessData(o_proc)) => s_proc == o_proc,
            _ => false,
        }
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
