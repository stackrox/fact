#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{ffi::CStr, os::raw::c_char, path::PathBuf};

use serde::Serialize;

use fact_ebpf::{event_t, file_activity_type_t};

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
pub enum Event {
    Open(BaseEvent),
    Creation(BaseEvent),
    Unlink(BaseEvent),
}

impl Event {
    #[cfg(test)]
    pub fn new(
        event_type: file_activity_type_t,
        hostname: &'static str,
        filename: PathBuf,
        host_file: PathBuf,
        process: Process,
    ) -> Self {
        let inner = BaseEvent::new(hostname, filename, host_file, process);
        match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => Event::Open(inner),
            file_activity_type_t::FILE_ACTIVITY_CREATION => Event::Creation(inner),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => Event::Unlink(inner),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        }
    }

    /// Get the event timestamp from the inner event.
    fn get_timestamp(&self) -> u64 {
        match self {
            Event::Open(event) | Event::Creation(event) | Event::Unlink(event) => event.timestamp,
        }
    }

    /// Consume the event and return the inner process information
    ///
    /// This is useful to avoid cloning values once we are done
    /// processing the file side of the event and want to turn to the
    /// process side of things.
    fn into_process(self) -> process::Process {
        match self {
            Event::Open(base_event) | Event::Creation(base_event) | Event::Unlink(base_event) => {
                base_event.process
            }
        }
    }
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let base = BaseEvent::try_from(value)?;
        match value.type_ {
            file_activity_type_t::FILE_ACTIVITY_OPEN => Ok(Event::Open(base)),
            file_activity_type_t::FILE_ACTIVITY_CREATION => Ok(Event::Creation(base)),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => Ok(Event::Unlink(base)),
            id => unreachable!("Invalid event type: {id:?}"),
        }
    }
}

impl From<&Event> for fact_api::file_activity::File {
    fn from(event: &Event) -> Self {
        match event {
            Event::Open(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileOpen { activity };
                fact_api::file_activity::File::Open(f_act)
            }
            Event::Creation(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileCreation { activity };
                fact_api::file_activity::File::Creation(f_act)
            }
            Event::Unlink(event) => {
                let activity = Some(fact_api::FileActivityBase::from(event));
                let f_act = fact_api::FileUnlink { activity };
                fact_api::file_activity::File::Unlink(f_act)
            }
        }
    }
}

impl From<Event> for fact_api::FileActivity {
    fn from(value: Event) -> Self {
        let file = fact_api::file_activity::File::from(&value);
        let timestamp = timestamp_to_proto(value.get_timestamp());
        let process = fact_api::ProcessSignal::from(value.into_process());

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
        match (self, other) {
            (Event::Open(this), Event::Open(other)) => this == other,
            (Event::Creation(this), Event::Creation(other)) => this == other,
            (Event::Unlink(this), Event::Unlink(other)) => this == other,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseEvent {
    timestamp: u64,
    hostname: &'static str,
    process: Process,
    pub filename: PathBuf,
    host_file: PathBuf,
}

impl BaseEvent {
    #[cfg(test)]
    pub fn new(
        hostname: &'static str,
        filename: PathBuf,
        host_file: PathBuf,
        process: Process,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos() as _;
        BaseEvent {
            timestamp,
            hostname,
            process,
            filename,
            host_file,
        }
    }
}

#[cfg(test)]
impl PartialEq for BaseEvent {
    fn eq(&self, other: &Self) -> bool {
        self.hostname == other.hostname
            && self.filename == other.filename
            && self.host_file == other.host_file
            && self.process == other.process
    }
}

impl TryFrom<&event_t> for BaseEvent {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let timestamp = host_info::get_boot_time() + value.timestamp;
        let filename = slice_to_string(value.filename.as_slice())?.into();
        let host_file = slice_to_string(value.host_file.as_slice())?.into();
        let process = value.process.try_into()?;

        Ok(BaseEvent {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            filename,
            host_file,
        })
    }
}

impl From<&BaseEvent> for fact_api::FileActivityBase {
    fn from(value: &BaseEvent) -> Self {
        fact_api::FileActivityBase {
            path: value.filename.to_string_lossy().to_string(),
            host_path: value.host_file.to_string_lossy().to_string(),
        }
    }
}
