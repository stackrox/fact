use std::{error::Error, fmt::Display, path::PathBuf};

use fact_ebpf::event_t;

use crate::{host_info, mount_info::MountInfo};

use super::{process::Process, Event, FileData};

#[derive(Debug)]
pub(crate) enum EventParserError {
    NotFound,
    ProcessParse(String),
    FileParse(String),
}

impl Error for EventParserError {}
impl Display for EventParserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventParserError::NotFound => write!(f, "mountpoint not found"),
            EventParserError::ProcessParse(e) => write!(f, "Failed to parse process: {e}"),
            EventParserError::FileParse(e) => write!(f, "Failed to parse file: {e}"),
        }
    }
}

pub(crate) struct EventParser {
    pub mountinfo: MountInfo,
}

impl EventParser {
    pub(crate) fn new(paths: &[PathBuf]) -> anyhow::Result<Self> {
        let mountinfo = MountInfo::new(paths)?;

        Ok(EventParser { mountinfo })
    }

    pub(crate) fn refresh(&mut self, paths: &[PathBuf]) -> anyhow::Result<()> {
        self.mountinfo.refresh(paths)
    }

    pub(crate) fn parse(&mut self, event: &event_t) -> Result<Event, EventParserError> {
        let process = match Process::try_from(event.process) {
            Ok(p) => p,
            Err(e) => return Err(EventParserError::ProcessParse(e.to_string())),
        };
        let timestamp = host_info::get_boot_time() + event.timestamp;

        let mounts = match self.mountinfo.get(&event.dev) {
            Some(mounts) => mounts,
            None => return Err(EventParserError::NotFound),
        };

        let file = match FileData::new(event.type_, event.filename, event.host_file, mounts) {
            Ok(f) => f,
            Err(e) => return Err(EventParserError::FileParse(e.to_string())),
        };

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            file,
        })
    }
}
