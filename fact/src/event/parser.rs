use fact_ebpf::event_t;

use crate::{host_info, mount_info::MountInfo};

use super::{process::Process, Event, FileData};

pub(crate) struct EventParser {
    mountinfo: MountInfo,
}

impl EventParser {
    pub(crate) fn new() -> anyhow::Result<Self> {
        let mountinfo = MountInfo::new()?;

        Ok(EventParser { mountinfo })
    }

    pub(crate) fn parse(&mut self, event: &event_t) -> anyhow::Result<Event> {
        let process = Process::try_from(event.process)?;
        let timestamp = host_info::get_boot_time() + event.timestamp;

        let mounts = match self.mountinfo.get(&event.dev) {
            Some(mounts) => mounts,
            None => {
                self.mountinfo.refresh()?;
                match self.mountinfo.get(&event.dev) {
                    Some(mounts) => mounts,
                    None => self.mountinfo.insert_empty(event.dev),
                }
            }
        };

        let file = FileData::new(event.type_, event.filename, event.host_file, mounts)?;

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            file,
        })
    }
}
