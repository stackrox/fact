#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    ffi::{CStr, OsStr},
    os::{raw::c_char, unix::ffi::OsStrExt},
    path::{Path, PathBuf},
};

use serde::Serialize;

use fact_ebpf::{event_t, file_activity_type_t, inode_key_t, PATH_MAX};

use crate::host_info;
use process::Process;

pub(crate) mod process;

fn slice_to_string(s: &[c_char]) -> anyhow::Result<String> {
    Ok(unsafe { CStr::from_ptr(s.as_ptr()) }.to_str()?.to_owned())
}

/// Sanitize a buffer obtained from calling d_path kernel side.
///
/// Sanitizing this type of buffer is a special case, because the kernel
/// may append " (deleted)" to a path when the file has been removed and
/// can mess with the event we report. This method will take a slice of
/// c_char and return a PathBuf with the " (deleted)" portion removed.
///
/// With the current implementation, non UTF-8 characters in the file
/// name will be replaced with the U+FFFD character.
///
/// Note that no special check is made for the case in which a file name
/// actually ends with the " (deleted)" suffix. This means that if we
/// would get an event on a file named `/etc/something/file\ (deleted)`,
/// we would wrongly report the file name as `/etc/something/file`.
/// However, we believe this would be a _very_ special case with a low
/// chance that we will stumble upon it, so we purposely decide to
/// ignore it.
fn sanitize_d_path(s: &[c_char]) -> PathBuf {
    let s = unsafe { CStr::from_ptr(s.as_ptr()) };
    let p = Path::new(OsStr::from_bytes(s.to_bytes()));

    // Take the file name of the path and remove the " (deleted)" suffix
    // if present.
    if let Some(file_name) = p.file_name() {
        if let Some(file_name) = file_name.to_string_lossy().strip_suffix(" (deleted)") {
            // The file name needed to be sanitized
            return p.parent().map(|p| p.join(file_name)).unwrap_or_default();
        }
    }

    p.to_path_buf()
}

fn timestamp_to_proto(ts: u64) -> prost_types::Timestamp {
    let seconds = (ts / 1_000_000_000) as i64;
    let nanos = (ts % 1_000_000_000) as i32;
    prost_types::Timestamp { seconds, nanos }
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) enum EventTestData {
    Creation,
    Unlink,
    Chmod(u16, u16),
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    timestamp: u64,
    hostname: &'static str,
    process: Process,
    file: FileData,
}

impl Event {
    #[cfg(test)]
    pub(crate) fn new(
        data: EventTestData,
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
            inode: Default::default(),
        };
        let file = match data {
            EventTestData::Creation => FileData::Creation(inner),
            EventTestData::Unlink => FileData::Unlink(inner),
            EventTestData::Chmod(new_mode, old_mode) => {
                let data = ChmodFileData {
                    inner,
                    new_mode,
                    old_mode,
                };
                FileData::Chmod(data)
            }
        };

        Ok(Event {
            timestamp,
            hostname,
            process,
            file,
        })
    }

    pub fn get_inode(&self) -> &inode_key_t {
        match &self.file {
            FileData::Open(data) => &data.inode,
            FileData::Creation(data) => &data.inode,
            FileData::Unlink(data) => &data.inode,
            FileData::Chmod(data) => &data.inner.inode,
        }
    }

    pub fn set_host_path(&mut self, host_path: PathBuf) {
        match &mut self.file {
            FileData::Open(data) => data.host_file = host_path,
            FileData::Creation(data) => data.host_file = host_path,
            FileData::Unlink(data) => data.host_file = host_path,
            FileData::Chmod(data) => data.inner.host_file = host_path,
        }
    }
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let process = Process::try_from(value.process)?;
        let timestamp = host_info::get_boot_time() + value.timestamp;
        let file = FileData::new(
            value.type_,
            value.filename,
            value.inode,
            value.__bindgen_anon_1,
        )?;

        Ok(Event {
            timestamp,
            hostname: host_info::get_hostname(),
            process,
            file,
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
            hostname: value.hostname.to_string(),
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
    Chmod(ChmodFileData),
}

impl FileData {
    pub fn new(
        event_type: file_activity_type_t,
        filename: [c_char; PATH_MAX as usize],
        inode: inode_key_t,
        extra_data: fact_ebpf::event_t__bindgen_ty_1,
    ) -> anyhow::Result<Self> {
        let inner = BaseFileData::new(filename, inode)?;
        let file = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            file_activity_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => FileData::Unlink(inner),
            file_activity_type_t::FILE_ACTIVITY_CHMOD => {
                let data = ChmodFileData {
                    inner,
                    new_mode: unsafe { extra_data.chmod.new },
                    old_mode: unsafe { extra_data.chmod.old },
                };
                FileData::Chmod(data)
            }
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
            FileData::Chmod(event) => {
                let f_act = fact_api::FilePermissionChange::from(event);
                fact_api::file_activity::File::Permission(f_act)
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
            (FileData::Chmod(this), FileData::Chmod(other)) => this == other,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseFileData {
    pub filename: PathBuf,
    host_file: PathBuf,
    inode: inode_key_t,
}

impl BaseFileData {
    pub fn new(filename: [c_char; PATH_MAX as usize], inode: inode_key_t) -> anyhow::Result<Self> {
        Ok(BaseFileData {
            filename: sanitize_d_path(&filename),
            host_file: PathBuf::new(), // this field is set by HostScanner
            inode,
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

#[derive(Debug, Clone, Serialize)]
pub struct ChmodFileData {
    inner: BaseFileData,
    new_mode: u16,
    old_mode: u16,
}

impl ChmodFileData {
    pub fn new(
        filename: [c_char; PATH_MAX as usize],
        inode: inode_key_t,
        new_mode: u16,
        old_mode: u16,
    ) -> anyhow::Result<Self> {
        let inner = BaseFileData::new(filename, inode)?;

        Ok(ChmodFileData {
            inner,
            new_mode,
            old_mode,
        })
    }
}

impl From<ChmodFileData> for fact_api::FilePermissionChange {
    fn from(value: ChmodFileData) -> Self {
        let ChmodFileData {
            inner: file,
            new_mode,
            old_mode: _,
        } = value;
        let activity = fact_api::FileActivityBase::from(file);
        fact_api::FilePermissionChange {
            activity: Some(activity),
            mode: new_mode as u32,
        }
    }
}

#[cfg(test)]
impl PartialEq for ChmodFileData {
    fn eq(&self, other: &Self) -> bool {
        self.new_mode == other.new_mode
            && self.old_mode == other.old_mode
            && self.inner == other.inner
    }
}
