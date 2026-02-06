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
            FileData::Chown(data) => &data.inner.inode,
        }
    }

    pub fn set_host_path(&mut self, host_path: PathBuf) {
        match &mut self.file {
            FileData::Open(data) => data.host_file = host_path,
            FileData::Creation(data) => data.host_file = host_path,
            FileData::Unlink(data) => data.host_file = host_path,
            FileData::Chmod(data) => data.inner.host_file = host_path,
            FileData::Chown(data) => data.inner.host_file = host_path,
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
    Chown(ChownFileData),
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
            file_activity_type_t::FILE_ACTIVITY_CHOWN => {
                let data = ChownFileData {
                    inner,
                    new_uid: unsafe { extra_data.chown.new.uid },
                    new_gid: unsafe { extra_data.chown.new.gid },
                    old_uid: unsafe { extra_data.chown.old.uid },
                    old_gid: unsafe { extra_data.chown.old.gid },
                };
                FileData::Chown(data)
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
            FileData::Chown(event) => {
                let f_act = fact_api::FileOwnershipChange::from(event);
                fact_api::file_activity::File::Ownership(f_act)
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

impl From<ChmodFileData> for fact_api::FilePermissionChange {
    fn from(value: ChmodFileData) -> Self {
        let ChmodFileData {
            inner: file,
            new_mode,
            ..
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

#[derive(Debug, Clone, Serialize)]
pub struct ChownFileData {
    inner: BaseFileData,
    new_uid: u32,
    new_gid: u32,
    old_uid: u32,
    old_gid: u32,
}

impl From<ChownFileData> for fact_api::FileOwnershipChange {
    fn from(value: ChownFileData) -> Self {
        let ChownFileData {
            inner: file,
            new_uid,
            new_gid,
            ..
        } = value;
        let activity = fact_api::FileActivityBase::from(file);
        fact_api::FileOwnershipChange {
            activity: Some(activity),
            uid: new_uid,
            gid: new_gid,
            username: "".to_string(),
            group: "".to_string(),
        }
    }
}

#[cfg(test)]
mod test_utils {
    use std::os::raw::c_char;

    /// Helper function to convert raw bytes to a c_char array for testing
    pub fn bytes_to_c_char_array<const N: usize>(bytes: &[u8]) -> [c_char; N] {
        let mut array = [0 as c_char; N];
        let len = bytes.len().min(N - 1);
        for (i, &byte) in bytes.iter().take(len).enumerate() {
            array[i] = byte as c_char;
        }
        array
    }

    /// Helper function to convert a Rust string to a c_char array for testing
    pub fn string_to_c_char_array<const N: usize>(s: &str) -> [c_char; N] {
        bytes_to_c_char_array(s.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_utils::*;

    #[test]
    fn slice_to_string_valid_utf8() {
        let tests = [
            ("hello", "ASCII"),
            ("café", "Latin-1 supplement"),
            ("файл", "Cyrillic"),
            ("测试文件", "Chinese"),
            ("test🚀file", "emoji"),
            ("test-файл-测试-🐛.txt", "mixed characters"),
            ("ملف", "Arabic"),
            ("קובץ", "Hebrew"),
            ("ファイル", "Japanese"),
        ];

        for (input, description) in tests {
            let arr = string_to_c_char_array::<256>(input);
            assert_eq!(slice_to_string(&arr).unwrap(), input, "Failed for {}", description);
        }
    }

    #[test]
    fn slice_to_string_invalid_utf8() {
        let tests: &[(&[u8], &str)] = &[
            (&[0xFF, 0xFE, 0xFD], "invalid continuation bytes"),
            (&[b't', b'e', b's', b't', 0xE2], "truncated multi-byte sequence"),
            (&[0xC0, 0x80], "overlong encoding"),
            (&[b'h', b'e', b'l', b'l', b'o', 0x80, b'w', b'o', b'r', b'l', b'd'], "invalid start byte"),
            (&[0x80], "lone continuation byte"),
            (&[b't', b'e', b's', b't', 0xFF, 0xFE], "mixed valid and invalid bytes"),
        ];

        for (bytes, description) in tests {
            let arr = bytes_to_c_char_array::<256>(bytes);
            assert!(slice_to_string(&arr).is_err(), "Should fail for {}", description);
        }
    }

    #[test]
    fn sanitize_d_path_valid_utf8() {
        let tests = [
            ("/etc/test", "/etc/test", "ASCII"),
            ("/tmp/файл.txt", "/tmp/файл.txt", "Cyrillic"),
            ("/home/user/测试文件.log", "/home/user/测试文件.log", "Chinese"),
            ("/data/🚀rocket.dat", "/data/🚀rocket.dat", "emoji"),
            ("/var/log/app-данные-数据-🐛.log", "/var/log/app-данные-数据-🐛.log", "mixed Unicode"),
            ("/home/ملف.txt", "/home/ملف.txt", "Arabic"),
            ("/opt/ファイル.conf", "/opt/ファイル.conf", "Japanese"),
        ];

        for (input, expected, description) in tests {
            let arr = string_to_c_char_array::<4096>(input);
            assert_eq!(sanitize_d_path(&arr), PathBuf::from(expected), "Failed for {}", description);
        }
    }

    #[test]
    fn sanitize_d_path_deleted_suffix() {
        let tests = [
            ("/tmp/test.txt (deleted)", "/tmp/test.txt", "ASCII with deleted suffix"),
            ("/tmp/файл.txt (deleted)", "/tmp/файл.txt", "Unicode with deleted suffix"),
            ("/etc/config.yaml", "/etc/config.yaml", "no deleted suffix"),
            ("/var/log/app/debug.log (deleted)", "/var/log/app/debug.log", "nested path with deleted suffix"),
        ];

        for (input, expected, description) in tests {
            let arr = string_to_c_char_array::<4096>(input);
            assert_eq!(sanitize_d_path(&arr), PathBuf::from(expected), "Failed for {}", description);
        }
    }

    #[test]
    fn sanitize_d_path_invalid_utf8() {
        let tests: &[(&[u8], &str, &str, &str)] = &[
            (
                &[b'/', b't', b'm', b'p', b'/', 0xFF, 0xFE, b'.', b't', b'x', b't'],
                "/tmp/",
                ".txt",
                "invalid continuation bytes",
            ),
            (
                &[b'/', b'v', b'a', b'r', b'/', b't', b'e', b's', b't', 0xE2, 0x80],
                "/var/",
                "",
                "truncated multi-byte sequence",
            ),
            (
                &[b'/', b'h', b'o', b'm', b'e', b'/', b'f', b'i', b'l', b'e', 0x80, b'.', b'l', b'o', b'g'],
                "/home/",
                ".log",
                "invalid start byte",
            ),
            (
                &[b'/', b't', b'm', b'p', b'/', 0xD1, 0x84, 0xFF, 0xD0, 0xBB, b'.', b't', b'x', b't'],
                "/tmp/",
                "",
                "mixed valid and invalid UTF-8",
            ),
        ];

        for (bytes, must_contain1, must_contain2, description) in tests {
            let arr = bytes_to_c_char_array::<4096>(bytes);
            let result = sanitize_d_path(&arr);
            let result_str = result.to_string_lossy();

            assert!(result_str.contains(must_contain1), "Failed for {} - should contain '{}'", description, must_contain1);
            if !must_contain2.is_empty() {
                assert!(result_str.contains(must_contain2), "Failed for {} - should contain '{}'", description, must_contain2);
            }
            assert!(result_str.contains('\u{FFFD}'), "Failed for {} - should contain replacement character", description);
        }
    }

    #[test]
    fn sanitize_d_path_invalid_utf8_with_deleted_suffix() {
        let invalid_with_deleted = bytes_to_c_char_array::<4096>(&[
            b'/', b't', b'm', b'p', b'/', 0xFF, 0xFE, b' ', b'(', b'd', b'e', b'l', b'e', b't', b'e', b'd', b')',
        ]);
        let result = sanitize_d_path(&invalid_with_deleted);
        let result_str = result.to_string_lossy();

        assert!(result_str.contains("/tmp/"));
        assert!(!result_str.ends_with(" (deleted)"));
        assert!(result_str.contains('\u{FFFD}'));
    }
}
