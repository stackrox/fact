#[cfg(all(test, feature = "bpf-test"))]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};

use globset::GlobSet;
use serde::Serialize;

use fact_ebpf::{inode_key_t, monitored_t};

use process::Process;

pub(crate) mod parser;
pub(crate) mod process;

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
fn sanitize_d_path(s: &[u8]) -> PathBuf {
    let p = Path::new(OsStr::from_bytes(s));

    // Take the file name of the path and remove the " (deleted)" suffix
    // if present.
    if let Some(file_name) = p.file_name()
        && let Some(file_name) = file_name.to_string_lossy().strip_suffix(" (deleted)")
    {
        // The file name needed to be sanitized
        return p.parent().map(|p| p.join(file_name)).unwrap_or_default();
    }

    p.to_path_buf()
}

fn timestamp_to_proto(ts: u64) -> prost_types::Timestamp {
    let seconds = (ts / 1_000_000_000) as i64;
    let nanos = (ts % 1_000_000_000) as i32;
    prost_types::Timestamp { seconds, nanos }
}

#[cfg(all(test, feature = "bpf-test"))]
#[derive(Debug)]
pub(crate) enum EventTestData {
    Creation,
    Unlink,
    Chmod(u16, u16),
    Rename(PathBuf),
}

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    timestamp: u64,
    hostname: &'static str,
    process: Process,
    file: FileData,
}

impl Event {
    #[cfg(all(test, feature = "bpf-test"))]
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
            parent_inode: Default::default(),
            monitored: Default::default(),
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
            EventTestData::Rename(old_path) => {
                let data = RenameFileData {
                    new: inner,
                    old: BaseFileData {
                        filename: old_path,
                        ..Default::default()
                    },
                };
                FileData::Rename(data)
            }
        };

        Ok(Event {
            timestamp,
            hostname,
            process,
            file,
        })
    }

    pub fn is_creation(&self) -> bool {
        matches!(self.file, FileData::Creation(_) | FileData::MkDir(_))
    }

    pub fn is_mkdir(&self) -> bool {
        matches!(self.file, FileData::MkDir(_))
    }

    pub fn is_rmdir(&self) -> bool {
        matches!(self.file, FileData::RmDir(_))
    }

    pub fn is_deletion(&self) -> bool {
        matches!(self.file, FileData::Unlink(_) | FileData::RmDir(_))
    }

    pub fn is_rename(&self) -> bool {
        matches!(self.file, FileData::Rename(_))
    }

    /// Unwrap the inner FileData and return the inode that triggered
    /// the event.
    ///
    /// In the case of operations that involve two inodes, like rename,
    /// the 'new' inode will be returned.
    pub fn get_inode(&self) -> &inode_key_t {
        match &self.file {
            FileData::Open(data) => &data.inode,
            FileData::Creation(data) => &data.inode,
            FileData::MkDir(data) => &data.inode,
            FileData::RmDir(data) => &data.inode,
            FileData::Unlink(data) => &data.inode,
            FileData::Chmod(data) => &data.inner.inode,
            FileData::Chown(data) => &data.inner.inode,
            FileData::Rename(data) => &data.new.inode,
        }
    }

    /// Get the parent inode for the file in this event.
    pub fn get_parent_inode(&self) -> &inode_key_t {
        match &self.file {
            FileData::Open(data) => &data.parent_inode,
            FileData::Creation(data) => &data.parent_inode,
            FileData::MkDir(data) => &data.parent_inode,
            FileData::RmDir(data) => &data.parent_inode,
            FileData::Unlink(data) => &data.parent_inode,
            FileData::Chmod(data) => &data.inner.parent_inode,
            FileData::Chown(data) => &data.inner.parent_inode,
            FileData::Rename(data) => &data.new.parent_inode,
        }
    }

    /// Same as `get_inode` but returning the 'old' inode for operations
    /// like rename. For operations that involve a single inode, `None`
    /// will be returned.
    pub fn get_old_inode(&self) -> Option<&inode_key_t> {
        match &self.file {
            FileData::Rename(data) => Some(&data.old.inode),
            _ => None,
        }
    }

    pub fn get_filename(&self) -> &PathBuf {
        match &self.file {
            FileData::Open(data) => &data.filename,
            FileData::Creation(data) => &data.filename,
            FileData::MkDir(data) => &data.filename,
            FileData::RmDir(data) => &data.filename,
            FileData::Unlink(data) => &data.filename,
            FileData::Chmod(data) => &data.inner.filename,
            FileData::Chown(data) => &data.inner.filename,
            FileData::Rename(data) => &data.new.filename,
        }
    }

    pub fn get_old_filename(&self) -> Option<&PathBuf> {
        match &self.file {
            FileData::Rename(data) => Some(&data.old.filename),
            _ => None,
        }
    }

    pub fn get_host_path(&self) -> &PathBuf {
        match &self.file {
            FileData::Open(data) => &data.host_file,
            FileData::Creation(data) => &data.host_file,
            FileData::MkDir(data) => &data.host_file,
            FileData::RmDir(data) => &data.host_file,
            FileData::Unlink(data) => &data.host_file,
            FileData::Chmod(data) => &data.inner.host_file,
            FileData::Chown(data) => &data.inner.host_file,
            FileData::Rename(data) => &data.new.host_file,
        }
    }

    pub fn get_old_host_path(&self) -> Option<&PathBuf> {
        match &self.file {
            FileData::Rename(data) => Some(&data.old.host_file),
            _ => None,
        }
    }

    /// Set the `host_file` field of the event to the one provided.
    ///
    /// In the case of operations that involve two paths, like rename,
    /// the 'new' host_file will be set.
    pub fn set_host_path(&mut self, host_path: PathBuf) {
        match &mut self.file {
            FileData::Open(data) => data.host_file = host_path,
            FileData::Creation(data) => data.host_file = host_path,
            FileData::MkDir(data) => data.host_file = host_path,
            FileData::RmDir(data) => data.host_file = host_path,
            FileData::Unlink(data) => data.host_file = host_path,
            FileData::Chmod(data) => data.inner.host_file = host_path,
            FileData::Chown(data) => data.inner.host_file = host_path,
            FileData::Rename(data) => data.new.host_file = host_path,
        }
    }

    /// Same as `set_host_path` but setting the 'old' host_file for
    /// operations that have one, like rename.
    pub fn set_old_host_path(&mut self, host_path: PathBuf) {
        if let FileData::Rename(data) = &mut self.file {
            data.old.host_file = host_path
        }
    }

    pub fn get_monitored(&self) -> monitored_t {
        match &self.file {
            FileData::Open(data) => data.monitored,
            FileData::Creation(data) => data.monitored,
            FileData::MkDir(data) => data.monitored,
            FileData::RmDir(data) => data.monitored,
            FileData::Unlink(data) => data.monitored,
            FileData::Chmod(data) => data.inner.monitored,
            FileData::Chown(data) => data.inner.monitored,
            FileData::Rename(data) => data.new.monitored,
        }
    }

    pub fn get_old_monitored(&self) -> Option<monitored_t> {
        match &self.file {
            FileData::Rename(data) => Some(data.old.monitored),
            _ => None,
        }
    }

    /// Determine if the event should be ignored.
    ///
    /// With wildcards, the kernel can only match on the inode and
    /// then the longest non-wildcard prefix (e.g. for /etc/**/*.conf,
    /// the kernel matches up to /etc/).
    ///
    /// The kernel sets inode to 0 when it matched via path prefix only.
    /// so we only need to perform a glob match against the filename.
    ///
    /// We also need to check the old values for rename events.
    pub fn is_ignored(&self, globset: &GlobSet) -> bool {
        self.get_monitored() != monitored_t::MONITORED_BY_INODE
            && self
                .get_old_monitored()
                .is_none_or(|m| m != monitored_t::MONITORED_BY_INODE)
            && !globset.is_match(self.get_filename())
            && self
                .get_old_filename()
                .is_none_or(|path| !globset.is_match(path))
    }

    pub fn is_monitored_by_parent(&self) -> bool {
        self.get_monitored() == monitored_t::MONITORED_BY_PARENT
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
    MkDir(BaseFileData),
    RmDir(BaseFileData),
    Unlink(BaseFileData),
    Chmod(ChmodFileData),
    Chown(ChownFileData),
    Rename(RenameFileData),
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
            FileData::MkDir(_) => {
                unreachable!("MkDir event reached protobuf conversion");
            }
            FileData::RmDir(_) => {
                unreachable!("RmDir event reached protobuf conversion");
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
            FileData::Rename(event) => {
                let f_act = fact_api::FileRename::from(event);
                fact_api::file_activity::File::Rename(f_act)
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
            (FileData::MkDir(this), FileData::MkDir(other)) => this == other,
            (FileData::RmDir(this), FileData::RmDir(other)) => this == other,
            (FileData::Unlink(this), FileData::Unlink(other)) => this == other,
            (FileData::Chmod(this), FileData::Chmod(other)) => this == other,
            (FileData::Rename(this), FileData::Rename(other)) => this == other,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct BaseFileData {
    pub filename: PathBuf,
    host_file: PathBuf,
    inode: inode_key_t,
    parent_inode: inode_key_t,
    monitored: monitored_t,
}

impl BaseFileData {
    pub fn new(
        filename: &[u8],
        inode: inode_key_t,
        parent_inode: inode_key_t,
        monitored: monitored_t,
    ) -> anyhow::Result<Self> {
        Ok(BaseFileData {
            filename: sanitize_d_path(filename),
            host_file: PathBuf::new(), // this field is set by HostScanner
            inode,
            parent_inode,
            monitored,
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

#[derive(Debug, Clone, Serialize)]
pub struct RenameFileData {
    new: BaseFileData,
    old: BaseFileData,
}

impl From<RenameFileData> for fact_api::FileRename {
    fn from(RenameFileData { new, old }: RenameFileData) -> Self {
        let new = fact_api::FileActivityBase::from(new);
        let old = fact_api::FileActivityBase::from(old);
        fact_api::FileRename {
            old: Some(old),
            new: Some(new),
        }
    }
}

#[cfg(test)]
impl PartialEq for RenameFileData {
    fn eq(&self, other: &Self) -> bool {
        self.new == other.new && self.old == other.old
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_d_path_valid_utf8() {
        let tests = [
            ("/etc/test", "/etc/test", "ASCII"),
            ("/tmp/файл.txt", "/tmp/файл.txt", "Cyrillic"),
            (
                "/home/user/测试文件.log",
                "/home/user/测试文件.log",
                "Chinese",
            ),
            ("/data/🚀rocket.dat", "/data/🚀rocket.dat", "Emoji"),
            (
                "/var/log/app-данные-数据-🐛.log",
                "/var/log/app-данные-数据-🐛.log",
                "Mixed Unicode",
            ),
            ("/home/ملف.txt", "/home/ملف.txt", "Arabic"),
            ("/opt/ファイル.conf", "/opt/ファイル.conf", "Japanese"),
        ];

        for (input, expected, description) in tests {
            assert_eq!(
                sanitize_d_path(input.as_bytes()),
                PathBuf::from(expected),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn sanitize_d_path_deleted_suffix() {
        let tests = [
            (
                "/tmp/test.txt (deleted)",
                "/tmp/test.txt",
                "ASCII with deleted suffix",
            ),
            (
                "/tmp/файл.txt (deleted)",
                "/tmp/файл.txt",
                "Unicode with deleted suffix",
            ),
            ("/etc/config.yaml", "/etc/config.yaml", "No deleted suffix"),
            (
                "/var/log/app/debug.log (deleted)",
                "/var/log/app/debug.log",
                "Nested path with deleted suffix",
            ),
        ];

        for (input, expected, description) in tests {
            assert_eq!(
                sanitize_d_path(input.as_bytes()),
                PathBuf::from(expected),
                "Failed for {}",
                description
            );
        }
    }

    #[test]
    fn sanitize_d_path_invalid_utf8() {
        use regex::Regex;

        let tests: &[(&[u8], &str, &str)] = &[
            (
                b"/tmp/\xFF\xFE.txt",
                r"^/tmp/\u{FFFD}+\.txt$",
                "Invalid continuation bytes",
            ),
            (
                b"/var/test\xE2\x80",
                r"^/var/test\u{FFFD}+$",
                "Truncated multi-byte sequence",
            ),
            (
                b"/home/file\x80.log",
                r"^/home/file\u{FFFD}\.log$",
                "Invalid start byte",
            ),
            (
                b"/tmp/\xD1\x84\xFF\xD0\xBB.txt",
                r"^/tmp/ф\u{FFFD}л\.txt$",
                "Mixed valid and invalid UTF-8",
            ),
        ];

        for (bytes, pattern, description) in tests {
            let result = sanitize_d_path(bytes);
            let result_str = result.to_string_lossy();

            let re = Regex::new(pattern).expect("Invalid regex pattern");
            assert!(
                re.is_match(&result_str),
                "Failed for {}: expected pattern '{}', got '{}'",
                description,
                pattern,
                result_str
            );
        }
    }

    #[test]
    fn sanitize_d_path_invalid_utf8_with_deleted_suffix() {
        let result = sanitize_d_path(b"/tmp/\xFF\xFE (deleted)");
        let result_str = result.to_string_lossy();

        assert!(result_str.contains("/tmp/"));
        assert!(!result_str.ends_with(" (deleted)"));
        assert!(result_str.contains('\u{FFFD}'));
    }
}
