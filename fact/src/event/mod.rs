//! Event handling module
//!
//! This module provides Rust types that make it easier and safer to
//! interact with the information received from the BPF programs.
//!
//! The main interest is the `Event` type, which can be parsed from an
//! element received from the ringbuffer and passed around to other
//! components.

#[cfg(test)]
use std::time::{SystemTime, UNIX_EPOCH};
use std::{
    ffi::OsStr,
    ops::{BitOrAssign, ShlAssign},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
};

use anyhow::bail;
use aya::maps::ring_buf::RingBufItem;
use log::warn;
use serde::Serialize;

use fact_ebpf::{file_activity_type_t, inode_key_t};

use crate::host_info;
use process::Process;

pub(crate) mod process;

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
            inode: Default::default(),
        };
        let file = match event_type {
            file_activity_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            file_activity_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => FileData::Unlink(inner),
            invalid => unreachable!("Invalid event type: {invalid:?}"),
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
        }
    }

    pub fn set_host_path(&mut self, host_path: PathBuf) {
        match &mut self.file {
            FileData::Open(data) => data.host_file = host_path,
            FileData::Creation(data) => data.host_file = host_path,
            FileData::Unlink(data) => data.host_file = host_path,
        }
    }

    /// Parse an integer value from the supplied slice.
    ///
    /// This method parses integers as they are added to the ringbuffer
    /// by the kernel side BPF programs. For simplicity, integers are
    /// always loaded in Big Endian format regardless of the
    /// architecture the program runs on.
    fn parse_int<T>(s: &[u8]) -> Option<(T, &[u8])>
    where
        T: From<u8> + BitOrAssign<T> + ShlAssign<i32>,
    {
        let len = size_of::<T>();
        let (val, s) = s.split_at_checked(len)?;
        let mut res = T::from(0);
        for byte in val {
            // Types with size of 1 byte cannot be shifted since they
            // would overflow, so we only shift bigger types.
            if len > 1 {
                res <<= 8;
            }
            res |= (*byte).into();
        }
        Some((res, s))
    }

    /// Parse a buffer from the supplied slice.
    ///
    /// This method parses buffers as they are added to the ringbuffer
    /// by the kernel side BPF programs. The format these programs use
    /// is relatively straightforward, they use 2 bytes in Big Endian
    /// format to encode the length of the buffer in bytes, then put
    /// the buffer right after, looking something like this:
    ///
    /// |--|--------------|-------
    /// |  |              | ^ rest of the event
    /// |  |              ^ buffer end
    /// |  ^ buffer start
    /// ^ length of the buffer
    ///
    /// This allows parsing fairly easy in userspace, we can simply
    /// parse a u16 for the size of the buffer, then take as many bytes
    /// as that value indicates.
    ///
    /// This representation also works for both strings and binary
    /// blobs, so it allows for quite good flexibility, leaving the
    /// specialization of the type to the caller.
    fn parse_buffer(s: &[u8]) -> Option<(&[u8], &[u8])> {
        let (len, s) = Event::parse_int::<u16>(s)?;
        s.split_at_checked(len as usize)
    }
}

impl TryFrom<RingBufItem<'_>> for Event {
    type Error = anyhow::Error;

    fn try_from(value: RingBufItem) -> Result<Self, Self::Error> {
        let Some((event_type, value)) = Event::parse_int::<u16>(&value) else {
            bail!("Failed to read event type");
        };
        let event_type = event_type.into();

        let Some((timestamp, value)) = Event::parse_int::<u64>(value) else {
            bail!("Failed to parse timestamp");
        };
        let timestamp = timestamp + host_info::get_boot_time();

        let (process, value) = Process::parse(value)?;

        let Some((inode, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse inode");
        };
        let Some((dev, value)) = Event::parse_int::<u32>(value) else {
            bail!("Failed to parse device number");
        };
        let inode = inode_key_t { inode, dev };
        let Some((filename, value)) = Event::parse_buffer(value) else {
            bail!("Failed to parse filename");
        };
        let filename = OsStr::from_bytes(filename).into();
        let file = FileData::new(event_type, filename, inode)?;

        // Handling of special fields.
        // TODO: Currently implemented events have no special fields.
        match event_type {
            file_activity_type_t::FILE_ACTIVITY_CREATION
            | file_activity_type_t::FILE_ACTIVITY_OPEN
            | file_activity_type_t::FILE_ACTIVITY_UNLINK => {}
            invalid => unreachable!("missing special field treatment for event type {invalid:?}"),
        }

        if !value.is_empty() {
            warn!("Event has remaining data");
        }

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
}

impl FileData {
    pub fn new(
        event_type: file_activity_type_t,
        filename: PathBuf,
        inode: inode_key_t,
    ) -> anyhow::Result<Self> {
        let inner = BaseFileData::new(filename, inode)?;
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
    inode: inode_key_t,
}

impl BaseFileData {
    pub fn new(filename: PathBuf, inode: inode_key_t) -> anyhow::Result<Self> {
        Ok(BaseFileData {
            filename,
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

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;

    struct ParseIntTestCase<'a, T> {
        input: &'a [u8],
        expected: Option<(T, &'a [u8])>,
    }

    impl<'a, T> ParseIntTestCase<'a, T> {
        fn new(input: &'a [u8], expected: Option<(T, &'a [u8])>) -> Self {
            ParseIntTestCase { input, expected }
        }
    }

    fn test_parse_int<T>(ParseIntTestCase { input, expected }: &ParseIntTestCase<T>)
    where
        T: From<u8> + BitOrAssign<T> + ShlAssign<i32> + Debug + PartialEq,
    {
        let res = Event::parse_int::<T>(input);
        assert_eq!(
            res, *expected,
            "\ninput: {input:#x?}\nexpected: {expected:#x?}\nres: {res:#x?}"
        )
    }

    #[test]
    fn test_parse_u8() {
        let tests = &[
            ParseIntTestCase::new(&[0xef], Some((0xef, &[]))),
            ParseIntTestCase::new(&[0xef, 0x00], Some((0xef, &[0x00]))),
            ParseIntTestCase::new(&[0xbe, 0xef, 0x00], Some((0xbe, &[0xef, 0x00]))),
            ParseIntTestCase::new(&[], None),
        ];

        for test in tests {
            test_parse_int::<u8>(test);
        }
    }

    #[test]
    fn test_parse_u16() {
        let tests = &[
            ParseIntTestCase::new(&[0xbe, 0xef], Some((0xbeef, &[]))),
            ParseIntTestCase::new(&[0xbe, 0xef, 0x00], Some((0xbeef, &[0x00]))),
            ParseIntTestCase::new(
                &[0xbe, 0xef, 0xbe, 0xef, 0x00],
                Some((0xbeef, &[0xbe, 0xef, 0x00])),
            ),
            ParseIntTestCase::new(&[0xef], None),
            ParseIntTestCase::new(&[], None),
        ];

        for test in tests {
            test_parse_int::<u16>(test);
        }
    }

    #[test]
    fn test_parse_u32() {
        let tests = &[
            ParseIntTestCase::new(&[0xde, 0xad, 0xbe, 0xef], Some((0xdeadbeef, &[]))),
            ParseIntTestCase::new(&[0xde, 0xad, 0xbe, 0xef, 0x00], Some((0xdeadbeef, &[0x00]))),
            ParseIntTestCase::new(
                &[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x00],
                Some((0xdeadbeef, &[0xde, 0xad, 0xbe, 0xef, 0x00])),
            ),
            ParseIntTestCase::new(&[0xad, 0xbe, 0xef], None),
            ParseIntTestCase::new(&[], None),
        ];

        for test in tests {
            test_parse_int::<u32>(test);
        }
    }

    #[test]
    fn test_parse_u64() {
        let tests = &[
            ParseIntTestCase::new(
                &[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef],
                Some((0xdeadbeefdeadbeef, &[])),
            ),
            ParseIntTestCase::new(
                &[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x00],
                Some((0xdeadbeefdeadbeef, &[0x00])),
            ),
            ParseIntTestCase::new(
                &[
                    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde,
                    0xad, 0xbe, 0xef, 0x00,
                ],
                Some((
                    0xdeadbeefdeadbeef,
                    &[0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0x00],
                )),
            ),
            ParseIntTestCase::new(&[0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef], None),
            ParseIntTestCase::new(&[], None),
        ];

        for test in tests {
            test_parse_int::<u64>(test);
        }
    }

    #[test]
    fn test_parse_buffer() {
        struct TestCase<'a> {
            input: &'a [u8],
            expected: Option<(&'a [u8], &'a [u8])>,
        }
        let tests = &[
            TestCase {
                input: b"\x00\x0B/usr/bin/rm",
                expected: Some((b"/usr/bin/rm", &[])),
            },
            TestCase {
                input: b"\x00\x0B/usr/bin/",
                expected: None,
            },
            TestCase {
                input: b"\x00\x0E/usr/bin/touch ignored",
                expected: Some((b"/usr/bin/touch", b" ignored")),
            },
            TestCase {
                input: b"\x00\x00\x00\x0E/usr/bin/touch ignored",
                expected: Some((b"", b"\x00\x0E/usr/bin/touch ignored")),
            },
            TestCase {
                input: b"",
                expected: None,
            },
        ];
        for TestCase { input, expected } in tests {
            let res = Event::parse_buffer(input);
            assert_eq!(res, *expected, "input: {}", String::from_utf8_lossy(input));
        }
    }
}
