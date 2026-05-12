use std::ffi::{CStr, CString};

use anyhow::bail;
use aya::maps::ring_buf::RingBufItem;
use byteorder::{ByteOrder, NativeEndian};
use fact_ebpf::{file_activity_type_t, inode_key_t, monitored_t};
use log::warn;

use crate::{
    event::{
        BaseFileData, ChmodFileData, ChownFileData, Event, FileData, RenameFileData,
        process::{Lineage, Process},
        sanitize_d_path,
    },
    host_info,
};

pub(crate) struct Parser<'a> {
    data: &'a [u8],
}

impl Parser<'_> {
    fn read_u8(&mut self) -> Option<u8> {
        let (val, data) = self.data.split_at_checked(size_of::<u8>())?;
        self.data = data;
        Some(val[0])
    }

    fn read_u16(&mut self) -> Option<u16> {
        let (val, data) = self.data.split_at_checked(size_of::<u16>())?;
        self.data = data;
        Some(NativeEndian::read_u16(val))
    }

    fn read_u32(&mut self) -> Option<u32> {
        let (val, data) = self.data.split_at_checked(size_of::<u32>())?;
        self.data = data;
        Some(NativeEndian::read_u32(val))
    }

    fn read_u64(&mut self) -> Option<u64> {
        let (val, data) = self.data.split_at_checked(size_of::<u64>())?;
        self.data = data;
        Some(NativeEndian::read_u64(val))
    }

    /// Parse inode information from the inner data.
    ///
    /// Under the hood, inodes are represented by two u32 integers.
    fn parse_inode(&mut self) -> Option<inode_key_t> {
        let inode = self.read_u32()?;
        let dev = self.read_u32()?;

        Some(inode_key_t { inode, dev })
    }

    /// Parse a buffer from the inner data.
    ///
    /// This method parses buffers as they are added to the ringbuffer
    /// by the kernel side BPF programs. The format these programs use
    /// is relatively straightforward, they use 2 bytes to encode the
    /// length of the buffer in bytes, then put the buffer right after,
    /// looking something like this:
    ///
    /// |--|--------------|-------
    /// |  |              | ^ rest of the event
    /// |  |              ^ buffer end
    /// |  ^ buffer start
    /// ^ length of the buffer
    ///
    /// This allows parsing fairly easy in userspace, we can simply
    /// read a u16 for the size of the buffer, then take as many bytes
    /// as that value indicates.
    ///
    /// This representation also works for both strings and binary
    /// blobs, so it allows for quite good flexibility, leaving the
    /// specialization of the type to the caller.
    fn parse_buffer(&mut self) -> Option<&[u8]> {
        let len = self.read_u16()?;
        let (buf, data) = self.data.split_at_checked(len as usize)?;
        self.data = data;
        Some(buf)
    }

    /// Parse the process comm value.
    ///
    /// For simplicity, the kernel side BPF program loads the result of
    /// calling the bpf_get_current_comm helper directly onto the event.
    /// The resulting value loaded in is 16 bytes with a guaranteed
    /// null terminator and null padding if needed.
    ///
    /// We could save a few bytes if we were to retrieve the string
    /// length in kernel side and load a generic buffer onto the event
    /// like `Parser::parse_buffer` expects, but we would need to do a
    /// bit more work kernel side that is not worth it.
    fn parse_comm(&mut self) -> Option<CString> {
        let (val, data) = self.data.split_at_checked(16)?;
        let res = CStr::from_bytes_until_nul(val).ok()?;
        self.data = data;
        Some(res.to_owned())
    }

    /// Parse the arguments of a process.
    ///
    /// The kernel stores arguments as a sequence of null terminated
    /// strings in a single buffer, we copy that blob directly onto the
    /// ringbuffer and prepend the actual length we copied in the same
    /// way `Event::parse_buffer` expects. This way we can read the
    /// buffer and then iterate over the null strings, mapping them to
    /// `CString`s in a vector.
    ///
    /// # Safety
    ///
    /// * The BPF program loading the arguments must ensure the last
    ///   portion ends with a null terminator, even if we truncate it
    ///   for performance reasons.
    fn parse_args(&mut self) -> anyhow::Result<Vec<CString>> {
        let Some(buf) = self.parse_buffer() else {
            bail!("Failed to get arguments length");
        };

        let args = buf
            .split_inclusive(|a| *a == 0)
            .map(|arg| CString::from_vec_with_nul(arg.to_vec()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(args)
    }

    /// Parse a `Lineage` object from a ringbuffer event.
    ///
    /// # Safety
    ///
    /// * The order of fields parsed must match the order used by the
    ///   BPF programs.
    fn parse_process_lineage(&mut self) -> anyhow::Result<Lineage> {
        let Some(uid) = self.read_u32() else {
            bail!("Failed to parse lineage uid");
        };
        let Some(exe_path) = self.parse_buffer() else {
            bail!("Failed to parse lineage exe_path");
        };
        let exe_path = sanitize_d_path(exe_path);

        let lineage = Lineage::new(uid, exe_path);

        Ok(lineage)
    }

    /// Parse a `Process` from a ringbuffer event.
    ///
    /// # Safety
    ///
    /// * The order of fields must match the order used by the BPF
    ///   programs.
    fn parse_process(&mut self) -> anyhow::Result<Process> {
        let Some(uid) = self.read_u32() else {
            bail!("Failed to parse uid");
        };
        let username = host_info::get_username(uid);
        let Some(gid) = self.read_u32() else {
            bail!("Failed to parse gid");
        };
        let Some(login_uid) = self.read_u32() else {
            bail!("Failed to parse login_uid");
        };
        let Some(pid) = self.read_u32() else {
            bail!("Failed to parse pid");
        };
        let Some(comm) = self.parse_comm() else {
            bail!("Failed to parse comm");
        };
        let args = self.parse_args()?;
        let Some(exe_path) = self.parse_buffer() else {
            bail!("Failed to parse exe_path");
        };
        let exe_path = sanitize_d_path(exe_path);
        let Some(cgroup) = self.parse_buffer() else {
            bail!("Failed to parse cgroup");
        };
        let cgroup = str::from_utf8(cgroup)?;
        let container_id = Process::extract_container_id(cgroup);
        let Some(in_root_mount_ns) = self.read_u8() else {
            bail!("Failed to parse in_root_mount_ns");
        };
        let in_root_mount_ns = in_root_mount_ns != 0;
        let Some(lineage_len) = self.read_u16() else {
            bail!("Failed to parse lineage length");
        };
        let mut lineage = Vec::with_capacity(lineage_len as usize);
        for _ in 0..lineage_len {
            let l = self.parse_process_lineage()?;
            lineage.push(l);
        }

        let process = Process::new(
            comm,
            args,
            exe_path,
            container_id,
            uid,
            username,
            gid,
            login_uid,
            pid,
            in_root_mount_ns,
            lineage,
        );

        Ok(process)
    }

    /// Consume the parser and create an Event
    ///
    /// Parsing an event is a destructive operation, the parser is
    /// created through a ringbuffer entry that has a single event in
    /// it, so it cannot be reused.
    pub(crate) fn parse(mut self) -> anyhow::Result<Event> {
        let Some(event_type) = self.read_u16() else {
            bail!("Failed to read event type");
        };
        let event_type = file_activity_type_t(event_type.into());

        let Some(timestamp) = self.read_u64() else {
            bail!("Failed to parse timestamp");
        };
        let timestamp = timestamp + host_info::get_boot_time();

        let process = self.parse_process()?;

        let Some(monitored) = self.read_u8() else {
            bail!("Failed to parse monitored field");
        };
        let monitored = monitored_t(monitored.into());

        let Some(inode) = self.parse_inode() else {
            bail!("Failed to parse inode");
        };

        let Some(parent_inode) = self.parse_inode() else {
            bail!("Failed to parse parent_inode");
        };

        let Some(filename) = self.parse_buffer() else {
            bail!("Failed to parse filename");
        };

        let inner = BaseFileData::new(filename, inode, parent_inode, monitored)?;

        let file = match event_type {
            file_activity_type_t::FILE_ACTIVITY_CREATION => FileData::Creation(inner),
            file_activity_type_t::FILE_ACTIVITY_OPEN => FileData::Open(inner),
            file_activity_type_t::FILE_ACTIVITY_UNLINK => FileData::Unlink(inner),
            file_activity_type_t::DIR_ACTIVITY_CREATION => FileData::MkDir(inner),
            file_activity_type_t::DIR_ACTIVITY_UNLINK => FileData::RmDir(inner),
            file_activity_type_t::FILE_ACTIVITY_CHMOD => {
                let Some(new_mode) = self.read_u16() else {
                    bail!("Failed to read new_mode field");
                };
                let Some(old_mode) = self.read_u16() else {
                    bail!("Failed to read old_mode field");
                };

                FileData::Chmod(ChmodFileData {
                    inner,
                    new_mode,
                    old_mode,
                })
            }
            file_activity_type_t::FILE_ACTIVITY_CHOWN => {
                let Some(new_uid) = self.read_u32() else {
                    bail!("Failed to read new_uid field");
                };
                let Some(new_gid) = self.read_u32() else {
                    bail!("Failed to read new_gid field");
                };
                let Some(old_uid) = self.read_u32() else {
                    bail!("Failed to read old_uid field");
                };
                let Some(old_gid) = self.read_u32() else {
                    bail!("Failed to read old_gid field");
                };

                FileData::Chown(ChownFileData {
                    inner,
                    new_uid,
                    new_gid,
                    old_uid,
                    old_gid,
                })
            }
            file_activity_type_t::FILE_ACTIVITY_RENAME => {
                let Some(old_monitored) = self.read_u8() else {
                    bail!("Failed to read old_monitored field");
                };
                let old_monitored = monitored_t(old_monitored.into());
                let Some(old_inode) = self.parse_inode() else {
                    bail!("Failed to read old_inode field");
                };
                let Some(old_filename) = self.parse_buffer() else {
                    bail!("Failed to read old_filename field");
                };

                FileData::Rename(RenameFileData {
                    new: inner,
                    old: BaseFileData::new(
                        old_filename,
                        old_inode,
                        Default::default(),
                        old_monitored,
                    )?,
                })
            }
            invalid => unreachable!("Invalid event type: {invalid:?}"),
        };

        if !self.data.is_empty() {
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

impl<'a> From<&'a RingBufItem<'a>> for Parser<'a> {
    fn from(data: &'a RingBufItem<'a>) -> Self {
        Parser { data }
    }
}
