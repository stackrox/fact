use std::ffi::CStr;

use crate::bpf::{self, bindings::process_t};

use bpf::bindings::event_t;

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct Process {
    comm: String,
    uid: u32,
    gid: u32,
    login_uid: u32,
}

impl TryFrom<&process_t> for Process {
    type Error = anyhow::Error;

    fn try_from(value: &process_t) -> Result<Self, Self::Error> {
        let process_t {
            comm,
            uid,
            gid,
            login_uid,
        } = value;
        let comm = unsafe { CStr::from_ptr(comm.as_ptr()) }
            .to_str()?
            .to_owned();

        Ok(Process {
            comm,
            uid: *uid,
            gid: *gid,
            login_uid: *login_uid,
        })
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct Event {
    process: Process,
    filename: String,
    host_file: String,
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let event_t {
            process,
            filename,
            host_file,
        } = value;
        let filename = unsafe { CStr::from_ptr(filename.as_ptr()) }
            .to_str()?
            .to_owned();
        let host_file = unsafe { CStr::from_ptr(host_file.as_ptr()) }
            .to_str()?
            .to_owned();

        Ok(Event {
            process: process.try_into()?,
            filename,
            host_file,
        })
    }
}
