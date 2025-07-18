use std::ffi::CStr;

use crate::bpf::{self, bindings::process_t};

use bpf::bindings::event_t;

#[allow(dead_code)]
#[derive(Debug, Default)]
pub struct Process {
    comm: String,
    args: Vec<String>,
    exe_path: String,
    uid: u32,
    gid: u32,
    login_uid: u32,
}

impl TryFrom<&process_t> for Process {
    type Error = anyhow::Error;

    fn try_from(value: &process_t) -> Result<Self, Self::Error> {
        let process_t {
            comm,
            args,
            exe_path,
            uid,
            gid,
            login_uid,
        } = value;
        let comm = unsafe { CStr::from_ptr(comm.as_ptr()) }
            .to_str()?
            .to_owned();
        let exe_path = unsafe { CStr::from_ptr(exe_path.as_ptr()) }
            .to_str()?
            .to_owned();

        let mut converted_args = Vec::new();
        let mut offset = 0;
        while offset < 4096 {
            let arg = unsafe { CStr::from_ptr(args.as_ptr().add(offset)) }
                .to_str()?
                .to_owned();
            if arg.is_empty() {
                break;
            }
            offset += arg.len() + 1;
            converted_args.push(arg);
        }

        Ok(Process {
            comm,
            args: converted_args,
            exe_path,
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
    is_external_mount: bool,
    filename: String,
    host_file: String,
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let event_t {
            process,
            is_external_mount,
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
            is_external_mount: *is_external_mount != 0,
            filename,
            host_file,
        })
    }
}
