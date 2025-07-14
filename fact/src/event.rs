use std::ffi::CStr;

use crate::bpf;

use bpf::bindings::event_t;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Event {
    comm: String,
    filename: String,
    host_file: String,
}

impl TryFrom<&event_t> for Event {
    type Error = anyhow::Error;

    fn try_from(value: &event_t) -> Result<Self, Self::Error> {
        let comm = unsafe { CStr::from_ptr(value.comm.as_ptr()) }
            .to_str()?
            .to_owned();
        let filename = unsafe { CStr::from_ptr(value.filename.as_ptr()) }
            .to_str()?
            .to_owned();
        let host_file = unsafe { CStr::from_ptr(value.host_file.as_ptr()) }
            .to_str()?
            .to_owned();

        Ok(Event {
            comm,
            filename,
            host_file,
        })
    }
}
