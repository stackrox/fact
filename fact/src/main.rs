use std::ffi::CStr;

use aya::{maps::RingBuf, programs::Lsm, Btf};
use log::debug;
use tokio::{io::unix::AsyncFd, signal, task::yield_now};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[allow(dead_code)]
#[derive(Debug)]
struct Event {
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Include the BPF object as raw bytes at compile-time and load it
    // at runtime.
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/main.o"
    )))?;
    let ringbuf = bpf.take_map("rb").unwrap();
    let ringbuf = RingBuf::try_from(ringbuf)?;
    let mut async_fd = AsyncFd::new(ringbuf)?;

    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("test_file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    tokio::spawn(async move {
        loop {
            let mut guard = async_fd.readable_mut().await.unwrap();
            let ringbuf = guard.get_inner_mut();
            while let Some(event) = ringbuf.next() {
                let event: &event_t = unsafe { &*(event.as_ptr() as *const _) };
                let event: Event = event.try_into().unwrap();
                println!("{event:?}");
            }
            guard.clear_ready();
            yield_now().await;
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
