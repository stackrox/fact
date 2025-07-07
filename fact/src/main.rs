use std::env;

use aya::{programs::Lsm, Btf};
#[rustfmt::skip]
use log::debug;
use tokio::signal;

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

    // Include the eBPF object as raw bytes at compile-time and load it
    // at runtime.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/main.o"
    )))?;
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = ebpf.program_mut("test_file_open").unwrap().try_into()?;
    program.load("file_open", &btf)?;
    program.attach()?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
