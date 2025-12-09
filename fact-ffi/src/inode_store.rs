use std::{
    ffi::{c_char, CString},
    os::fd::{AsFd, AsRawFd},
    path::Path,
};

use aya::maps::MapData;

#[link(name = "inode")]
unsafe extern "C" {
    fn add_path(map_fd: i32, path: *const c_char, host_path: *const c_char) -> i32;
}

fn path_to_cstring(path: &Path) -> anyhow::Result<CString> {
    let path = path.as_os_str().to_string_lossy();
    Ok(CString::new(path.to_string())?)
}

pub fn try_add_path(
    inode_store: &mut MapData,
    path: &Path,
    host_path: &Path,
) -> anyhow::Result<()> {
    let path = path_to_cstring(path)?;
    let host_path = path_to_cstring(host_path)?;
    let fd = inode_store.fd().as_fd().as_raw_fd();
    let res = unsafe { add_path(fd, path.as_ptr(), host_path.as_ptr()) };

    if res != 0 {
        anyhow::bail!("Failed to add inode: {res}");
    }
    Ok(())
}
