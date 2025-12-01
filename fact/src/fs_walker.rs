use std::path::Path;

use aya::maps::MapData;
use log::debug;

use crate::host_info;

pub fn walk_path(inode_store: &mut MapData, path: &Path) -> anyhow::Result<()> {
    if path.is_dir() {
        for entry in (path.read_dir()?).flatten() {
            walk_path(inode_store, &entry.path())?;
        }
    }

    if path.is_file() {
        let host_path = path
            .strip_prefix(host_info::get_host_mount())
            .unwrap_or(path);
        let host_path = Path::new("/").join(host_path);
        debug!("Adding inode: {path:?} - {host_path:?}");
        fact_ffi::inode_store::try_add_path(inode_store, path, &host_path)?;
    }

    Ok(())
}
