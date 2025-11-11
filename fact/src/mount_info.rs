use std::{
    collections::HashMap,
    fs::read_to_string,
    path::{Path, PathBuf},
};

use anyhow::bail;

use crate::host_info;

#[derive(Debug)]
pub struct MountEntry {
    pub root: PathBuf,
    pub mount_point: PathBuf,
}

#[derive(Debug)]
pub struct MountInfo(HashMap<u32, Vec<MountEntry>>);

impl MountInfo {
    pub fn new() -> anyhow::Result<Self> {
        let cache = MountInfo::build_cache()?;
        Ok(MountInfo(cache))
    }

    pub fn refresh(&mut self) -> anyhow::Result<()> {
        let cache = MountInfo::build_cache()?;
        self.0 = cache;
        Ok(())
    }

    fn parse_dev(dev: &str) -> anyhow::Result<u32> {
        let mut dev_split = dev.split(':');
        let Some(major) = dev_split.next() else {
            bail!("Failed to read device major part");
        };
        let Some(minor) = dev_split.next() else {
            bail!("Failed to read device minor part");
        };
        if dev_split.next().is_some() {
            bail!("Invalid device");
        }

        let major = major.parse::<u32>()?;
        let minor = minor.parse::<u32>()?;
        Ok((major << 20) + (minor & 0xFFFFF))
    }

    pub fn get(&self, k: &u32) -> Option<&Vec<MountEntry>> {
        self.0.get(k)
    }

    pub fn insert_empty(&mut self, k: u32) -> &Vec<MountEntry> {
        self.0.entry(k).or_default()
    }

    fn build_cache() -> anyhow::Result<HashMap<u32, Vec<MountEntry>>> {
        let host_mount = host_info::get_host_mount();
        let path = PathBuf::from("/proc/self/mountinfo");
        if !path.exists() {
            bail!("/proc/self/mountinfo does not exist");
        }
        let mounts = read_to_string(path)?;
        let mountinfo_it = mounts.lines().map(|line| {
            let mut parts = line.split(' ');
            let Some(dev) = parts.nth(2) else {
                bail!("Failed to retrieve device number");
            };
            let dev = MountInfo::parse_dev(dev)?;

            let Some(root) = parts.next() else {
                bail!("Failed to retrieve root");
            };

            let Some(mount_point) = parts.next() else {
                bail!("Failed to retrieve mount point");
            };
            let mut mount_point = Path::new(mount_point);
            if host_mount != Path::new("/") {
                if let Ok(mp) = mount_point.strip_prefix(host_mount) {
                    mount_point = mp;
                }
            }

            let entry = MountEntry {
                root: root.into(),
                mount_point: Path::new("/").join(mount_point),
            };
            Ok((dev, entry))
        });

        let mut cache = HashMap::new();
        for i in mountinfo_it {
            let (dev, mountinfo) = i?;
            let entry: &mut Vec<MountEntry> = cache.entry(dev).or_default();
            if mountinfo.root != Path::new("/") && mountinfo.root != mountinfo.mount_point {
                entry.push(mountinfo);
            }
        }

        Ok(cache)
    }
}
