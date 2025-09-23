use std::{
    collections::HashMap,
    os::unix::fs::DirEntryExt,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime},
};

use log::warn;
use tokio::{
    sync::{watch::Receiver, Mutex},
    task::JoinHandle,
    time,
};

use crate::host_info::get_cgroup_paths;

#[derive(Debug)]
struct ContainerIdEntry {
    container_id: Option<String>,
    pub last_seen: SystemTime,
}

type ContainerIdMap = HashMap<u64, ContainerIdEntry>;

#[derive(Debug, Clone, Default)]
pub struct ContainerIdCache(Arc<Mutex<ContainerIdMap>>);

impl ContainerIdCache {
    pub fn new() -> Self {
        let mut map = HashMap::new();
        ContainerIdCache::update_unlocked(&mut map);
        ContainerIdCache(Arc::new(Mutex::new(map)))
    }

    fn update_unlocked(map: &mut ContainerIdMap) {
        for root in get_cgroup_paths() {
            ContainerIdCache::walk_cgroupfs(&root, map, None);
        }
    }

    async fn update(&mut self) {
        let mut map = self.0.lock().await;
        ContainerIdCache::update_unlocked(&mut map);
    }

    async fn prune(&mut self) {
        let now = SystemTime::now();
        self.0.lock().await.retain(|_, value| {
            now.duration_since(value.last_seen).unwrap() < Duration::from_secs(30)
        })
    }

    pub async fn get_container_id(&self, cgroup_id: u64) -> Option<String> {
        let mut map = self.0.lock().await;
        match map.get(&cgroup_id) {
            Some(entry) => entry.container_id.clone(),
            None => {
                // Update the container ID cache and try again
                ContainerIdCache::update_unlocked(&mut map);
                map.get(&cgroup_id).map(|s| s.container_id.clone())?
            }
        }
    }

    pub fn start_worker(mut self, mut running: Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut update_interval = time::interval(time::Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = update_interval.tick() => {
                        self.update().await;
                        self.prune().await;
                    },
                    _ = running.changed() => {
                        if !*running.borrow() {
                            return;
                        }
                    }
                }
            }
        })
    }

    fn walk_cgroupfs(path: &PathBuf, map: &mut ContainerIdMap, parent_id: Option<&str>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    warn!("Failed to read {}: {e}", path.display());
                    continue;
                }
            };

            let p = entry.path();
            if !p.is_dir() {
                continue;
            }

            let container_id = match map.get_mut(&entry.ino()) {
                Some(e) => {
                    e.last_seen = SystemTime::now();
                    e.container_id.clone()
                }
                None => {
                    let last_component = p
                        .file_name()
                        .map(|f| f.to_str().unwrap_or(""))
                        .unwrap_or("");
                    let container_id = match ContainerIdCache::extract_container_id(last_component)
                    {
                        Some(cid) => Some(cid),
                        None => parent_id.map(|f| f.to_owned()),
                    };
                    let last_seen = SystemTime::now();
                    map.insert(
                        entry.ino(),
                        ContainerIdEntry {
                            container_id: container_id.clone(),
                            last_seen,
                        },
                    );
                    container_id
                }
            };
            ContainerIdCache::walk_cgroupfs(&p, map, container_id.as_deref());
        }
    }

    pub fn extract_container_id(cgroup: &str) -> Option<String> {
        if cgroup.is_empty() {
            return None;
        }

        let cgroup = cgroup.strip_suffix(".scope").unwrap_or(cgroup);
        if cgroup.len() < 64 {
            return None;
        }

        let (prefix, id) = cgroup.split_at(cgroup.len() - 64);

        if !prefix.is_empty() && !prefix.ends_with('-') {
            return None;
        }

        if id.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(id.split_at(12).0.to_owned())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_container_id() {
        let tests = [
            ("e73c55f3e7f5b6a9cfc32a89bf13e44d348bcc4fa7b079f804d61fb1532ddbe5", Some("e73c55f3e7f5")),
            ("cri-containerd-219d7afb8e7450929eaeb06f2d27cbf7183bfa5b55b7275696f3df4154a979af.scope", Some("219d7afb8e74")),
            ("kubelet-kubepods-burstable-pod469726a5_079d_4d15_a259_1f654b534b44.slice", None),
            ("libpod-conmon-a2d2a36121868d946af912b931fc5f6b42bf84c700cef67784422b1e2c8585ee.scope", Some("a2d2a3612186")),
            ("init.scope", None),
            ("app-flatpak-com.github.IsmaelMartinez.teams_for_linux-384393947.scope", None),
        ];

        for (cgroup, expected) in tests {
            let cid = ContainerIdCache::extract_container_id(cgroup);
            assert_eq!(cid.as_deref(), expected);
        }
    }
}
