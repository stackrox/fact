use std::{
    ffi::{c_char, CStr},
    os::unix::fs::DirEntryExt,
    path::Path,
};

use aya::maps::{MapData, MapError};
use fact_ebpf::{cgroup_entry_t, event_t};
use log::warn;

use crate::{host_info, metrics::EventCounter};

use super::Event;

pub struct Parser {
    cgroup_map: aya::maps::HashMap<MapData, u64, cgroup_entry_t>,
    metrics: Option<EventCounter>,
}

impl Parser {
    pub fn new(mut cgroup_map: aya::maps::HashMap<MapData, u64, cgroup_entry_t>) -> Self {
        for fs in host_info::get_cgroup_paths() {
            Parser::fill_in_map(&mut cgroup_map, &fs);
        }
        Parser {
            cgroup_map,
            metrics: None,
        }
    }

    pub fn set_metrics(&mut self, metrics: EventCounter) {
        self.metrics = Some(metrics);
    }

    fn metrics_added(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.added();
        }
    }

    fn metrics_ignored(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.ignored();
        }
    }

    fn metrics_dropped(&self) {
        if let Some(metrics) = &self.metrics {
            metrics.dropped();
        }
    }

    pub fn parse(&mut self, event: &event_t) -> anyhow::Result<Event> {
        let container_id = self.get_container_id(&event.process.cgroup_id);
        Event::new(event, container_id)
    }

    fn fill_in_map(cgroup_map: &mut aya::maps::HashMap<MapData, u64, cgroup_entry_t>, path: &Path) {
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
            let Some(p_str) = p.to_str() else {
                warn!("p.to_str() failed");
                continue;
            };
            let container_id = Parser::extract_container_id(p_str);
            let id = entry.ino();
            let path = unsafe {
                let mut path: [c_char; 4096] = std::mem::zeroed();
                if let Some(cid) = &container_id {
                    std::ptr::copy(cid.as_ptr(), path.as_mut_ptr().cast(), cid.len());
                }

                path
            };
            let cid_entry = fact_ebpf::cgroup_entry_t {
                parsed: true as c_char,
                path,
            };
            if let Err(e) = cgroup_map.insert(id, cid_entry, 1) {
                warn!("Failed to insert entry for {id}: {e}");
            }

            Parser::fill_in_map(cgroup_map, &p);
        }
    }

    fn get_container_id(&mut self, k: &u64) -> Option<String> {
        self.metrics_added();
        let mut cgroup = match self.cgroup_map.get(k, 0) {
            Ok(cgroup) => cgroup,
            Err(MapError::KeyNotFound) => {
                self.metrics_ignored();
                return None;
            }
            Err(e) => {
                warn!("Failed to retrieve entry for {k}: {e}");
                self.metrics_dropped();
                return None;
            }
        };

        if cgroup.parsed != 0 {
            let cid = unsafe { CStr::from_ptr(cgroup.path.as_ptr()) };
            let cid = match cid.to_str() {
                Ok(cid) => cid,
                Err(e) => {
                    warn!("Failed to read cid for {k}: {e}");
                    self.metrics_dropped();
                    return None;
                }
            };
            Some(cid.to_string())
        } else {
            cgroup.parsed = true as c_char;
            let path = match unsafe { CStr::from_ptr(cgroup.path.as_ptr()) }.to_str() {
                Ok(path) => path,
                Err(e) => {
                    warn!("Failed to read path for {k}: {e}");
                    self.metrics_dropped();
                    return None;
                }
            };
            let cid = Parser::extract_container_id(path);

            if let Some(cid) = &cid {
                unsafe {
                    std::ptr::copy(cid.as_ptr(), cgroup.path.as_mut_ptr().cast(), cid.len());
                }
                cgroup.path[12] = '\0' as c_char;
            } else {
                cgroup.path[0] = '\0' as c_char;
            }
            if let Err(e) = self.cgroup_map.insert(k, cgroup, 2) {
                warn!("Failed to update entry for {k}: {e}");
            }
            cid
        }
    }

    pub(super) fn extract_container_id(cgroup: &str) -> Option<String> {
        let cgroup = if let Some(i) = cgroup.rfind(".scope") {
            cgroup.split_at(i).0
        } else {
            cgroup
        };

        if cgroup.is_empty() || cgroup.len() < 65 {
            return None;
        }

        let cgroup = cgroup.split_at(cgroup.len() - 65).1;
        let (c, cgroup) = cgroup.split_at(1);
        if c != "/" && c != "-" {
            return None;
        }

        if cgroup.chars().all(|c| c.is_ascii_hexdigit()) {
            Some(cgroup.split_at(12).0.to_owned())
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
            ("", None),
            ("init.scope", None),
            (
                "/docker/951e643e3c241b225b6284ef2b79a37c13fc64cbf65b5d46bda95fcb98fe63a4",
                Some("951e643e3c24".to_string()),
            ),
            (
                "/kubepods/kubepods/besteffort/pod690705f9-df6e-11e9-8dc5-025000000001/c3bfd81b7da0be97190a74a7d459f4dfa18f57c88765cde2613af112020a1c4b",
                Some("c3bfd81b7da0".to_string()),
            ),
            (
                "/kubepods/burstable/pod7cd3dba6-e475-11e9-8f99-42010a8a00d2/2bc55a8cae1704a733ba5d785d146bbed9610483380507cbf00c96b32bb637e1",
                Some("2bc55a8cae17".to_string()),
            ),
            (
              "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podce705797_e47e_11e9_bd71_42010a000002.slice/docker-6525e65814a99d431b6978e8f8c895013176c6c58173b56639d4b020c14e6022.scope",
              Some("6525e65814a9".to_string()),
            ),
            (
                "/machine.slice/libpod-b6e375cfe46efa5cd90d095603dec2de888c28b203285819233040b5cf1212ac.scope/container",
                Some("b6e375cfe46e".to_string()),
            ),
            (
              "/machine.slice/libpod-cbdfa0f1f08763b1963c30d98e11e1f052cb67f1e9b7c0ab8a6ca6c70cbcad69.scope/container/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubelet-kubepods-besteffort-pod6eab3b7b_f0a6_4bb8_bff2_d5bc9017c04b.slice/cri-containerd-5ebf11e02dbde102cda4b76bc0e3849a65f9edac7a12bdabfd34db01b9556101.scope",
              Some("5ebf11e02dbd".to_string()),
            ),
        ];

        for (input, expected) in tests {
            let id = Parser::extract_container_id(input);
            assert_eq!(id, expected);
        }
    }
}
