use std::{
    collections::HashMap,
    fs,
    path::{Component, Path, PathBuf},
    sync::{LazyLock, RwLock},
};

use anyhow::{Context, bail};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::host_info;

const RUNTIME_ROOTS: [&str; 2] = [
    "run/containers/storage/overlay-containers",
    "var/lib/containers/storage/overlay-containers",
];

static CACHE: LazyLock<RwLock<HashMap<String, ContainerMetadata>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerMetadata {
    pub namespace: String,
    pub pod_uid: String,
    pub pod_name: String,
    pub container_name: String,
    pub image_name: String,
    pub image_ref: String,
    pub container_type: String,
    pub openshift_scc: String,
    pub created: String,
    pub oc_debug: bool,
    pub privileged: bool,
    pub host_pid: bool,
    pub host_network: bool,
    pub host_root_mount: bool,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
    pub sandbox: Option<SandboxMetadata>,
    #[serde(skip)]
    oci: OciDebugMetadata,
}

/// Curated OCI runtime configuration retained for development diagnostics.
/// It is intentionally excluded from the Sensor protobuf and normal JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct OciDebugMetadata {
    pub container_id: String,
    pub version: String,
    pub root_path: String,
    pub root_read_only: bool,
    pub process_args: Vec<String>,
    pub process_cwd: String,
    pub effective_capabilities: Vec<String>,
    pub bounding_capabilities: Vec<String>,
    pub namespaces: Vec<String>,
    mounts: Vec<OciMount>,
}

/// Relationship between one event path and the OCI mount table. This exposes
/// runtime facts only; callers must not treat it as a filtering decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OciPathDebugInfo {
    pub status: &'static str,
    pub destination: Option<PathBuf>,
    pub source: Option<PathBuf>,
    pub mount_type: Option<String>,
    pub options: Vec<String>,
    pub resolved_source_path: Option<PathBuf>,
}

impl OciPathDebugInfo {
    pub(crate) fn unavailable(status: &'static str) -> Self {
        Self {
            status,
            destination: None,
            source: None,
            mount_type: None,
            options: Vec::new(),
            resolved_source_path: None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxMetadata {
    pub id: String,
    pub oci_version: String,
    pub image_name: String,
    pub image_ref: String,
    pub labels: HashMap<String, String>,
    pub annotations: HashMap<String, String>,
}

impl ContainerMetadata {
    pub(crate) fn oci_debug(&self) -> &OciDebugMetadata {
        &self.oci
    }

    pub(crate) fn match_mount(&self, path: &Path) -> OciPathDebugInfo {
        if !is_normal_absolute_path(path) {
            return OciPathDebugInfo::unavailable("invalid_event_path");
        }

        let matched = self
            .oci
            .mounts
            .iter()
            .filter(|mount| {
                let destination = Path::new(&mount.destination);
                is_normal_absolute_path(destination) && path.starts_with(destination)
            })
            .max_by_key(|mount| Path::new(&mount.destination).components().count());

        let Some(mount) = matched else {
            return OciPathDebugInfo::unavailable("no_mount_match");
        };

        let destination = PathBuf::from(&mount.destination);
        let source = PathBuf::from(&mount.source);
        let suffix = path.strip_prefix(&destination).ok();
        OciPathDebugInfo {
            status: "matched",
            destination: Some(destination),
            source: Some(source.clone()),
            mount_type: Some(mount.mount_type.clone()),
            options: mount.options.clone(),
            resolved_source_path: suffix.map(|suffix| source.join(suffix)),
        }
    }
}

fn is_normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

pub fn resolve(short_id: &str) -> Option<ContainerMetadata> {
    if let Some(metadata) = CACHE.read().ok()?.get(short_id) {
        return Some(metadata.clone());
    }

    match resolve_from_root(host_info::get_host_mount(), short_id) {
        Ok(Some(metadata)) => {
            if let Ok(mut cache) = CACHE.write() {
                cache.insert(short_id.to_owned(), metadata.clone());
            }
            Some(metadata)
        }
        Ok(None) => None,
        Err(error) => {
            debug!("Failed to resolve OCI metadata for container {short_id}: {error:#}");
            None
        }
    }
}

fn resolve_from_root(
    host_root: &Path,
    short_id: &str,
) -> anyhow::Result<Option<ContainerMetadata>> {
    if short_id.is_empty() || !short_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }

    for runtime_root in RUNTIME_ROOTS {
        let root = host_root.join(runtime_root);
        let Some(config) = find_config(&root, short_id)? else {
            continue;
        };
        let spec = read_spec(&config)?;
        let sandbox_id = annotation(&spec.annotations, "io.kubernetes.cri-o.SandboxID");
        let mut metadata = ContainerMetadata::from(spec);
        metadata.oci.container_id = config
            .parent()
            .and_then(Path::parent)
            .and_then(Path::file_name)
            .and_then(|id| id.to_str())
            .unwrap_or_default()
            .to_owned();
        metadata.sandbox = match resolve_sandbox(host_root, &sandbox_id, &metadata) {
            Ok(sandbox) => sandbox,
            Err(error) => {
                debug!(
                    "Failed to resolve OCI sandbox metadata for container {short_id}: {error:#}"
                );
                None
            }
        };
        return Ok(Some(metadata));
    }

    Ok(None)
}

fn read_spec(config: &Path) -> anyhow::Result<OciSpec> {
    let contents =
        fs::read_to_string(config).with_context(|| format!("reading {}", config.display()))?;
    serde_json::from_str(&contents).with_context(|| format!("parsing {}", config.display()))
}

fn resolve_sandbox(
    host_root: &Path,
    sandbox_id: &str,
    container: &ContainerMetadata,
) -> anyhow::Result<Option<SandboxMetadata>> {
    if sandbox_id.len() != 64 || !sandbox_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }

    for runtime_root in RUNTIME_ROOTS {
        let config = host_root
            .join(runtime_root)
            .join(sandbox_id)
            .join("userdata/config.json");
        if !config.is_file() {
            continue;
        }

        let spec = read_spec(&config)?;
        if annotation(&spec.annotations, "io.kubernetes.cri-o.ContainerType") != "sandbox" {
            bail!("{} is not a sandbox OCI config", config.display());
        }
        if annotation(&spec.annotations, "io.kubernetes.pod.uid") != container.pod_uid {
            bail!("sandbox pod UID does not match its container");
        }

        return Ok(Some(SandboxMetadata {
            id: sandbox_id.to_owned(),
            oci_version: spec.oci_version,
            image_name: annotation(&spec.annotations, "io.kubernetes.cri-o.ImageName"),
            image_ref: annotation(&spec.annotations, "io.kubernetes.cri-o.ImageRef"),
            labels: parse_map(spec.annotations.get("io.kubernetes.cri-o.Labels")),
            annotations: parse_map(spec.annotations.get("io.kubernetes.cri-o.Annotations")),
        }));
    }

    Ok(None)
}

fn find_config(root: &Path, short_id: &str) -> anyhow::Result<Option<PathBuf>> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", root.display())),
    };

    let mut matches = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading an entry in {}", root.display()))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name.len() == 64
            && name.starts_with(short_id)
            && name.chars().all(|c| c.is_ascii_hexdigit())
        {
            let config = entry.path().join("userdata/config.json");
            if config.is_file() {
                matches.push(config);
            }
        }
        if matches.len() > 1 {
            bail!(
                "container ID prefix {short_id} is ambiguous under {}",
                root.display()
            );
        }
    }

    Ok(matches.pop())
}

#[derive(Debug, Default, Deserialize)]
struct OciSpec {
    #[serde(default, rename = "ociVersion")]
    oci_version: String,
    #[serde(default)]
    annotations: HashMap<String, String>,
    #[serde(default)]
    mounts: Vec<OciMount>,
    #[serde(default)]
    root: OciRoot,
    #[serde(default)]
    process: OciProcess,
    #[serde(default)]
    linux: OciLinux,
}

#[derive(Debug, Default, Deserialize)]
struct OciRoot {
    #[serde(default)]
    path: String,
    #[serde(default, rename = "readonly")]
    read_only: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
struct OciMount {
    #[serde(default)]
    destination: String,
    #[serde(default, rename = "type")]
    mount_type: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    options: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OciProcess {
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cwd: String,
    #[serde(default)]
    capabilities: OciCapabilities,
}

#[derive(Debug, Default, Deserialize)]
struct OciCapabilities {
    #[serde(default)]
    effective: Vec<String>,
    #[serde(default)]
    bounding: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OciLinux {
    #[serde(default)]
    namespaces: Vec<OciNamespace>,
    #[serde(default, rename = "maskedPaths")]
    masked_paths: Vec<String>,
    #[serde(default, rename = "readonlyPaths")]
    readonly_paths: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OciNamespace {
    #[serde(default, rename = "type")]
    kind: String,
}

impl From<OciSpec> for ContainerMetadata {
    fn from(spec: OciSpec) -> Self {
        let labels = parse_map(spec.annotations.get("io.kubernetes.cri-o.Labels"));
        let annotations = parse_map(spec.annotations.get("io.kubernetes.cri-o.Annotations"));
        let oc_debug = spec
            .annotations
            .keys()
            .chain(labels.keys())
            .chain(annotations.keys())
            .any(|key| key.starts_with("debug.openshift.io/"));
        let has_namespace = |kind: &str| spec.linux.namespaces.iter().any(|ns| ns.kind == kind);
        let privileged = spec
            .process
            .capabilities
            .effective
            .iter()
            .any(|capability| capability == "CAP_SYS_ADMIN")
            && spec.linux.masked_paths.is_empty()
            && spec.linux.readonly_paths.is_empty();
        let host_root_mount = spec.mounts.iter().any(|mount| {
            mount.source == "/"
                && mount.destination != "/"
                && mount.options.iter().any(|option| option == "rw")
        });
        let oci = OciDebugMetadata {
            version: spec.oci_version,
            root_path: spec.root.path,
            root_read_only: spec.root.read_only,
            process_args: spec.process.args,
            process_cwd: spec.process.cwd,
            effective_capabilities: spec.process.capabilities.effective,
            bounding_capabilities: spec.process.capabilities.bounding,
            namespaces: spec
                .linux
                .namespaces
                .iter()
                .map(|namespace| namespace.kind.clone())
                .collect(),
            mounts: spec.mounts,
            ..Default::default()
        };

        Self {
            namespace: annotation(&spec.annotations, "io.kubernetes.pod.namespace"),
            pod_uid: annotation(&spec.annotations, "io.kubernetes.pod.uid"),
            pod_name: annotation(&spec.annotations, "io.kubernetes.pod.name"),
            container_name: annotation(&spec.annotations, "io.kubernetes.container.name"),
            image_name: annotation(&spec.annotations, "io.kubernetes.cri-o.ImageName"),
            image_ref: annotation(&spec.annotations, "io.kubernetes.cri-o.ImageRef"),
            container_type: annotation(&spec.annotations, "io.kubernetes.cri-o.ContainerType"),
            openshift_scc: annotation(&spec.annotations, "openshift.io/scc"),
            created: annotation(&spec.annotations, "io.kubernetes.cri-o.Created"),
            oc_debug,
            privileged,
            host_pid: !has_namespace("pid"),
            host_network: !has_namespace("network"),
            host_root_mount,
            labels,
            annotations,
            sandbox: None,
            oci,
        }
    }
}

fn annotation(annotations: &HashMap<String, String>, key: &str) -> String {
    annotations.get(key).cloned().unwrap_or_default()
}

fn parse_map(value: Option<&String>) -> HashMap<String, String> {
    value
        .and_then(|value| serde_json::from_str(value).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_ID: &str = "e72fce5766ead840d848faae8843678ff84e779443c6776e941421a6617acdbd";
    const SANDBOX_ID: &str = "dbb94bac0914953156552635dbc8e2125913c8c38bbab78930020f6cb5b57427";

    fn write_config(root: &Path, id: &str) {
        let directory = root.join(RUNTIME_ROOTS[0]).join(id).join("userdata");
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("config.json"),
            r#"{
              "ociVersion": "1.2.0",
              "root": {"path":"/var/lib/containers/storage/overlay/rootfs","readonly":true},
              "annotations": {
                "io.kubernetes.pod.namespace": "test-ns",
                "io.kubernetes.pod.uid": "pod-uid",
                "io.kubernetes.pod.name": "pod-name",
                "io.kubernetes.container.name": "container-name",
                "io.kubernetes.cri-o.ImageName": "example/image:tag",
                "io.kubernetes.cri-o.ImageRef": "sha256:image",
                "io.kubernetes.cri-o.ContainerType": "container",
                "io.kubernetes.cri-o.ContainerID": "e72fce5766ead840d848faae8843678ff84e779443c6776e941421a6617acdbd",
                "io.kubernetes.cri-o.Name": "k8s_container-name_pod-name_test-ns_pod-uid_0",
                "io.kubernetes.cri-o.LogPath": "/var/log/pods/test-ns_pod-name_pod-uid/container-name/0.log",
                "io.kubernetes.cri-o.SandboxID": "dbb94bac0914953156552635dbc8e2125913c8c38bbab78930020f6cb5b57427",
                "io.kubernetes.cri-o.Created": "2026-08-31T20:18:23.652874525Z",
                "io.kubernetes.cri-o.Labels": "{\"app\":\"test\",\"debug.openshift.io/managed-by\":\"oc-debug\"}",
                "io.kubernetes.cri-o.Annotations": "{\"example\":\"value\"}",
                "openshift.io/scc": "privileged",
                "io.container.manager": "cri-o"
              },
              "mounts": [{"destination":"/host","source":"/","options":["rbind","rw"]}],
              "process": {
                "args":["/usr/bin/example","--serve"],
                "cwd":"/work",
                "capabilities":{
                  "effective":["CAP_SYS_ADMIN"],
                  "bounding":["CAP_SYS_ADMIN","CAP_CHOWN"]
                }
              },
              "linux": {"namespaces":[{"type":"ipc"},{"type":"mount"}]}
            }"#,
        )
        .unwrap();

        let sandbox_directory = root
            .join(RUNTIME_ROOTS[0])
            .join(SANDBOX_ID)
            .join("userdata");
        fs::create_dir_all(&sandbox_directory).unwrap();
        fs::write(
            sandbox_directory.join("config.json"),
            r#"{
              "ociVersion": "1.3.0",
              "annotations": {
                "io.kubernetes.cri-o.ContainerType": "sandbox",
                "io.kubernetes.cri-o.ImageName": "example/pause@sha256:digest",
                "io.kubernetes.cri-o.ImageRef": "sandbox-image-id",
                "io.kubernetes.pod.uid": "pod-uid",
                "io.kubernetes.cri-o.Labels": "{\"app\":\"sandbox-label\",\"pod-template-hash\":\"abc123\"}",
                "io.kubernetes.cri-o.Annotations": "{\"pod.example/annotation\":\"value\"}"
              }
            }"#,
        )
        .unwrap();
    }

    #[test]
    fn resolves_unique_prefix_and_extracts_metadata() {
        let root = tempfile::tempdir().unwrap();
        write_config(root.path(), FULL_ID);

        let metadata = resolve_from_root(root.path(), &FULL_ID[..12])
            .unwrap()
            .unwrap();

        assert_eq!(metadata.namespace, "test-ns");
        assert_eq!(metadata.pod_uid, "pod-uid");
        assert_eq!(metadata.image_name, "example/image:tag");
        assert_eq!(metadata.labels.get("app").unwrap(), "test");
        assert!(metadata.oc_debug);
        assert!(metadata.privileged);
        assert!(metadata.host_pid);
        assert!(metadata.host_network);
        assert!(metadata.host_root_mount);
        assert_eq!(metadata.oci.container_id, FULL_ID);
        assert_eq!(metadata.oci.version, "1.2.0");
        assert!(metadata.oci.root_read_only);
        assert_eq!(metadata.oci.process_args[0], "/usr/bin/example");
        assert_eq!(metadata.oci.process_cwd, "/work");
        assert_eq!(metadata.oci.namespaces, ["ipc", "mount"]);
        let sandbox = metadata.sandbox.unwrap();
        assert_eq!(sandbox.id, SANDBOX_ID);
        assert_eq!(sandbox.oci_version, "1.3.0");
        assert_eq!(sandbox.image_name, "example/pause@sha256:digest");
        assert_eq!(sandbox.labels.get("app").unwrap(), "sandbox-label");
        assert_eq!(sandbox.labels.get("pod-template-hash").unwrap(), "abc123");
    }

    #[test]
    fn ambiguous_prefix_fails_open() {
        let root = tempfile::tempdir().unwrap();
        write_config(root.path(), FULL_ID);
        write_config(
            root.path(),
            "e72fce5766eaffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );

        assert!(resolve_from_root(root.path(), &FULL_ID[..12]).is_err());
    }

    #[test]
    fn invalid_or_missing_prefix_is_unresolved() {
        let root = tempfile::tempdir().unwrap();
        assert!(resolve_from_root(root.path(), "not-hex").unwrap().is_none());
        assert!(
            resolve_from_root(root.path(), "0123456789ab")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn matches_longest_mount_destination() {
        let metadata = ContainerMetadata {
            oci: OciDebugMetadata {
                mounts: vec![
                    OciMount {
                        destination: "/etc".into(),
                        mount_type: "bind".into(),
                        source: "/host/etc".into(),
                        options: vec!["ro".into(), "bind".into()],
                    },
                    OciMount {
                        destination: "/etc/prometheus/config_out".into(),
                        mount_type: "bind".into(),
                        source: "/var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~empty-dir/config-out".into(),
                        options: vec!["rw".into(), "rbind".into()],
                    },
                ],
                ..Default::default()
            },
            ..Default::default()
        };

        let info =
            metadata.match_mount(Path::new("/etc/prometheus/config_out/prometheus.env.yaml"));

        assert_eq!(info.status, "matched");
        assert_eq!(
            info.destination.as_deref(),
            Some(Path::new("/etc/prometheus/config_out"))
        );
        assert_eq!(
            info.resolved_source_path.as_deref(),
            Some(Path::new(
                "/var/lib/kubelet/pods/pod-uid/volumes/kubernetes.io~empty-dir/config-out/prometheus.env.yaml"
            ))
        );
        assert_eq!(info.options, ["rw", "rbind"]);
    }

    #[test]
    fn mount_match_is_component_aware() {
        let metadata = ContainerMetadata {
            oci: OciDebugMetadata {
                mounts: vec![OciMount {
                    destination: "/data".into(),
                    mount_type: "bind".into(),
                    source: "/source".into(),
                    options: vec!["rw".into()],
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        assert_eq!(
            metadata.match_mount(Path::new("/database/file")).status,
            "no_mount_match"
        );
        let invalid = metadata.match_mount(Path::new("/data/../host/file"));
        assert_eq!(invalid.status, "invalid_event_path");
    }
}
