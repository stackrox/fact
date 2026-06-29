use std::collections::BTreeMap;

use fact_core::config::FactConfig;
use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, DaemonSetSpec},
        core::v1::{
            Capabilities, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EnvVar,
            HostPathVolumeSource, PodSpec, PodTemplateSpec, SecurityContext, Volume, VolumeMount,
        },
    },
    apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference},
};
use kube::{CustomResource, Resource, ResourceExt, api::ObjectMeta};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use yaml_rust2::YamlEmitter;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, CustomResource)]
#[serde(rename_all = "camelCase")]
#[kube(
    group = "fact.stackrox.io",
    version = "v1alpha1",
    kind = "Fact",
    namespaced
)]
pub(crate) struct FactSpec {
    // Configuration requiring restarts
    pub image: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,

    // Configuration hot-reloaded via configmap
    pub config: FactConfig,
}

fn default_log_level() -> String {
    String::from("info")
}

pub(crate) fn build_configmap(fact: &Fact) -> ConfigMap {
    let config = fact.spec.config.to_yaml();
    let mut output = String::new();
    YamlEmitter::new(&mut output).dump(&config).unwrap();

    let data = BTreeMap::from([("fact.yml".into(), output)]);
    ConfigMap {
        data: Some(data),
        metadata: ObjectMeta {
            name: Some(format!("{}-config", fact.name_any())),
            namespace: fact.namespace(),
            owner_references: fact.controller_owner_ref(&()).map(|r| vec![r]),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[derive(Debug, Default)]
pub(crate) struct DaemonSetBuilder {
    name: String,
    namespace: Option<String>,
    owner_references: Option<Vec<OwnerReference>>,

    image: Option<String>,
    log_level: String,
}

impl DaemonSetBuilder {
    #[cfg(test)]
    fn set_name(self, name: &str) -> Self {
        DaemonSetBuilder {
            name: name.to_string(),
            ..self
        }
    }

    #[cfg(test)]
    fn set_image(self, image: &str) -> Self {
        DaemonSetBuilder {
            image: Some(image.to_string()),
            ..self
        }
    }

    #[cfg(test)]
    fn set_log_level(self, log_level: &str) -> Self {
        DaemonSetBuilder {
            log_level: log_level.to_string(),
            ..self
        }
    }

    pub fn build(self) -> DaemonSet {
        let DaemonSetBuilder {
            name,
            namespace,
            owner_references,
            image,
            log_level,
        } = self;
        let labels = BTreeMap::from([("app".into(), "fact".into())]);

        let metadata = ObjectMeta {
            labels: Some(labels.clone()),
            name: Some(name.clone()),
            namespace,
            owner_references,
            ..Default::default()
        };

        let container = Container {
            name: "fact".into(),
            image,
            image_pull_policy: Some("IfNotPresent".into()),
            ports: Some(vec![ContainerPort {
                container_port: 9000,
                name: Some("monitoring".into()),
                ..Default::default()
            }]),
            env: Some(vec![
                EnvVar {
                    name: "FACT_LOGLEVEL".into(),
                    value: Some(log_level),
                    ..Default::default()
                },
                EnvVar {
                    name: "FACT_HOST_MOUNT".into(),
                    value: Some("/host".into()),
                    ..Default::default()
                },
            ]),
            security_context: Some(SecurityContext {
                capabilities: Some(Capabilities {
                    drop: Some(vec!["NET_RAW".into()]),
                    ..Default::default()
                }),
                privileged: Some(true),
                read_only_root_filesystem: Some(true),
                ..Default::default()
            }),
            volume_mounts: Some(vec![
                VolumeMount {
                    name: "root-ro".into(),
                    mount_path: "/host".into(),
                    read_only: Some(true),
                    mount_propagation: Some("HostToContainer".into()),
                    ..Default::default()
                },
                VolumeMount {
                    mount_path: "/etc/stackrox".into(),
                    name: "fact-config".into(),
                    read_only: Some(true),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        };

        let volumes = vec![
            Volume {
                host_path: Some(HostPathVolumeSource {
                    path: "/".into(),
                    ..Default::default()
                }),
                name: "root-ro".into(),
                ..Default::default()
            },
            Volume {
                name: "fact-config".into(),
                config_map: Some(ConfigMapVolumeSource {
                    name: format!("{name}-config"),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ];

        let spec = DaemonSetSpec {
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            ..Default::default()
        };

        DaemonSet {
            metadata,
            spec: Some(spec),
            ..Default::default()
        }
    }
}

impl From<&Fact> for DaemonSetBuilder {
    fn from(fact: &Fact) -> Self {
        let name = fact.name_any();
        let namespace = fact.namespace();
        let owner_references = fact.controller_owner_ref(&()).map(|r| vec![r]);
        let image = fact.spec.image.clone();
        let log_level = fact.spec.log_level.clone();

        DaemonSetBuilder {
            name,
            namespace,
            owner_references,
            image: Some(image),
            log_level,
        }
    }
}

#[cfg(test)]
mod tests {
    use yaml_rust2::Yaml;

    use super::*;

    fn yaml_to_string(input: &Yaml) -> String {
        let mut output = String::new();
        YamlEmitter::new(&mut output).dump(input).unwrap();
        output
    }

    #[test]
    fn test_build_configmap() {
        fn full_config() -> FactConfig {
            FactConfig::try_from(
                r#"
            paths:
            - /etc
            grpc:
              url: 'https://svc.sensor.stackrox:9090'
              certs: /etc/stackrox/certs
            endpoint:
              address: 0.0.0.0:8080
              expose_metrics: true
              health_check: true
            skip_pre_flight: false
            json: false
            bpf:
                ringbuf_size: 8192
                inodes_max: 64
            hotreload: false
            scan_interval: 60
            rate_limit: 1000
            "#,
            )
            .unwrap()
        }

        let tests = [
            (
                Fact::new(
                    "fact",
                    FactSpec {
                        image: "quay.io/stackrox-io/fact:0.3.0".into(),
                        log_level: "debug".into(),
                        config: FactConfig::default(),
                    },
                ),
                ConfigMap {
                    data: Some(BTreeMap::from([(
                        "fact.yml".to_string(),
                        yaml_to_string(&FactConfig::default().to_yaml()),
                    )])),
                    metadata: ObjectMeta {
                        name: Some("fact-config".into()),
                        namespace: None,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                Fact::new(
                    "not-fact",
                    FactSpec {
                        image: "quay.io/stackrox-io/fact:0.3.0".into(),
                        log_level: "debug".into(),
                        config: FactConfig::default(),
                    },
                ),
                ConfigMap {
                    data: Some(BTreeMap::from([(
                        "fact.yml".to_string(),
                        yaml_to_string(&FactConfig::default().to_yaml()),
                    )])),
                    metadata: ObjectMeta {
                        name: Some("not-fact-config".into()),
                        namespace: None,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
            (
                Fact::new(
                    "fact",
                    FactSpec {
                        image: "quay.io/stackrox-io/fact:0.3.0".into(),
                        log_level: "debug".into(),
                        config: full_config(),
                    },
                ),
                ConfigMap {
                    data: Some(BTreeMap::from([(
                        "fact.yml".to_string(),
                        yaml_to_string(&full_config().to_yaml()),
                    )])),
                    metadata: ObjectMeta {
                        name: Some("fact-config".into()),
                        namespace: None,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            ),
        ];

        for (fact, expected) in tests {
            let cm = build_configmap(&fact);
            assert_eq!(cm, expected);
        }
    }

    #[test]
    fn test_build_daemonset() {
        let tests = [
            (
                Fact::new(
                    "fact",
                    FactSpec {
                        image: "quay.io/stackrox-io/fact:0.3.0".into(),
                        log_level: "info".into(),
                        config: FactConfig::default(),
                    },
                ),
                DaemonSetBuilder::default()
                    .set_image("quay.io/stackrox-io/fact:0.3.0")
                    .set_name("fact")
                    .set_log_level("info")
                    .build(),
            ),
            (
                Fact::new(
                    "other-fact",
                    FactSpec {
                        image: "quay.io/rhacs-eng/fact:0.3.0".into(),
                        log_level: "warn".into(),
                        config: FactConfig::default(),
                    },
                ),
                DaemonSetBuilder::default()
                    .set_image("quay.io/rhacs-eng/fact:0.3.0")
                    .set_name("other-fact")
                    .set_log_level("warn")
                    .build(),
            ),
        ];

        for (fact, expected) in tests {
            let res = DaemonSetBuilder::from(&fact).build();
            assert_eq!(res, expected);
        }
    }
}
