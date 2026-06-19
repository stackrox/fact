use std::collections::BTreeMap;

use k8s_openapi::{
    api::{
        apps::v1::{DaemonSet, DaemonSetSpec},
        core::v1::{
            Capabilities, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EnvVar,
            HostPathVolumeSource, PodSpec, PodTemplateSpec, SecurityContext, Volume, VolumeMount,
        },
    },
    apimachinery::pkg::apis::meta::v1::LabelSelector,
};
use kube::{CustomResource, Resource, ResourceExt, api::ObjectMeta};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, CustomResource)]
#[serde(rename_all = "camelCase")]
#[kube(
    group = "fact.stackrox.io",
    version = "v1alpha1",
    kind = "Fact",
    namespaced
)]
pub(crate) struct FactSpec {
    pub image: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u64,
}

fn default_log_level() -> String {
    String::from("info")
}

fn default_rate_limit() -> u64 {
    0
}

pub(crate) fn build_configmap(fact: &Fact) -> ConfigMap {
    let data = BTreeMap::from([(
        "fact.yml".into(),
        format!("rate_limit: {}", fact.spec.rate_limit),
    )]);
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

pub(crate) fn build_daemonset(fact: &Fact) -> DaemonSet {
    let spec = &fact.spec;
    let name = fact.name_any();
    let namespace = fact.namespace();
    let labels = BTreeMap::from([("app".into(), "fact".into())]);

    let metadata = ObjectMeta {
        labels: Some(labels.clone()),
        name: Some(name),
        namespace,
        owner_references: fact.controller_owner_ref(&()).map(|r| vec![r]),
        ..Default::default()
    };

    let container = Container {
        name: "fact".into(),
        image: Some(spec.image.clone()),
        image_pull_policy: Some("IfNotPresent".into()),
        args: Some(vec![
            "--paths".into(),
            "/etc:/bin:/sbin:/usr/bin:/usr/sbin".into(),
        ]),
        ports: Some(vec![ContainerPort {
            container_port: 9000,
            name: Some("monitoring".into()),
            ..Default::default()
        }]),
        env: Some(vec![
            EnvVar {
                name: "FACT_LOGLEVEL".into(),
                value: Some(spec.log_level.clone()),
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
                name: format!("{}-config", fact.name_any()),
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
