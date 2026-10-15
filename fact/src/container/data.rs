use std::{collections::HashMap, path::PathBuf};

use anyhow::bail;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
enum ContainerMountType {
    Artifact,
    Bind,
    Devpts,
    Glob,
    Image,
    Ramfs,
    Tmpfs,
    Volume,
    #[default]
    Unknown,
}

impl TryFrom<&JsonValue> for ContainerMountType {
    type Error = anyhow::Error;

    fn try_from(value: &JsonValue) -> Result<Self, Self::Error> {
        let Some(value) = value.as_str() else {
            bail!("Mount type is not string: {value:#?}");
        };
        use ContainerMountType::*;
        let value = match value {
            "artifact" => Artifact,
            "bind" => Bind,
            "devpts" => Devpts,
            "glob" => Glob,
            "image" => Image,
            "ramfs" => Ramfs,
            "tmpfs" => Tmpfs,
            "volume" => Volume,
            _ => Unknown,
        };

        Ok(value)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ContainerMount {
    r#type: ContainerMountType,
    source: PathBuf,
    destination: PathBuf,
    mode: String,
    rw: bool,
    propagation: String,
}

impl TryFrom<&JsonValue> for ContainerMount {
    type Error = anyhow::Error;

    fn try_from(value: &JsonValue) -> Result<Self, Self::Error> {
        if !value.is_object() {
            bail!("Mount is not object: {value:#?}");
        }

        let r#type = value
            .get("Type")
            .ok_or_else(|| anyhow::anyhow!("Failed to get mount type"))?
            .try_into()?;
        let source = ContainerData::get_str_value(value, "Source")?.into();
        let destination = ContainerData::get_str_value(value, "Destination")?.into();
        let mode = ContainerData::get_str_value(value, "Mode")?;
        let Some(rw) = value.get("RW").and_then(|rw| rw.as_bool()) else {
            bail!("Failed to retrieve Mount.RW value");
        };
        let propagation = ContainerData::get_str_value(value, "Propagation")?;

        Ok(ContainerMount {
            r#type,
            source,
            destination,
            mode,
            rw,
            propagation,
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContainerData {
    pub(super) id: String,
    name: String,
    image: String,
    args: Vec<String>,
    mounts: Vec<ContainerMount>,
    labels: HashMap<String, String>,
    ports: Vec<String>,
}

impl ContainerData {
    fn get_str_value(map: &JsonValue, value: &str) -> anyhow::Result<String> {
        let Some(v) = map.get(value) else {
            bail!("Missing '{value}' field");
        };
        let Some(v) = v.as_str().map(String::from) else {
            bail!("'{value}' field has invalid type: {v:?}");
        };

        Ok(v)
    }

    fn map_array_value<T>(
        map: &JsonValue,
        value: &str,
        f: impl Fn(&JsonValue) -> anyhow::Result<T>,
    ) -> anyhow::Result<Vec<T>> {
        let Some(v) = map.get(value) else {
            bail!("'{value}' not found");
        };
        let Some(arr) = v.as_array() else {
            bail!("'{value}' not array");
        };

        arr.iter().map(f).collect::<Result<Vec<_>, _>>()
    }

    fn get_labels(config: &JsonValue) -> anyhow::Result<HashMap<String, String>> {
        let Some(labels) = config.get("Labels") else {
            bail!("'Config.Labels' not found");
        };
        let Some(labels) = labels.as_object() else {
            bail!("'Config.Labels' is not object");
        };
        labels
            .iter()
            .map(|(k, v)| {
                let v = v
                    .as_str()
                    .map(String::from)
                    .ok_or_else(|| anyhow::anyhow!("Labels has non-string value"))?;
                Ok((k.clone(), v))
            })
            .collect::<Result<HashMap<_, _>, anyhow::Error>>()
    }
}

impl TryFrom<&JsonValue> for ContainerData {
    type Error = anyhow::Error;

    fn try_from(container: &JsonValue) -> Result<Self, Self::Error> {
        if !container.is_object() {
            bail!("Container JSON is not object: {container:#?}");
        }

        let id = ContainerData::get_str_value(container, "Id")?;
        let name = ContainerData::get_str_value(container, "Name")?;
        let args = ContainerData::map_array_value(container, "Args", |arg| {
            arg.as_str()
                .map(String::from)
                .ok_or_else(|| anyhow::anyhow!("'Args' array has non-string element"))
        })?;
        let mounts = ContainerData::map_array_value(container, "Mounts", |mount| {
            ContainerMount::try_from(mount)
        })?;
        let Some(config) = container.get("Config") else {
            bail!("'Config' field not found");
        };
        let image = ContainerData::get_str_value(config, "Image")?;
        let labels = ContainerData::get_labels(config)?;
        let ports = if let Some(ports) = config.get("ExposedPorts") {
            let Some(ports) = ports.as_object() else {
                bail!("'Config.ExposedPorts' is not object: {ports:#?}");
            };
            ports.iter().map(|(k, _)| k.clone()).collect()
        } else {
            Vec::new()
        };

        Ok(ContainerData {
            id,
            name,
            image,
            args,
            mounts,
            labels,
            ports,
        })
    }
}

#[cfg(feature = "otel")]
impl From<ContainerData> for opentelemetry::logs::AnyValue {
    fn from(value: ContainerData) -> Self {
        use opentelemetry::logs::AnyValue;

        let map = HashMap::from([
            ("id".into(), value.id.into()),
            ("name".into(), value.name.into()),
            ("image".into(), value.image.into()),
        ]);

        AnyValue::Map(Box::new(map))
    }
}
