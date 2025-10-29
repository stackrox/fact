use std::{fs::read_to_string, path::PathBuf, sync::LazyLock};

use anyhow::Context;
use clap::Parser;

use crate::config::FactCli;

use super::FactConfig;

pub(super) struct FactConfigBuilder {
    files: Vec<PathBuf>,
}

impl FactConfigBuilder {
    pub(super) fn new() -> Self {
        let files = Vec::new();
        FactConfigBuilder { files }
    }

    pub(super) fn add_files(
        mut self,
        files: &[impl Into<PathBuf> + AsRef<std::ffi::OsStr>],
    ) -> Self {
        for file in files {
            self.files.push(file.into());
        }
        self
    }

    pub(super) fn files(&self) -> &[PathBuf] {
        self.files.as_slice()
    }

    pub(super) fn build(&self) -> anyhow::Result<FactConfig> {
        let mut config = self
            .files
            .iter()
            .filter(|p| p.exists())
            .map(|p| {
                let content =
                    read_to_string(p).with_context(|| format!("Failed to read {}", p.display()))?;
                FactConfig::try_from(content.as_str())
                    .with_context(|| format!("parsing error while processing {}", p.display()))
            })
            .try_fold(
                FactConfig::default(),
                |mut config: FactConfig, other: anyhow::Result<FactConfig>| {
                    config.update(&other?);
                    Ok::<FactConfig, anyhow::Error>(config)
                },
            )?;

        // Once file configuration is handled, apply CLI arguments
        static CLI_ARGS: LazyLock<FactConfig> = LazyLock::new(|| FactCli::parse().to_config());
        config.update(&CLI_ARGS);

        Ok(config)
    }
}
