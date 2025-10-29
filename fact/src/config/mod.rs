use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::bail;
use clap::Parser;
use yaml_rust2::{yaml, Yaml, YamlLoader};

mod builder;
pub mod reloader;
#[cfg(test)]
mod tests;

pub const DEFAULT_RINGBUFFER_SIZE: u32 = 8192;

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct FactConfig {
    paths: Option<Vec<PathBuf>>,
    pub grpc: GrpcConfig,
    pub endpoint: EndpointConfig,
    skip_pre_flight: Option<bool>,
    json: Option<bool>,
    ringbuf_size: Option<u32>,
    hotreload: Option<bool>,
}

impl FactConfig {
    pub fn update(&mut self, from: &FactConfig) {
        if let Some(paths) = from.paths.as_deref() {
            self.paths = Some(paths.to_owned());
        }

        self.grpc.update(&from.grpc);
        self.endpoint.update(&from.endpoint);

        if let Some(skip_pre_flight) = from.skip_pre_flight {
            self.skip_pre_flight = Some(skip_pre_flight);
        }

        if let Some(json) = from.json {
            self.json = Some(json);
        }

        if let Some(ringbuf_size) = from.ringbuf_size {
            self.ringbuf_size = Some(ringbuf_size);
        }

        if let Some(hotreload) = from.hotreload {
            self.hotreload = Some(hotreload);
        }
    }

    pub fn paths(&self) -> &[PathBuf] {
        self.paths.as_ref().map(|v| v.as_ref()).unwrap_or(&[])
    }

    pub fn skip_pre_flight(&self) -> bool {
        self.skip_pre_flight.unwrap_or(false)
    }

    pub fn json(&self) -> bool {
        self.json.unwrap_or(false)
    }

    pub fn ringbuf_size(&self) -> u32 {
        self.ringbuf_size.unwrap_or(DEFAULT_RINGBUFFER_SIZE)
    }

    pub fn hotreload(&self) -> bool {
        self.hotreload.unwrap_or(true)
    }

    #[cfg(test)]
    pub fn set_paths(&mut self, paths: Vec<PathBuf>) {
        self.paths = Some(paths);
    }
}

impl TryFrom<&str> for FactConfig {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        YamlLoader::load_from_str(value)?.try_into()
    }
}

impl TryFrom<Vec<Yaml>> for FactConfig {
    type Error = anyhow::Error;

    fn try_from(value: Vec<Yaml>) -> Result<Self, Self::Error> {
        if value.is_empty() {
            // Ignore empty configuration
            return Ok(Default::default());
        }

        if value.len() > 1 {
            bail!("YAML file contains multiple documents");
        }

        let mut config = FactConfig::default();
        let value = &value[0];
        if value.is_null() {
            return Ok(config);
        }

        let Some(value) = value.as_hash() else {
            bail!("Wrong configuration type");
        };

        for (k, v) in value.iter() {
            let Some(k) = k.as_str() else {
                bail!("key is not string: {k:?}")
            };

            match k {
                "paths" if v.is_array() => {
                    let paths = v
                        .as_vec()
                        .unwrap()
                        .iter()
                        .map(|p| {
                            let Some(p) = p.as_str() else {
                                bail!("Path has invalid type: {p:?}");
                            };
                            Ok(PathBuf::from(p))
                        })
                        .collect::<anyhow::Result<_>>()?;
                    config.paths = Some(paths);
                }
                "paths" if v.is_null() => {
                    config.paths = Some(Vec::new());
                }
                "grpc" if v.is_hash() => {
                    let grpc = v.as_hash().unwrap();
                    config.grpc = GrpcConfig::try_from(grpc)?;
                }
                "endpoint" if v.is_hash() => {
                    let endpoint = v.as_hash().unwrap();
                    config.endpoint = EndpointConfig::try_from(endpoint)?;
                }
                "skip_pre_flight" => {
                    let Some(spf) = v.as_bool() else {
                        bail!("skip_pre_flight field has incorrect type: {v:?}");
                    };
                    config.skip_pre_flight = Some(spf);
                }
                "json" => {
                    let Some(json) = v.as_bool() else {
                        bail!("json field has incorrect type: {v:?}");
                    };
                    config.json = Some(json);
                }
                "ringbuf_size" => {
                    let Some(rb_size) = v.as_i64() else {
                        bail!("ringbuf_size field has incorrect type: {v:?}");
                    };
                    if rb_size < 64 || rb_size > (u32::MAX / 1024) as i64 {
                        bail!("ringbuf_size out of range: {rb_size}");
                    }
                    let rb_size = rb_size as u32;
                    if rb_size.count_ones() != 1 {
                        bail!("ringbuf_size is not a power of 2: {rb_size}");
                    }
                    config.ringbuf_size = Some(rb_size);
                }
                "hotreload" => {
                    let Some(hotreload) = v.as_bool() else {
                        bail!("hotreload field has incorrect type: {v:?}");
                    };
                    config.hotreload = Some(hotreload);
                }
                name => bail!("Invalid field '{name}' with value: {v:?}"),
            }
        }

        Ok(config)
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct EndpointConfig {
    address: Option<SocketAddr>,
    expose_metrics: Option<bool>,
    health_check: Option<bool>,
}

impl EndpointConfig {
    fn update(&mut self, from: &EndpointConfig) {
        if let Some(address) = from.address {
            self.address = Some(address);
        }

        if let Some(expose_metrics) = from.expose_metrics {
            self.expose_metrics = Some(expose_metrics);
        }

        if let Some(health_check) = from.health_check {
            self.health_check = Some(health_check);
        }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 9000)))
    }

    pub fn expose_metrics(&self) -> bool {
        self.expose_metrics.unwrap_or(false)
    }

    pub fn health_check(&self) -> bool {
        self.health_check.unwrap_or(false)
    }
}

impl TryFrom<&yaml::Hash> for EndpointConfig {
    type Error = anyhow::Error;

    fn try_from(value: &yaml::Hash) -> Result<Self, Self::Error> {
        let mut endpoint = EndpointConfig::default();
        for (k, v) in value.iter() {
            let Some(k) = k.as_str() else {
                bail!("key is not string: {k:?}");
            };

            match k {
                "address" => {
                    let Some(addr) = v.as_str() else {
                        bail!("endpoint.address field has incorrect type: {v:?}");
                    };
                    let address = match SocketAddr::from_str(addr) {
                        Ok(a) => a,
                        Err(e) => bail!("Failed to parse endpoint.address: {e}"),
                    };
                    endpoint.address = Some(address);
                }
                "expose_metrics" => {
                    let Some(em) = v.as_bool() else {
                        bail!("endpoint.expose_metrics field has incorrect type: {v:?}");
                    };
                    endpoint.expose_metrics = Some(em);
                }
                "health_check" => {
                    let Some(hc) = v.as_bool() else {
                        bail!("endpoint.health_check field has incorrect type: {v:?}");
                    };
                    endpoint.health_check = Some(hc);
                }
                name => bail!("Invalid field 'endpoint.{name}' with value: {v:?}"),
            }
        }

        Ok(endpoint)
    }
}

#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct GrpcConfig {
    url: Option<String>,
    certs: Option<PathBuf>,
}

impl GrpcConfig {
    fn update(&mut self, from: &GrpcConfig) {
        if let Some(url) = from.url.as_deref() {
            self.url = Some(url.to_owned());
        }

        if let Some(certs) = from.certs.as_deref() {
            self.certs = Some(certs.to_owned());
        }
    }

    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    pub fn certs(&self) -> Option<&Path> {
        self.certs.as_deref()
    }
}

impl TryFrom<&yaml::Hash> for GrpcConfig {
    type Error = anyhow::Error;

    fn try_from(value: &yaml::Hash) -> Result<Self, Self::Error> {
        let mut grpc = GrpcConfig::default();
        for (k, v) in value.iter() {
            let Some(k) = k.as_str() else {
                bail!("key is not string: {k:?}");
            };

            match k {
                "url" => {
                    let Some(url) = v.as_str() else {
                        bail!("url field has incorrect type: {v:?}");
                    };
                    grpc.url = Some(url.to_owned());
                }
                "certs" => {
                    let Some(certs) = v.as_str() else {
                        bail!("certs field has incorrect type: {v:?}");
                    };
                    grpc.certs = Some(PathBuf::from(certs));
                }
                name => bail!("Invalid field 'grpc.{name}' with value: {v:?}"),
            }
        }

        Ok(grpc)
    }
}

#[derive(Debug, Parser)]
#[clap(version = crate::version::FACT_VERSION, about)]
pub struct FactCli {
    /// List of paths to be monitored
    #[clap(short, long, num_args = 0..16, value_delimiter = ':', env = "FACT_PATHS")]
    paths: Option<Vec<PathBuf>>,

    /// URL to forward the packages to
    #[arg(env = "FACT_URL")]
    url: Option<String>,

    /// Directory holding the mTLS certificates and keys
    #[arg(short, long, env = "FACT_CERTS")]
    certs: Option<PathBuf>,

    /// The port to bind for all exposed endpoints
    #[arg(long, short, env = "FACT_ENDPOINT_ADDRESS")]
    address: Option<SocketAddr>,

    /// Whether prometheus metrics should be collected and exposed
    #[arg(
        long,
        overrides_with("no_expose_metrics"),
        env = "FACT_ENDPOINT_EXPOSE_METRICS"
    )]
    expose_metrics: bool,
    #[arg(long, overrides_with = "expose_metrics", hide(true))]
    no_expose_metrics: bool,

    /// Whether a small health_check probe should be run
    #[arg(
        long,
        overrides_with("no_health_check"),
        env = "FACT_ENDPOINT_HEALTH_CHECK"
    )]
    health_check: bool,
    #[arg(long, overrides_with = "health_check", hide(true))]
    no_health_check: bool,

    /// Whether to perform a pre flight check
    #[arg(
        long,
        overrides_with = "no_skip_pre_flight",
        env = "FACT_SKIP_PRE_FLIGHT"
    )]
    skip_pre_flight: bool,
    #[arg(long, overrides_with = "skip_pre_flight", hide(true))]
    no_skip_pre_flight: bool,

    /// Force events to be output as JSON to stdout
    #[arg(long, short, overrides_with = "no_json", env = "FACT_JSON")]
    json: bool,
    #[arg(long, short, overrides_with = "json", hide(true))]
    no_json: bool,

    /// Sets the size of the ringbuffer to be used in kilobytes
    ///
    /// The size must be a power of 2, preferably a multiple of the page
    /// size on the running system (usually 4KB).
    /// The minimum allowed size is 64KB.
    /// There is no maximum size, but it is recommended to keep this
    /// at a reasonable value.
    /// Default value is 8MB.
    #[arg(long, short, env = "FACT_RINGBUF_SIZE")]
    ringbuf_size: Option<u32>,

    /// Whether configuration should be hotreloaded
    #[arg(long, overrides_with = "no_hotreload", env = "FACT_HOTRELOAD")]
    hotreload: bool,
    #[arg(long, overrides_with = "hotreload", hide(true))]
    no_hotreload: bool,
}

impl FactCli {
    fn to_config(&self) -> FactConfig {
        FactConfig {
            paths: self.paths.clone(),
            grpc: GrpcConfig {
                url: self.url.clone(),
                certs: self.certs.clone(),
            },
            endpoint: EndpointConfig {
                address: self.address,
                expose_metrics: resolve_bool_arg(self.expose_metrics, self.no_expose_metrics),
                health_check: resolve_bool_arg(self.health_check, self.no_health_check),
            },
            skip_pre_flight: resolve_bool_arg(self.skip_pre_flight, self.no_skip_pre_flight),
            json: resolve_bool_arg(self.json, self.no_json),
            ringbuf_size: self.ringbuf_size,
            hotreload: resolve_bool_arg(self.hotreload, self.no_hotreload),
        }
    }
}

fn resolve_bool_arg(yes: bool, no: bool) -> Option<bool> {
    match (yes, no) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        (false, false) => None,
        (_, _) => unreachable!("clap should make this impossible"),
    }
}
