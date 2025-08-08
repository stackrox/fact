use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version, about)]
pub struct FactConfig {
    /// List of paths to be monitored
    #[clap(short, long, num_args = 0..16, value_delimiter = ':')]
    pub paths: Vec<PathBuf>,

    /// URL to forward the packages to
    #[arg(env = "FACT_URL")]
    pub url: Option<String>,

    /// Directory holding the mTLS certificates and keys
    #[arg(short, long, env = "FACT_CERTS")]
    pub certs: Option<PathBuf>,

    /// Whether a small health_check probe should be run
    #[arg(long)]
    pub health_check: bool,
}
