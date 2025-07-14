use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[clap(version, about)]
pub struct FactConfig {
    #[clap(short, long, num_args = 0..16, value_delimiter = ':')]
    pub paths: Vec<PathBuf>,
}
