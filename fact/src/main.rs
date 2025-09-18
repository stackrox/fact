use std::io::Write;
use std::str::FromStr;

use fact::{
    config::FactConfig,
    host_info::{get_architecture, get_distro, get_kernel_version},
};
use log::{info, LevelFilter};

mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let log_level = std::env::var("FACT_LOGLEVEL").unwrap_or("info".to_owned());
    let log_level = LevelFilter::from_str(&log_level)?;
    env_logger::Builder::new()
        .filter_level(log_level)
        .format(move |buf, record| {
            write!(buf, "[{:<5} {}] ", record.level(), buf.timestamp_seconds())?;
            if matches!(log_level, LevelFilter::Debug | LevelFilter::Trace) {
                write!(
                    buf,
                    "({}:{}) ",
                    record.file().unwrap_or_default(),
                    record.line().unwrap_or_default()
                )?;
            }
            writeln!(buf, "{}", record.args())
        })
        .init();

    // Log system information as early as possible so we have it
    // available in case of a crash
    info!("fact version: {}", version::FACT_VERSION);
    info!("OS: {}", get_distro());
    info!("Kernel version: {}", get_kernel_version());
    info!("Architecture: {}", get_architecture());

    let config = FactConfig::new(&[
        "/etc/stackrox/fact.yml",
        "/etc/stackrox/fact.yaml",
        "fact.yml",
        "fact.yaml",
    ])?;

    fact::run(config).await
}
