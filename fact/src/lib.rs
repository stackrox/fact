use std::{io::Write, str::FromStr};

use anyhow::Context;
use bpf::Bpf;
use host_info::{get_distro, get_hostname, SystemInfo};
use log::{debug, info, warn, LevelFilter};
use metrics::exporter::Exporter;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{broadcast, watch},
};

mod bpf;
pub mod config;
mod endpoints;
mod event;
mod host_info;
mod metrics;
mod output;
mod pre_flight;

use config::FactConfig;
use pre_flight::pre_flight;

pub fn init_log() -> anyhow::Result<()> {
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
    Ok(())
}

mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

pub fn log_system_information() {
    info!("fact version: {}", version::FACT_VERSION);
    info!("OS: {}", get_distro());
    match SystemInfo::new() {
        Ok(sysinfo) => {
            info!("Kernel version: {}", sysinfo.kernel);
            info!("Architecture: {}", sysinfo.arch);
        }
        Err(e) => warn!("Failed to get system information: {e}"),
    }
    info!("Hostname: {}", get_hostname());
}

pub async fn run(config: FactConfig) -> anyhow::Result<()> {
    // Log system information as early as possible so we have it
    // available in case of a crash
    log_system_information();
    let (running, _) = watch::channel(true);
    let (tx, rx) = broadcast::channel(100);

    if !config.skip_pre_flight() {
        debug!("Performing pre-flight checks");
        pre_flight().context("Pre-flight checks failed")?;
    } else {
        debug!("Skipping pre-flight checks");
    }

    let mut bpf = Bpf::new(&config)?;

    let exporter = Exporter::new(bpf.get_metrics()?);

    let reloader = config::reloader::Reloader::from(config);
    let config_trigger = reloader.get_trigger();

    output::start(
        rx,
        running.subscribe(),
        exporter.metrics.output.clone(),
        reloader.grpc(),
        reloader.config().json(),
    )?;

    endpoints::Server::new(exporter.clone(), reloader.endpoint(), running.subscribe()).start();

    reloader.start(running.subscribe());

    // Gather events from the ring buffer and print them out.
    Bpf::start_worker(
        tx,
        bpf.fd,
        running.subscribe(),
        exporter.metrics.bpf_worker.clone(),
    );

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => config_trigger.notify_one(),
        }
    }

    running.send(false)?;
    info!("Exiting...");

    Ok(())
}
