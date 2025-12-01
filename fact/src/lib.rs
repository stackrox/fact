use std::{borrow::BorrowMut, io::Write, str::FromStr};

use anyhow::Context;
use bpf::Bpf;
use fs_walker::walk_path;
use host_info::{get_distro, get_hostname, SystemInfo};
use log::{debug, info, warn, LevelFilter};
use metrics::exporter::Exporter;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::watch,
};

mod bpf;
pub mod config;
mod endpoints;
mod event;
mod fs_walker;
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

    if !config.skip_pre_flight() {
        debug!("Performing pre-flight checks");
        pre_flight().context("Pre-flight checks failed")?;
    } else {
        debug!("Skipping pre-flight checks");
    }

    let reloader = config::reloader::Reloader::from(config);
    let config_trigger = reloader.get_trigger();

    let mut bpf = Bpf::new(reloader.paths(), reloader.config().ringbuf_size())?;
    let exporter = Exporter::new(bpf.take_metrics()?);

    // TODO: The inode tracking algorithm for host paths only works on
    // files that exist at startup, this needs to be improved.
    let inode_store = bpf.get_inode_store()?;
    for p in reloader.paths().borrow().iter() {
        let mounted_path = host_info::get_host_mount().join(p.strip_prefix("/")?);
        walk_path(inode_store, &mounted_path)?;
    }

    output::start(
        bpf.subscribe(),
        running.subscribe(),
        exporter.metrics.output.clone(),
        reloader.grpc(),
        reloader.config().json(),
    )?;
    endpoints::Server::new(exporter.clone(), reloader.endpoint(), running.subscribe()).start();
    let mut bpf_handle = bpf.start(running.subscribe(), exporter.metrics.bpf_worker.clone());
    reloader.start(running.subscribe());

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = sigterm.recv() => break,
            _ = sighup.recv() => config_trigger.notify_one(),
            res = bpf_handle.borrow_mut() => {
                match res {
                    Ok(res) => if let Err(e) = res {
                        warn!("BPF worker errored out: {e:?}");
                    }
                    Err(e) => warn!("BPF task errored out: {e:?}"),
                }
                break;
            }
        }
    }

    running.send(false)?;
    info!("Exiting...");

    Ok(())
}
