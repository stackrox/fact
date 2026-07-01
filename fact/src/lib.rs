use std::{borrow::BorrowMut, io::Write, str::FromStr};

use anyhow::{Context, bail};
use bpf::Bpf;
use host_info::{SystemInfo, get_distro, get_hostname};
use host_scanner::HostScanner;
use log::{LevelFilter, debug, info, warn};
use metrics::exporter::Exporter;
use rate_limiter::RateLimiter;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::watch,
    task::JoinError,
};

mod bpf;
pub mod config;
mod endpoints;
mod event;
mod host_info;
mod host_scanner;
mod metrics;
mod output;
mod pre_flight;
mod rate_limiter;

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

fn flatten_task_result(
    component: &str,
    res: Result<anyhow::Result<()>, JoinError>,
) -> anyhow::Result<()> {
    match res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => {
            bail!("{component} worker errored out: {e:?}");
        }
        Err(e) => bail!("{component} task errored out: {e:?}"),
    }
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

    let (mut bpf, rx) = Bpf::new(reloader.paths(), &reloader.config().bpf)?;
    let exporter = Exporter::new(bpf.take_metrics()?);

    let (host_scanner, rx) = HostScanner::new(
        &mut bpf,
        rx,
        reloader.paths(),
        reloader.scan_interval(),
        running.subscribe(),
        exporter.metrics.host_scanner.clone(),
    )?;

    let (rate_limiter, rx) = RateLimiter::new(
        rx,
        reloader.rate_limit(),
        running.subscribe(),
        exporter.metrics.rate_limiter.clone(),
    )?;

    let mut output_handle = output::start(
        rx,
        running.subscribe(),
        exporter.metrics.output.clone(),
        reloader.grpc(),
        reloader.otel(),
        reloader.config().json(),
    );
    let mut host_scanner_handle = host_scanner.start();
    let mut rate_limiter_handle = rate_limiter.start();
    endpoints::Server::new(exporter.clone(), reloader.endpoint(), running.subscribe()).start();
    let mut bpf_handle = bpf.start(running.subscribe(), exporter.metrics.bpf_worker.clone());
    reloader.start(running.subscribe());

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let res = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = sigterm.recv() => break Ok(()),
            _ = sighup.recv() => config_trigger.notify_one(),
            task_res = bpf_handle.borrow_mut() => {
                break flatten_task_result("BPF", task_res);
            }
            task_res = host_scanner_handle.borrow_mut() => {
                break flatten_task_result("HostScanner", task_res);
            }
            task_res = rate_limiter_handle.borrow_mut() => {
                break flatten_task_result("Rate limiter", task_res);
            }
            task_res = output_handle.borrow_mut() => {
                break flatten_task_result("Output", task_res);
            }
        }
    };

    running.send(false)?;
    info!("Exiting...");

    res
}
