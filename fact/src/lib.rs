use std::{io::Write, path::PathBuf, str::FromStr, time::Duration};

use anyhow::{Context, Result};
use bpf::Bpf;
use host_info::{SystemInfo, get_distro, get_hostname};
use host_scanner::HostScanner;
use log::{LevelFilter, debug, info, warn};
use metrics::exporter::Exporter;
use rate_limiter::RateLimiter;
use tokio::{
    signal::unix::{SignalKind, signal},
    sync::{mpsc, watch},
    task::JoinSet,
    time::timeout,
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
mod replay;

use config::FactConfig;
use pre_flight::pre_flight;

use crate::{
    config::BpfConfig,
    event::Event,
    metrics::{Metrics, kernel_metrics::KernelMetrics},
};

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
    task_res: Result<anyhow::Result<()>, impl Into<anyhow::Error>>,
) -> anyhow::Result<()> {
    match task_res {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(e) => Err(e.into()),
    }
}

async fn join_all_tasks(mut task_set: JoinSet<anyhow::Result<()>>) -> anyhow::Result<()> {
    while let Some(task_res) = task_set.join_next().await {
        flatten_task_result(task_res)?;
    }
    Ok(())
}

struct SetupArgs<'a> {
    skip_pre_flight: bool,
    running: watch::Receiver<bool>,
    task_set: &'a mut JoinSet<anyhow::Result<()>>,
    reloader: &'a config::reloader::Reloader,
    metrics: &'a Metrics,

    // Replay mode
    replay: Option<PathBuf>,

    // BPF mode
    bpf_config: BpfConfig,
}

pub async fn run(config: FactConfig) -> anyhow::Result<()> {
    // Log system information as early as possible so we have it
    // available in case of a crash
    log_system_information();
    let (running_pipeline_tx, running_pipeline_rx) = watch::channel(true);
    let (running_helpers, _) = watch::channel(true);

    let stdout_enabled = config.json();
    let skip_pre_flight = config.skip_pre_flight();
    let replay = config.replay().map(PathBuf::from);
    let bpf_config = config.bpf.clone();

    let metrics_userspace = Metrics::new();
    let mut task_set = JoinSet::new();
    let reloader = config::reloader::Reloader::from(config);

    let setup_args = SetupArgs {
        skip_pre_flight,
        running: running_pipeline_rx.clone(),
        task_set: &mut task_set,
        reloader: &reloader,
        metrics: &metrics_userspace,
        replay,
        bpf_config,
    };

    let config_trigger = reloader.get_trigger();

    let (metrics_kernelspace, rx) = setup_input(setup_args)?;
    let (rate_limiter, rx) = RateLimiter::new(
        rx,
        reloader.rate_limit(),
        metrics_userspace.rate_limiter.clone(),
    )?;

    output::start(
        &mut task_set,
        rx,
        metrics_userspace.output.clone(),
        reloader.grpc(),
        reloader.otel(),
        stdout_enabled,
    );

    rate_limiter.start(&mut task_set);
    let exporter = Exporter::new(&metrics_userspace, metrics_kernelspace);
    endpoints::Server::new(exporter, reloader.endpoint(), running_helpers.subscribe()).start();
    reloader.start(running_helpers.subscribe());

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;
    let mut res = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = sigterm.recv() => break Ok(()),
            _ = sighup.recv() => config_trigger.notify_one(),
            task_res = task_set.join_next() => {
                let Some(task_res) = task_res else {
                    unreachable!("No task in task_set");
                };
                break flatten_task_result(task_res);
            }
        }
    };

    // Stop the input of the pipeline, this will cascade as the sender
    // ends of the channels used for communication are dropped, causing
    // elements in the pipeline to be stopped as they empty their
    // receivers.
    let _ = running_pipeline_tx.send(false);
    if res.is_ok() {
        let join_res = timeout(Duration::from_secs(5), join_all_tasks(task_set)).await;
        res = flatten_task_result(join_res);
    }
    let _ = running_helpers.send(false);

    info!("Exiting...");
    res
}

fn setup_input(args: SetupArgs) -> anyhow::Result<(Option<KernelMetrics>, mpsc::Receiver<Event>)> {
    match args.replay {
        Some(replay_file) => {
            let rx = replay::start(args.task_set, &replay_file, args.running)?;
            Ok((None, rx))
        }
        None => {
            if !args.skip_pre_flight {
                debug!("Performing pre-flight checks");
                pre_flight().context("Pre-flight checks failed")?;
            } else {
                debug!("Skipping pre-flight checks");
            }

            bpf_input(args)
        }
    }
}

fn bpf_input(args: SetupArgs) -> anyhow::Result<(Option<KernelMetrics>, mpsc::Receiver<Event>)> {
    let (mut bpf, rx) = Bpf::new(
        args.reloader.paths(),
        &args.bpf_config,
        args.running.clone(),
        args.metrics.bpf_worker.clone(),
    )?;
    let metrics_kernelspace = KernelMetrics::new(bpf.take_metrics()?);

    let (host_scanner, rx) = HostScanner::new(
        &mut bpf,
        rx,
        args.reloader.paths(),
        args.reloader.scan_interval(),
        args.metrics.host_scanner.clone(),
    )?;

    bpf.start(args.task_set);
    host_scanner.start(args.task_set);
    Ok((Some(metrics_kernelspace), rx))
}
