use anyhow::Context;
use bpf::Bpf;
use log::{debug, info};
use output::Output;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{broadcast, watch},
};

mod bpf;
pub mod config;
mod event;
mod health_check;
mod host_info;
mod output;
mod pre_flight;

use config::FactConfig;
use pre_flight::pre_flight;

pub async fn run(config: FactConfig) -> anyhow::Result<()> {
    let (run_tx, run_rx) = watch::channel(true);
    let (tx, rx) = broadcast::channel(100);

    if !config.skip_pre_flight {
        debug!("Performing pre-flight checks");
        pre_flight().context("Pre-flight checks failed")?;
    } else {
        debug!("Skipping pre-flight checks");
    }

    let bpf = Bpf::new(&config.paths)?;

    if config.health_check {
        // At this point the BPF code is in the kernel, we can start our
        // healthcheck probe
        health_check::start();
    }

    let output = Output::new(run_rx.clone(), rx);
    output.start(&config)?;

    // Gather events from the ring buffer and print them out.
    Bpf::start_worker(tx, bpf.fd, config.paths, run_rx);

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    run_tx.send(false)?;
    info!("Exiting...");

    Ok(())
}
