use anyhow::Context;
use bpf::Bpf;
use log::info;
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::watch::channel,
};

mod bpf;
mod client;
pub mod config;
mod event;
mod health_check;
mod host_info;
mod pre_flight;

use client::Client;
use config::FactConfig;
use pre_flight::pre_flight;

pub async fn run(config: FactConfig) -> anyhow::Result<()> {
    let (tx, rx) = channel(true);

    pre_flight().context("Pre-flight checks failed")?;

    let bpf = Bpf::new(&config.paths)?;

    if config.health_check {
        // At this point the BPF code is in the kernel, we can start our
        // healthcheck probe
        health_check::start();
    }

    // Create the gRPC client
    let client = if let Some(url) = config.url.as_ref() {
        Some(Client::start(url, config.certs)?)
    } else {
        None
    };

    // Gather events from the ring buffer and print them out.
    Bpf::start_worker(client, bpf.fd, config.paths, rx.clone());

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    tx.send(false)?;
    info!("Exiting...");

    Ok(())
}
