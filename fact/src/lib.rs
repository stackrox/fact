use std::sync::Arc;

use anyhow::Context;
use bpf::Bpf;
use log::{info, debug};
use tokio::{
    signal::unix::{signal, SignalKind},
    sync::{broadcast, watch},
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
    let (run_tx, run_rx) = watch::channel(true);
    let (output_tx, mut output_rx) = broadcast::channel(100);

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

    // Create the gRPC client
    let mut client = if let Some(url) = config.url.as_ref() {
        Some(Client::start(url, config.certs)?)
    } else {
        None
    };

    let mut running = run_rx.clone();

    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = output_rx.recv() => {
                    let event = Arc::unwrap_or_clone(event.expect("Failed to receive event"));

                    println!("{event:?}");
                    if let Some(client) = client.as_mut() {
                         client.send(event).await.unwrap();
                    }
                },
                _ = running.changed() => {
                    if !*running.borrow() {
                        info!("Stopping output worker...");
                        return;
                    }
                }
            }
        }
    });

    // Gather events from the ring buffer and print them out.
    Bpf::start_worker(output_tx, bpf.fd, config.paths, run_rx.clone());

    let mut sigterm = signal(SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }

    run_tx.send(false)?;
    info!("Exiting...");

    Ok(())
}
