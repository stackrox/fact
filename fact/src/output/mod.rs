use std::sync::Arc;

use log::{debug, warn};
use tokio::sync::{broadcast, mpsc, watch};

use crate::{config::GrpcConfig, event::Event, metrics::OutputMetrics};

mod grpc;
mod stdout;

/// Starts all the output tasks.
///
/// Each task is responsible for managing its lifetime, handling
/// incoming events and reloading configuration.
pub fn start(
    mut rx: mpsc::Receiver<Event>,
    running: watch::Receiver<bool>,
    metrics: OutputMetrics,
    config: watch::Receiver<GrpcConfig>,
    stdout_enabled: bool,
) -> anyhow::Result<()> {
    let (broad_tx, broad_rx) = broadcast::channel(100);
    let mut run = running.clone();
    tokio::spawn(async move {
        debug!("Starting output component...");
        loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some(event) = event else {
                        break;
                    };

                    if let Err(e) = broad_tx.send(Arc::new(event)) {
                        warn!("Failed to forward output event: {e}");
                    }
                }
                _ = run.changed() => if !*run.borrow() { break; }
            }
        }
        debug!("Stopping output component...");
    });

    let grpc_client = grpc::Client::new(
        broad_rx.resubscribe(),
        running.clone(),
        metrics.grpc.clone(),
        config.clone(),
    );

    // JSON client will only start if explicitly enabled or no other
    // output is active at startup
    if !grpc_client.is_enabled() || stdout_enabled {
        stdout::Client::new(
            broad_rx.resubscribe(),
            running.clone(),
            metrics.stdout.clone(),
        )
        .start();
    }

    grpc_client.start();

    Ok(())
}
