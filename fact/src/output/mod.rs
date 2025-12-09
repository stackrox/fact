use std::sync::Arc;

use log::{info, warn};
use tokio::sync::{broadcast, mpsc, watch};

use crate::{config::GrpcConfig, event::Event, metrics::OutputMetrics};

mod grpc;
mod stdout;

/// Starts all the output tasks.
///
/// Each task is responsible for managing its lifetime, handling
/// incoming events and reloading configuration.
pub fn start(
    mut input: mpsc::Receiver<Event>,
    mut running: watch::Receiver<bool>,
    metrics: OutputMetrics,
    config: watch::Receiver<GrpcConfig>,
    stdout_enabled: bool,
) -> anyhow::Result<()> {
    let (tx, _) = broadcast::channel(100);

    let grpc_client = grpc::Client::new(
        tx.subscribe(),
        running.clone(),
        metrics.grpc.clone(),
        config.clone(),
    );

    // JSON client will only start if explicitly enabled or no other
    // output is active at startup
    if !grpc_client.is_enabled() || stdout_enabled {
        stdout::Client::new(tx.subscribe(), running.clone(), metrics.stdout.clone()).start();
    }

    tokio::spawn(async move {
        info!("Starting output dispatcher");
        loop {
            tokio::select! {
                event = input.recv() => {
                    let Some(event) = event else {
                        info!("No more messages to process");
                        break;
                    };
                    if let Err(e) = tx.send(Arc::new(event)) {
                        warn!("Failed to receive message: {e}");
                    }
                },
                _ = running.changed() => {
                    if !*running.borrow() {
                        info!("Stopping output dispatcher");
                        break;
                    }
                }
            }
        }
    });

    grpc_client.start();

    Ok(())
}
