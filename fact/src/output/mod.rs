use std::sync::Arc;

use tokio::sync::{broadcast, watch};

use crate::{config::GrpcConfig, event::Event, metrics::OutputMetrics};

mod grpc;
mod stdout;

/// Starts all the output tasks.
///
/// Each task is responsible for managing its lifetime, handling
/// incoming events and reloading configuration.
pub fn start(
    rx: broadcast::Receiver<Arc<Event>>,
    running: watch::Receiver<bool>,
    metrics: OutputMetrics,
    config: watch::Receiver<GrpcConfig>,
    stdout_enabled: bool,
) -> anyhow::Result<()> {
    let grpc_client = grpc::Client::new(
        rx.resubscribe(),
        running.clone(),
        metrics.grpc.clone(),
        config.clone(),
    );

    // JSON client will only start if explicitly enabled or no other
    // output is active at startup
    if !grpc_client.is_active() || stdout_enabled {
        stdout::Client::new(rx.resubscribe(), running.clone(), metrics.stdout.clone()).start();
    }

    grpc_client.start();

    Ok(())
}
