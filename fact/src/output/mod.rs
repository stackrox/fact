use std::{borrow::BorrowMut, sync::Arc};

use anyhow::bail;
use log::{debug, warn};
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinHandle,
};

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
) -> JoinHandle<anyhow::Result<()>> {
    let (broad_tx, broad_rx) = broadcast::channel(100);
    let mut run = running.clone();

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

    let mut grpc_handle = grpc_client.start();

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
                res = grpc_handle.borrow_mut() => {
                    match res {
                        Ok(Ok(_)) => break,
                        Ok(Err(e)) => bail!("grpc worker errored out: {e:?}"),
                        Err(e) => bail!("grpc task errored out: {e:?}"),
                    }
                }
                _ = run.changed() => if !*run.borrow() { break; }
            }
        }
        debug!("Stopping output component...");
        Ok(())
    })
}
