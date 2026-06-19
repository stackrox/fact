use std::sync::Arc;

use log::{debug, warn};
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::{JoinHandle, JoinSet},
};

use crate::{event::Event, metrics::OutputMetrics};

use fact_core::config::{GrpcConfig, OTelConfig};

mod grpc;
#[cfg(feature = "otel")]
mod otel;
mod stdout;

type EventReceiver = broadcast::Receiver<Arc<Event>>;

/// Starts all the output tasks.
///
/// Each task is responsible for managing its lifetime, handling
/// incoming events and reloading configuration.
pub fn start(
    mut rx: mpsc::Receiver<Event>,
    running: watch::Receiver<bool>,
    metrics: OutputMetrics,
    grpc_config: watch::Receiver<GrpcConfig>,
    #[allow(unused)] otel_config: watch::Receiver<OTelConfig>,
    stdout_enabled: bool,
) -> JoinHandle<anyhow::Result<()>> {
    let (broad_tx, _) = broadcast::channel(100);
    let (subs_req, mut subs_rx) = mpsc::channel(10);
    let mut run = running.clone();
    let mut handles = JoinSet::new();

    let grpc_client = grpc::Client::new(
        subs_req.clone(),
        running.clone(),
        metrics.grpc.clone(),
        grpc_config,
    );
    #[allow(unused_mut)]
    let mut non_stdout_enabled = grpc_client.is_enabled();
    grpc_client.start(&mut handles);

    #[cfg(feature = "otel")]
    {
        let otel_client = otel::Client::new(
            subs_req.clone(),
            running.clone(),
            metrics.otel.clone(),
            otel_config,
        );
        non_stdout_enabled = non_stdout_enabled || otel_client.is_enabled();
        otel_client.start(&mut handles);
    }

    // JSON client will only start if explicitly enabled or no other
    // output is active at startup
    if stdout_enabled || !non_stdout_enabled {
        stdout::Client::new(
            broad_tx.subscribe(),
            running.clone(),
            metrics.stdout.clone(),
        )
        .start();
    }

    tokio::spawn(async move {
        debug!("Starting output component...");
        let res = loop {
            tokio::select! {
                event = rx.recv() => {
                    let Some(event) = event else {
                        // Channel has been closed and no more messages
                        // are present.
                        break Ok(());
                    };

                    if let Err(e) = broad_tx.send(Arc::new(event)) {
                        warn!("Failed to forward output event: {e}");
                    }
                }
                req = subs_rx.recv() => {
                    let Some(req) = req else { break Ok(()); };
                    let rx = broad_tx.subscribe();
                    if let Err(e) = req.send(rx) {
                        break Err(anyhow::anyhow!("Failed to subscribe worker: {e:?}"));
                    }
                }
                res = handles.join_next() => {
                    let Some(res) = res else {
                        unreachable!("output handles should always have a task");
                    };
                    match res {
                        Ok(Ok(_)) => break Ok(()),
                        Ok(Err(e)) => break Err(e),
                        Err(e) => break Err(e.into()),
                    }
                }
                _ = run.changed() => if !*run.borrow() { break Ok(()); }
            }
        };
        debug!("Stopping output component...");
        res
    })
}
