use std::sync::Arc;

use log::{debug, warn};
use tokio::{
    sync::{broadcast, mpsc, watch},
    task::JoinSet,
};

use crate::{
    config::{GrpcConfig, OTelConfig},
    event::Event,
    flatten_task_result, join_all_tasks,
    metrics::OutputMetrics,
};

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
    task_set: &mut JoinSet<anyhow::Result<()>>,
    mut rx: mpsc::Receiver<Event>,
    metrics: OutputMetrics,
    grpc_config: watch::Receiver<GrpcConfig>,
    #[allow(unused)] otel_config: watch::Receiver<OTelConfig>,
    stdout_enabled: bool,
) {
    let (broad_tx, _) = broadcast::channel(100);
    let (subs_req, mut subs_rx) = mpsc::channel(10);
    let (running, _) = watch::channel(true);
    let mut handles = JoinSet::new();

    let grpc_client = grpc::Client::new(
        subs_req.clone(),
        running.subscribe(),
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
            running.subscribe(),
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
            running.subscribe(),
            metrics.stdout.clone(),
        )
        .start(&mut handles);
    }

    task_set.spawn(async move {
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
                    break flatten_task_result(res);
                }
            }
        };
        debug!("Stopping output component...");

        if res.is_ok() {
            // Wait for outputs to empty their channels before exiting
            // ourselves.
            let receiver_count = broad_tx.receiver_count();
            drop(subs_rx);
            drop(broad_tx);

            for _ in 0..receiver_count {
                let Some(task_res) = handles.join_next().await else {
                    break;
                };
                flatten_task_result(task_res)?;
            }

            // Force idle outputs to stop
            let _ = running.send(false);
            join_all_tasks(handles).await
        } else {
            res
        }
    });
}
