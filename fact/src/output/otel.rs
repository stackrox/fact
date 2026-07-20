use std::sync::Arc;

use anyhow::bail;
use log::{debug, info, warn};
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use tokio::{
    sync::{broadcast::error::RecvError, mpsc, oneshot, watch},
    task::JoinSet,
};

use crate::{metrics::EventCounter, output::EventReceiver};

use fact_core::config::OTelConfig;

pub(super) struct Client {
    subscriber: mpsc::Sender<oneshot::Sender<EventReceiver>>,
    running: watch::Receiver<bool>,
    config: watch::Receiver<OTelConfig>,
    metrics: EventCounter,
}

impl Client {
    pub(super) fn new(
        subscriber: mpsc::Sender<oneshot::Sender<EventReceiver>>,
        running: watch::Receiver<bool>,
        metrics: EventCounter,
        config: watch::Receiver<OTelConfig>,
    ) -> Self {
        Client {
            subscriber,
            running,
            config,
            metrics,
        }
    }

    pub(super) fn start(mut self, set: &mut JoinSet<anyhow::Result<()>>) {
        set.spawn(async move {
            loop {
                let res = if self.is_enabled() {
                    self.run().await
                } else {
                    self.idle().await
                };

                match res {
                    Ok(true) => info!("Reloading oTel configuration..."),
                    Ok(false) => {
                        info!("Stopping oTel output...");
                        break;
                    }
                    Err(e) => bail!("oTel error: {e:?}"),
                }
            }
            Ok(())
        });
    }

    async fn run(&mut self) -> anyhow::Result<bool> {
        let Some(endpoint) = self.config.borrow().endpoint().map(|e| e.to_string()) else {
            bail!("Attempted to unwrap empty endpoint");
        };
        debug!("oTel: forwarding events to {endpoint}");
        let exporter_otlp = LogExporter::builder()
            .with_http()
            .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
            .with_endpoint(endpoint)
            .build()?;

        let logger_provider = SdkLoggerProvider::builder()
            .with_batch_exporter(exporter_otlp)
            .with_resource(Resource::builder().with_service_name("fact").build())
            .build();
        let logger = logger_provider.logger("fact");

        let (tx, rx) = oneshot::channel();
        self.subscriber.send(tx).await?;
        let mut rx = rx.await?;

        let res = loop {
            tokio::select! {
                event = rx.recv() => {
                    match event {
                        Ok(event) => {
                            self.metrics.added();
                            let event= Arc::unwrap_or_clone(event);
                            let mut record = logger.create_log_record();
                            record.set_severity_number(Severity::Info);
                            record.set_body(
                                format!("{} on {} ({})",
                                    event.event_type(),
                                    event.get_filename().display(),
                                    event.get_host_path().display()).into());
                            if let AnyValue::Map(map) = event.into() {
                                for (k, v) in *map {
                                    record.add_attribute(k, v);
                                }
                            }
                            logger.emit(record);
                        }
                        Err(RecvError::Closed) => break Err(anyhow::anyhow!("oTel: event stream closed")),
                        Err(RecvError::Lagged(n)) => {
                            warn!("oTel stream lagged, dropped {n} events");
                            self.metrics.dropped_n(n);
                        }
                    }
                }
                _ = self.config.changed() => break Ok(true),
                _ = self.running.changed() => break Ok(*self.running.borrow()),
            }
        };

        logger_provider.shutdown()?;
        res
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.config.borrow().endpoint().is_some()
    }

    async fn idle(&mut self) -> anyhow::Result<bool> {
        tokio::select! {
            _ = self.config.changed() => Ok(true),
            _ = self.running.changed() => Ok(*self.running.borrow()),
        }
    }
}
