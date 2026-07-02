use std::sync::Arc;

use log::warn;
use opentelemetry::logs::{AnyValue, LogRecord, Logger, LoggerProvider, Severity};
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use tokio::sync::broadcast::{self, error::RecvError};

use crate::event::Event;

pub(super) struct Client {
    rx: broadcast::Receiver<Arc<Event>>,
}

impl Client {
    pub(super) fn new(rx: broadcast::Receiver<Arc<Event>>) -> Self {
        Client { rx }
    }

    pub(super) fn start(mut self) {
        tokio::spawn(async move {
            let exporter_otlp = LogExporter::builder()
                .with_http()
                .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
                .with_endpoint("http://127.0.0.1:4318/v1/logs")
                .build()
                .expect("Failed to create log exporter");

            let logger_provider = SdkLoggerProvider::builder()
                .with_batch_exporter(exporter_otlp)
                .with_resource(Resource::builder().with_service_name("fact").build())
                .build();
            let logger = logger_provider.logger("fact");

            loop {
                match self.rx.recv().await {
                    Ok(event) => {
                        let event = Arc::unwrap_or_clone(event).into();
                        let mut record = logger.create_log_record();
                        record.set_severity_number(Severity::Info);
                        if let AnyValue::Map(map) = event {
                            for (k, v) in *map {
                                record.add_attribute(k, v);
                            }
                        }
                        logger.emit(record);
                    }
                    Err(RecvError::Closed) => break,
                    Err(RecvError::Lagged(n)) => {
                        warn!("oTel stream lagged, dropped {n} events");
                    }
                }
            }

            let _ = logger_provider.shutdown();
        });
    }
}
