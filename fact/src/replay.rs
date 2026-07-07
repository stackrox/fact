use std::path::Path;

use anyhow::Context;
use log::{info, warn};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    sync::{mpsc, watch},
    task::JoinSet,
};

use crate::event::Event;

pub fn start(
    task_set: &mut JoinSet<anyhow::Result<()>>,
    path: &Path,
    running: watch::Receiver<bool>,
) -> anyhow::Result<mpsc::Receiver<Event>> {
    anyhow::ensure!(
        path.exists(),
        "Replay file does not exist: {}",
        path.display()
    );
    let (tx, rx) = mpsc::channel(100);
    let path = path.to_owned();

    task_set.spawn(async move {
        let file = tokio::fs::File::open(&path)
            .await
            .with_context(|| format!("Failed to open replay file: {}", path.display()))?;
        let reader = BufReader::new(file);
        let mut lines = reader.lines();

        info!("Replaying events from {}", path.display());
        while let Some(line) = lines.next_line().await? {
            if !*running.borrow() {
                break;
            }

            let value: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to parse JSON: {e}");
                    continue;
                }
            };
            match serde_json::from_value::<Event>(value) {
                Ok(event) => {
                    if tx.send(event).await.is_err() {
                        break;
                    }
                }
                Err(e) => warn!("Failed to deserialize event: {e}"),
            }
        }

        info!("Replay finished");
        Ok(())
    });

    Ok(rx)
}
