use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, bail};
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request, StatusCode, Uri,
    body::{Buf as _, Bytes},
    header,
};
use hyper_util::rt::TokioIo;
use log::{debug, info, warn};
use serde_json::Value as JsonValue;
use tokio::{
    io::AsyncBufReadExt,
    net::UnixStream,
    sync::{mpsc, watch},
    task::JoinSet,
};
use tokio_stream::StreamExt;
use tokio_util::{
    io::StreamReader,
    time::{
        DelayQueue,
        delay_queue::{self, Expired},
    },
};

use crate::{container::data::ContainerData, event::Event};

pub(crate) mod data;

const DOCKER_HOST: &str = "/var/run/docker.sock";
// Hex encoded "unix:///var/run/docker.sock:0"
const URI_BASE: &str = "unix://2f7661722f72756e2f646f636b65722e736f636b:0";

fn short_container_id(id: &str) -> &str {
    id.split_at(12).0
}

#[derive(Debug)]
struct ContainerMap(HashMap<String, Arc<ContainerData>>);

impl ContainerMap {
    fn new() -> Self {
        ContainerMap(HashMap::new())
    }

    fn insert(&mut self, container: Arc<ContainerData>) -> Option<Arc<ContainerData>> {
        let k = short_container_id(&container.id).to_string();
        self.0.insert(k, container)
    }

    fn remove(&mut self, id: &str) -> Option<Arc<ContainerData>> {
        if id.len() >= 12 {
            self.0.remove(short_container_id(id))
        } else {
            None
        }
    }
}

impl DerefMut for ContainerMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Deref for ContainerMap {
    type Target = HashMap<String, Arc<ContainerData>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug)]
pub struct ContainerGatherer {
    containers: ContainerMap,

    rx: mpsc::Receiver<Event>,
    tx: mpsc::Sender<Event>,

    /// Used for querying container information
    task_set: JoinSet<anyhow::Result<ContainerData>>,
    /// Used for removing container entries with a delay
    expiring_ids: DelayQueue<String>,
    /// Events waiting on container data to be queried
    pending_events: HashMap<String, HashSet<delay_queue::Key>>,
    expiring_events: DelayQueue<Event>,

    /// Global running flag
    running: watch::Receiver<bool>,
}

impl ContainerGatherer {
    pub fn new(
        rx: mpsc::Receiver<Event>,
        running: watch::Receiver<bool>,
    ) -> (Self, mpsc::Receiver<Event>) {
        let containers = ContainerMap::new();
        let task_set = JoinSet::new();
        let expiring_ids = DelayQueue::new();
        let pending_events = HashMap::new();
        let expiring_events = DelayQueue::new();
        let (tx, output) = mpsc::channel(100);

        let cg = ContainerGatherer {
            containers,
            rx,
            tx,
            task_set,
            expiring_ids,
            pending_events,
            expiring_events,
            running,
        };

        (cg, output)
    }

    async fn query_api(endpoint: &str) -> anyhow::Result<hyper::Response<hyper::body::Incoming>> {
        let uri = format!("{URI_BASE}{endpoint}").parse::<Uri>()?;

        let stream = UnixStream::connect(DOCKER_HOST).await?;
        let io = TokioIo::new(stream);

        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        // Move the handshake forward in a separate task
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                warn!("Connection failed: {e:?}");
            }
        });

        let req = Request::builder()
            .uri(uri.path())
            .header(header::HOST, uri.authority().unwrap().as_str())
            .body(Empty::<Bytes>::new())?;
        let res = sender.send_request(req).await?;

        Ok(res)
    }

    fn handle_container_create_event(&mut self, id: &str) {
        debug!("Got container create event for {id}");
        let endpoint = format!("/containers/{id}/json");
        self.task_set.spawn(async move {
            let res = ContainerGatherer::query_api(&endpoint).await?;
            if res.status() != StatusCode::OK {
                bail!("Failed to inspect container: {}", res.status());
            }

            let body = res.collect().await?.aggregate();
            let container: JsonValue = serde_json::from_reader(body.reader())?;
            ContainerData::try_from(&container)
        });
    }

    fn handle_container_remove_event(&mut self, id: &str) {
        debug!("Got container remove event for {id}");
        self.expiring_ids
            .insert(id.to_string(), Duration::from_secs(5));
    }

    fn handle_container_event(&mut self, event: &str) -> anyhow::Result<()> {
        let event: HashMap<String, JsonValue> = serde_json::from_str(event)
            .with_context(|| format!("Failed to format event: {event}"))?;
        let Some(action) = event.get("Action").and_then(|action| action.as_str()) else {
            return Ok(());
        };
        let Some(id) = event
            .get("Actor")
            .and_then(|actor| actor.get("ID").and_then(|id| id.as_str()))
        else {
            return Ok(());
        };
        match action {
            "create" => self.handle_container_create_event(id),
            "remove" => self.handle_container_remove_event(id),
            _ => {}
        }

        Ok(())
    }

    async fn send_event(&self, event: Event) {
        if let Err(e) = self.tx.send(event).await {
            warn!("Failed to send event: {e:?}");
        }
    }

    async fn handle_event(&mut self, mut event: Event) {
        let Some(container_id) = event.get_container_id() else {
            self.send_event(event).await;
            return;
        };
        match self.containers.get(container_id) {
            Some(container_data) => {
                event.set_container_data(container_data.clone());
                self.send_event(event).await;
            }
            None => {
                // We don't have the data for the container, add it to the
                // pending queue with a 200 ms timeout.
                debug!("Pending event for {container_id}");
                let container_id = short_container_id(container_id).to_string();
                self.handle_container_create_event(&container_id);
                let key = self
                    .expiring_events
                    .insert(event, Duration::from_millis(200));
                self.pending_events
                    .entry(container_id)
                    .and_modify(|pending| {
                        pending.insert(key);
                    })
                    .or_insert(HashSet::from([key]));
            }
        }
    }

    async fn handle_pending_events(&mut self, container: Arc<ContainerData>) {
        let container_id = short_container_id(&container.id);
        let Some(event_keys) = self.pending_events.remove(container_id) else {
            debug!("No waiting_events found for {}", container_id);
            return;
        };

        for key in event_keys {
            let Some(event) = self.expiring_events.try_remove(&key) else {
                continue;
            };

            let mut event = event.into_inner();
            event.set_container_data(container.clone());
            self.send_event(event).await;
        }
    }

    async fn handle_expired_event(&mut self, event: Expired<Event>) {
        // Need to remove the key from the waiting_events.
        let key = event.key();
        let event = event.into_inner();
        let Some(container_id) = event.get_container_id() else {
            unreachable!("Event with no container ID cannot be waiting on container data");
        };
        let container_id = short_container_id(container_id);
        if let Some(waiting) = self.pending_events.get_mut(container_id) {
            waiting.remove(&key);
            if waiting.is_empty() {
                self.pending_events.remove(container_id);
            }
        };
        self.send_event(event).await;
    }

    async fn start_events_stream() -> anyhow::Result<impl AsyncBufReadExt> {
        // the endpoint is URL encoded JSON equivalent to:
        //      "/events?filters={"type":["container"]}"
        let res = ContainerGatherer::query_api(
            "/events?filters=%7B%22type%22%3A%5B%22container%22%5D%7D",
        )
        .await?;
        if res.status() != StatusCode::OK {
            bail!("Failed to start events stream: {}", res.status());
        }

        let stream = res
            .into_data_stream()
            .map(|result| result.map_err(std::io::Error::other));
        Ok(StreamReader::new(stream))
    }

    async fn populate_map(&mut self) -> anyhow::Result<()> {
        let res = ContainerGatherer::query_api("/containers/json").await?;
        let body = res.collect().await?.aggregate();
        let containers: Vec<JsonValue> = serde_json::from_reader(body.reader())
            .context("Containers representation is not array")?;

        // For consistency and in order to retrieve as much infomation
        // as possible about each container, we query each one we get
        // individually. We do this by treating each container we find
        // as a container create event.
        for container in containers {
            if !container.is_object() {
                bail!("Received container is not object");
            }
            let Some(id) = container.get("Id").and_then(|id| id.as_str()) else {
                bail!("Received container has invalid ID");
            };
            self.handle_container_create_event(id);
        }

        Ok(())
    }

    pub fn start(mut self, task_set: &mut JoinSet<anyhow::Result<()>>) {
        task_set.spawn(async move {
            info!("Starting container gatherer...");

            let mut stream = ContainerGatherer::start_events_stream().await?.lines();
            self.populate_map().await?;

            loop {
                tokio::select! {
                    event = self.rx.recv() => {
                        let Some(event) = event else {
                            info!("No more events to process");
                            break;
                        };
                        self.handle_event(event).await;
                    }
                    event = stream.next_line() => {
                        let event = match event {
                            Ok(Some(event)) => event,
                            Ok(None) => {
                                warn!("Container events stream ended");
                                break;
                            }
                            Err(e) => {
                                warn!("Failed to read line: {e:?}");
                                break;
                            }
                        };
                        self.handle_container_event(&event)?;
                    }
                    res = self.task_set.join_next(), if !self.task_set.is_empty() => {
                        let container = match res {
                            Some(Ok(Ok(c))) => Arc::new(c),
                            Some(Ok(Err(e))) => {
                                warn!("Failed to retreive container information: {e}");
                                continue;
                            }
                            Some(Err(e)) => {
                                warn!("Task retreiving container information failed: {e:?}");
                                continue;
                            }
                            None => {
                                continue;
                            }
                        };
                        debug!("Resolved task for container query");
                        self.containers.insert(container.clone());
                        self.handle_pending_events(container).await;
                    }
                    Some(id) = self.expiring_ids.next(), if !self.expiring_ids.is_empty() => {
                        let id = id.into_inner();
                        self.containers.remove(&id);
                    }
                    Some(event) = self.expiring_events.next(), if !self.expiring_events.is_empty() => {
                        self.handle_expired_event(event).await;
                    }
                    _ = self.running.changed() => {
                        if !*self.running.borrow() {
                            break;
                        }
                    }
                }
            }
            info!("Stopping container gatherer...");
            Ok(())
        });
    }
}
