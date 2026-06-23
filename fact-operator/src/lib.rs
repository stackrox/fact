use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use k8s_openapi::api::{apps::v1::DaemonSet, core::v1::ConfigMap};
use kube::{
    Api, Client, ResourceExt,
    api::{Patch, PatchParams},
    runtime::{Controller, controller::Action, watcher},
};
use log::{info, warn};

use crate::spec::{DaemonSetBuilder, Fact};

mod spec;

struct Context {
    client: Client,
}

async fn reconcile(fact: Arc<Fact>, ctx: Arc<Context>) -> Result<Action, kube::Error> {
    info!("Starting reconciliation loop");
    let ns = fact.namespace().unwrap();

    let cm = spec::build_configmap(&fact);
    let api = Api::<ConfigMap>::namespaced(ctx.client.clone(), &ns);
    api.patch(
        &format!("{}-config", fact.name_any()),
        &PatchParams::apply("fact-operator"),
        &Patch::Apply(cm),
    )
    .await?;

    let ds = DaemonSetBuilder::from(&*fact).build();
    let api = Api::<DaemonSet>::namespaced(ctx.client.clone(), &ns);
    api.patch(
        &fact.name_any(),
        &PatchParams::apply("fact-operator"),
        &Patch::Apply(ds),
    )
    .await?;

    info!("Reconciliation done");
    Ok(Action::requeue(Duration::from_secs(300)))
}

fn error_policy(_obj: Arc<Fact>, _err: &kube::Error, _ctx: Arc<Context>) -> Action {
    Action::requeue(Duration::from_secs(60))
}

pub async fn run() -> anyhow::Result<()> {
    env_logger::init();
    info!("Operator starting...");
    let client = Client::try_default().await?;
    let fact = Api::<Fact>::all(client.clone());

    Controller::new(fact, watcher::Config::default())
        .owns(
            Api::<DaemonSet>::all(client.clone()),
            watcher::Config::default(),
        )
        .owns(
            Api::<ConfigMap>::all(client.clone()),
            watcher::Config::default(),
        )
        .run(reconcile, error_policy, Arc::new(Context { client }))
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("reconciled: {o:?}"),
                Err(e) => warn!("reconciler failed: {e:?}"),
            }
        })
        .await;

    info!("Operator done");
    Ok(())
}
