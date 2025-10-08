use std::sync::LazyLock;

use anyhow::bail;
use pprof::{protos::Message, ProfilerGuard};
use tokio::sync::Mutex;

static PROFILER_GUARD: LazyLock<Mutex<Option<ProfilerGuard<'_>>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(Clone)]
pub struct Profiler {}

impl Profiler {
    pub fn new() -> Self {
        Profiler {}
    }

    pub async fn get_status(&self) -> &'static str {
        if PROFILER_GUARD.lock().await.is_some() {
            r#"{"cpu":"on"}"#
        } else {
            r#"{"cpu":"off"}"#
        }
    }

    pub async fn start(&self) -> anyhow::Result<()> {
        let mut guard = PROFILER_GUARD.lock().await;
        if guard.is_some() {
            bail!("CPU profiler already started");
        }

        // The blocklist is required because libunwind is not signal
        // safe. See the backtrace section in the following link:
        // https://docs.rs/crate/pprof
        *guard = Some(
            pprof::ProfilerGuardBuilder::default()
                .frequency(1000)
                .blocklist(&["libc", "libgcc", "pthread", "vdso"])
                .build()?,
        );

        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        let mut guard = PROFILER_GUARD.lock().await;
        if guard.is_none() {
            bail!("CPU profiler already stopped");
        }

        guard.take();
        Ok(())
    }

    pub async fn get(&self) -> anyhow::Result<Vec<u8>> {
        let guard = PROFILER_GUARD.lock().await;
        let Some(ref profiler) = *guard else {
            bail!("CPU profiler is not running");
        };
        let profile = profiler.report().build()?.pprof()?.encode_to_vec();
        Ok(profile)
    }
}
