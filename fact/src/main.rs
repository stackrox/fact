use fact::config::FactConfig;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:false\0";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact::init_log()?;

    // Log system information as early as possible so we have it
    // available in case of a crash
    fact::log_system_information();

    let config = FactConfig::new(&[
        "/etc/stackrox/fact.yml",
        "/etc/stackrox/fact.yaml",
        "fact.yml",
        "fact.yaml",
    ])?;

    fact::run(config).await
}
