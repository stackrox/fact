use fact::config::FactConfig;

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
