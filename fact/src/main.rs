use fact::config::FactConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact::init_log()?;
    let config = FactConfig::new(&[
        "/etc/stackrox/fact.yml",
        "/etc/stackrox/fact.yaml",
        "fact.yml",
        "fact.yaml",
    ])?;

    fact::run(config).await
}
