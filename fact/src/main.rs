use clap::Parser;
use env_logger::Env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(Env::default().filter_or("FACT_LOGLEVEL", "info")).init();

    let config = fact::config::FactConfig::try_parse()?;

    fact::run(config).await
}
