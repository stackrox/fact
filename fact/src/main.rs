#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact::init_log()?;

    fact::run().await
}
