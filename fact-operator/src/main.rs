#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fact_operator::run().await
}
