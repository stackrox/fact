use anyhow::Context;

fn main() -> anyhow::Result<()> {
    tonic_build::configure()
        .build_server(false)
        .compile_protos(
            &["../third_party/stackrox/proto/internalapi/sensor/sfa_iservice.proto"],
            &["../third_party/stackrox/proto"],
        )
        .context("Failed to compile protos. Please makes sure you update your git submodules!")?;
    Ok(())
}
