use anyhow::Context;

fn main() -> anyhow::Result<()> {
    tonic_prost_build::configure()
        .build_server(false)
        .include_file("mod.rs")
        .compile_protos(
            &[
                "../third_party/stackrox/proto/internalapi/sensor/sfa_iservice.proto",
                "../third_party/stackrox/proto/internalapi/sensor/signal_iservice.proto",
            ],
            &["../third_party/stackrox/proto"],
        )
        .context("Failed to compile protos. Please makes sure you update your git submodules!")?;
    Ok(())
}
