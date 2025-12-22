use anyhow::Context;
use aya::{programs::Lsm, Btf};
use log::debug;

pub(super) struct Checks {
    pub(super) path_hooks_support_bpf_d_path: bool,
}

impl Checks {
    pub(super) fn new(btf: &Btf) -> anyhow::Result<Self> {
        let mut obj = aya::EbpfLoader::new()
            .load(fact_ebpf::CHECKS_OBJ)
            .context("Failed to load checks.o")?;

        let prog = obj
            .program_mut("check_path_unlink_supports_bpf_d_path")
            .context("Failed to find 'check_path_unlink_supports_bpf_d_path' program")?;
        let prog: &mut Lsm = prog.try_into()?;
        let path_hooks_support_bpf_d_path = prog.load("path_unlink", btf).is_ok();
        debug!("path_unlink_supports_bpf_d_path: {path_hooks_support_bpf_d_path}");

        Ok(Checks {
            path_hooks_support_bpf_d_path,
        })
    }
}
