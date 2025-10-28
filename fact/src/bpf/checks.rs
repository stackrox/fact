use anyhow::{Context, Ok};
use aya::{programs::Lsm, Btf, Ebpf};
use log::debug;

#[derive(Default)]
pub(super) struct Checks {
    pub(super) lsm_support: bool,
    pub(super) path_unlink_supports_bpf_d_path: bool,
}

impl Checks {
    pub(super) fn new(btf: &Btf) -> anyhow::Result<Self> {
        let checks = ChecksBuilder::new(btf)?
            .check_lsm_support()
            .check_path_unlink_supports_bpf_d_path()
            .build();

        Ok(checks)
    }
}

struct ChecksBuilder<'a> {
    obj: Ebpf,
    btf: &'a Btf,
    checks: Checks,
}

impl<'a> ChecksBuilder<'a> {
    fn new(btf: &'a Btf) -> anyhow::Result<Self> {
        let obj = aya::EbpfLoader::new()
            .load(fact_ebpf::CHECKS_OBJ)
            .context("Failed to load checks.o")?;

        let checks = Checks::default();

        Ok(ChecksBuilder { obj, btf, checks })
    }

    fn build(self) -> Checks {
        self.checks
    }

    fn check_lsm_support(mut self) -> Self {
        let prog = self
            .obj
            .program_mut("check_lsm_support")
            .expect("Failed to find 'check_lsm_support' program");
        let prog: &mut Lsm = prog.try_into().expect("'check_lsm_support' is not Lsm");

        self.checks.lsm_support = prog.load("file_open", self.btf).is_ok() && prog.attach().is_ok();
        self
    }

    fn check_path_unlink_supports_bpf_d_path(mut self) -> Self {
        let prog = self
            .obj
            .program_mut("check_path_unlink_supports_bpf_d_path")
            .expect("Failed to find 'check_path_unlink_supports_bpf_d_path' program");
        let prog: &mut Lsm = prog
            .try_into()
            .expect("'check_path_unlink_supports_bpf_d_path' is not Lsm");
        let path_unlink_supports_bpf_d_path = prog.load("path_unlink", self.btf).is_ok();
        debug!("path_unlink_supports_bpf_d_path: {path_unlink_supports_bpf_d_path}");
        self
    }
}
