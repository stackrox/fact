use anyhow::Context;
use aya::{Btf, programs::Lsm};
use log::debug;

pub(super) struct Checks {
    pub(super) path_hooks_support_bpf_d_path: bool,
    supports_inode_set_acl: bool,
}

impl Checks {
    pub(super) fn new(btf: &Btf) -> anyhow::Result<Self> {
        let mut obj = aya::EbpfLoader::new()
            .load(fact_ebpf::CHECKS_OBJ)
            .context("Failed to load checks.o")?;

        let path_hooks_support_bpf_d_path = Self::probe_hook(
            &mut obj,
            "check_path_unlink_supports_bpf_d_path",
            "path_unlink",
            btf,
        );
        debug!("path_hooks_support_bpf_d_path: {path_hooks_support_bpf_d_path}");

        let supports_inode_set_acl =
            Self::probe_hook(&mut obj, "check_inode_set_acl", "inode_set_acl", btf);
        debug!("supports_inode_set_acl: {supports_inode_set_acl}");

        Ok(Checks {
            path_hooks_support_bpf_d_path,
            supports_inode_set_acl,
        })
    }

    fn probe_hook(obj: &mut aya::Ebpf, prog_name: &str, hook: &str, btf: &Btf) -> bool {
        let Some(prog) = obj.program_mut(prog_name) else {
            return false;
        };
        let Ok(prog): Result<&mut Lsm, _> = prog.try_into() else {
            return false;
        };
        prog.load(hook, btf).is_ok()
    }

    pub(super) fn is_unsupported_hook(&self, hook: &str) -> bool {
        hook == "inode_set_acl" && !self.supports_inode_set_acl
    }
}
