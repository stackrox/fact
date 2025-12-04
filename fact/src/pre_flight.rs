use std::fs::read_to_string;

use anyhow::{bail, Context};
use log::debug;

use crate::host_info::get_host_mount;

fn have_bpf_lsm_inner(lsm_config: &str) -> anyhow::Result<()> {
    if !lsm_config.split(',').any(|cap| cap == "bpf") {
        bail!("BPF capability for LSM is not configured")
    }
    Ok(())
}

fn have_bpf_lsm() -> anyhow::Result<()> {
    let lsm_config = get_host_mount().join("sys/kernel/security/lsm");
    let lsm_config = read_to_string(lsm_config).context("Failed to read LSM configuration")?;
    have_bpf_lsm_inner(&lsm_config)
}

fn using_fips() -> anyhow::Result<()> {
    if let Err(e) = aws_lc_rs::try_fips_mode() {
        bail!("FIPS mode is not enabled: {e}");
    }
    debug!("FIPS mode enabled");
    Ok(())
}

pub fn pre_flight() -> anyhow::Result<()> {
    have_bpf_lsm()?;
    using_fips()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_have_bpf_lsm() {
        let tests = [
            (
                "lockdown,capability,yama,selinux,bpf,landlock,ipe,ima,evm",
                true,
            ),
            (
                "bpf,lockdown,capability,yama,selinux,landlock,ipe,ima,evm",
                true,
            ),
            (
                "lockdown,capability,yama,selinux,landlock,ipe,ima,evm,bpf",
                true,
            ),
            (
                "lockdown,capability,yama,selinux,landlock,ipe,ima,evm",
                false,
            ),
        ];

        for (input, available) in tests {
            let res = have_bpf_lsm_inner(input);
            assert_eq!(available, res.is_ok());
        }
    }
}
