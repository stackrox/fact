use crate::version::FACT_VERSION;

pub mod config;

mod version {
    include!(concat!(env!("OUT_DIR"), "/version.rs"));
}

pub fn version() -> &'static str {
    FACT_VERSION
}
