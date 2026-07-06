// Library re-exports for integration/property tests and for the
// cargo-fuzz harnesses in fuzz/.

pub mod btf_offsets;
pub mod cloud_platform;
pub mod collector_health;
pub mod collectors;
pub mod detectors;
pub mod event_channels;
pub mod event_pipeline;
pub mod path_trust;

pub fn event_pipeline_builtin_packs() -> &'static [(&'static str, &'static str)] {
    event_pipeline::BUILTIN_PACKS
}
