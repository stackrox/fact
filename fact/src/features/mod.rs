//! Optional event feature modules. Keep provider state and format-specific
//! enrichment inside each module; core event handling should only register the
//! feature and supply event identity when needed.

pub(crate) mod container_metadata;
pub(crate) use container_metadata::OciPathDebugInfo;

pub(crate) async fn preload(container_id: &str) {
    container_metadata::preload(container_id).await;
}

pub(crate) fn resolve(container_id: &str) -> Option<container_metadata::ContainerMetadata> {
    container_metadata::resolve(container_id)
}
