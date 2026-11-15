//! Hydra device catalog service.
//!
//! Part of the Hydra edge device orchestration platform.
//!
//! MBSE architecture:
//! - ARCH-CATALOG-SVC → REQ-005, REQ-007
//! - ARCH-FLEET → REQ-006
//! - ARCH-DISCOVERY → REQ-008
//! - ARCH-STORAGE → REQ-014
//! - ARCH-STORAGE-SQLITE → ARCH-STORAGE (implementation)
//! - ARCH-STORAGE-POSTGRES → ARCH-STORAGE (implementation)
//! - ARCH-CATALOG-STORE → depends_on ARCH-CATALOG-SVC

mbse_graph::collect_test!();

pub mod storage;
pub mod catalog;
pub mod fleet;
pub mod discovery;

pub use storage::{DeviceStore, Device, DeviceFilters, DeviceUpdates, Fleet, DiscoveryInfo, PostgresStore, SqliteStore, StoreError};
pub use catalog::CatalogService;
pub use fleet::FleetManager;
pub use discovery::DiscoveryEngine;

#[cfg(test)]
mod tests;
