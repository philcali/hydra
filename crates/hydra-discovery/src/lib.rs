//! Hydra discovery engine (ARCH-DISCOVERY).
//!
//! Maps to MBSE architecture:
//! - REQ-008 — discovery of devices on the edge network
//! - P-DISCOVERY-INTERVAL — maximum interval between discovery polls
//!
//! The scan side of the pipeline: this crate detects devices on the
//! edge network (mDNS / subnet poll / heartbeat) and hands the
//! `DiscoveredDevice` list to the catalog (ARCH-CATALOG-SVC) for
//! registration.

mbse_graph::collect_test!();

pub mod config;
pub mod engine;
pub mod sources;

pub use config::{DiscoveryConfig, DiscoveryConfigStore};
pub use engine::{DiscoveryError, DiscoveryService};
pub use sources::{DiscoveredDevice, MdnsSource, PollSource, ScanSource};

#[cfg(test)]
mod tests;
