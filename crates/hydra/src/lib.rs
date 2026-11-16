//! Hydra system orchestrator (ARCH-SYS-MGMT).
//!
//! Assembles the services into the edge device orchestration platform
//! and coordinates the CONOPS flows:
//! - CONOPS-001 — authenticate, manage the catalog, issue commands
//! - CONOPS-002 — discover, register, match a driver
//! - CONOPS-003 — fleet flows dispatched to drivers
//! - CONOPS-004 — degradation → metric stream event → audit record
//! - CONOPS-005 — scale to thousands of devices

mbse_graph::collect_test!();

pub mod provisioning;
pub mod system;

pub use provisioning::{FleetPolicy, FleetRule, Provisioned, Provisioner, ProvisionError};
pub use system::{HydraConfig, HydraSystem, SystemError, SystemStatus};

#[cfg(test)]
mod tests;
