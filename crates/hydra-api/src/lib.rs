//! Hydra API gateway, split by plane (ARCH-CTRL-GW / ARCH-DATA-GW).
//!
//! Maps to MBSE architecture:
//! - REQ-004 — an API with operations for device management
//! - REQ-018 — data-plane device ops are gated by driver fidelity
//!
//! Every request takes the full path: authenticate (ARCH-AUTH) →
//! authorize (ACL) → execute → audit (ARCH-AUDIT).

mbse_graph::collect_test!();

pub mod gateway;

pub use gateway::{
    ApiError, ApiGateway, DataPlaneGateway, DeviceOperation, Operation,
};

#[cfg(test)]
mod tests;
