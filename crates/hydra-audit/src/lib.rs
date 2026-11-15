//! Hydra audit service (ARCH-AUDIT).
//!
//! Maps to MBSE architecture:
//! - REQ-016 — immutable audit log for all actions made to devices
//! - P-AUDIT-FLUSH-LATENCY — flush latency to the durable store
//!
//! Immutability is structural: records form a SHA-256 hash chain, the
//! log is append-only (no remove/clear API), and `verify` detects any
//! tampering.

mbse_graph::collect_test!();

pub mod log;

pub use log::{AuditError, AuditLog, AuditRecord};

#[cfg(test)]
mod tests;
