//! Hydra audit service (ARCH-AUDIT) — cross-system, domain-scoped audit.
//!
//! Every control-plane action (REQ-036) and data-plane device operation
//! (REQ-037) is appended to an immutable, hash-chained log (REQ-016) on a
//! pluggable, configurable durable store (REQ-038) that operators can query
//! (REQ-039). Records can be pushed out to delivery targets (REQ-040), and
//! retention is enforced (REQ-041).
//!
//! Immutability is structural: records form a SHA-256 hash chain per
//! domain, the store is append-only (no remove/clear API), and
//! `verify_records` detects any tampering. The only way records leave the
//! active log is explicit retention rotation (REQ-041).

mbse_graph::collect_test!();

pub mod backend;
pub mod delivery;
pub mod engine;
pub mod record;

pub use backend::{
    AuditBackend, PostgresAuditStore, SqliteAuditStore, AUDIT_FLUSH_BUDGET_MS,
    AUDIT_RETENTION_RECORDS,
};
pub use delivery::{
    AuditHttp, AuditTransport, CallbackAuditTransport, HttpAuditTransport, RecordingAuditHttp,
};
pub use engine::{AuditBackendKind, AuditConfig, AuditEngine};
pub use record::{
    now_ms, verify_records, AuditDomain, AuditError, AuditFilters, AuditRecord,
};

#[cfg(test)]
mod tests;
