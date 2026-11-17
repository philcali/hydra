//! The audit engine (ARCH-AUDIT): the cross-system audit service.
//!
//! Every control-plane action (REQ-036) and data-plane device operation
//! (REQ-037) is appended to the immutable, hash-chained log (REQ-016). The
//! log lives on a pluggable, configurable durable store (REQ-038) that is
//! queryable (REQ-039); records can be pushed out to delivery targets
//! (REQ-040); retention is enforced (REQ-041).

use std::time::Instant;

use crate::backend::{
    AuditBackend, PostgresAuditStore, SqliteAuditStore, AUDIT_RETENTION_RECORDS,
};
use crate::delivery::{AuditHttp, AuditTransport, HttpAuditTransport};
use crate::record::{
    now_ms, verify_records, AuditDomain, AuditError, AuditFilters, AuditRecord,
};

use mbse::links_to;
use mbse::mbse_exempt;

/// Which persistence backend to use — configured at startup (REQ-038).
#[derive(Debug, Clone)]
#[mbse_exempt("config data type — not a model node")]
pub enum AuditBackendKind {
    /// Single-node / edge (ARCH-AUDIT-SQLITE).
    Sqlite { path: String },
    /// Multi-node / production (ARCH-AUDIT-POSTGRES).
    Postgres { url: String },
}

/// Startup configuration for the audit subsystem (REQ-038): which
/// persistence backend, the retention bound, and the delivery target.
#[derive(Debug, Clone)]
#[mbse_exempt("config data type — not a model node")]
pub struct AuditConfig {
    pub backend: AuditBackendKind,
    /// Maximum records kept per domain in the active log (bounded by
    /// P-AUDIT-RETENTION).
    pub retention_records: u64,
    /// If set, each record is also pushed to this endpoint (REQ-040).
    /// Building the engine requires an `AuditHttp` client (see
    /// `AuditConfig::engine`).
    pub delivery_url: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            backend: AuditBackendKind::Sqlite {
                path: "hydra-audit.db".into(),
            },
            retention_records: AUDIT_RETENTION_RECORDS,
            delivery_url: None,
        }
    }
}

impl AuditConfig {
    /// Build the configured backend (REQ-038).
    pub fn backend(&self) -> Result<Box<dyn AuditBackend>, AuditError> {
        match &self.backend {
            AuditBackendKind::Sqlite { path } => {
                Ok(Box::new(SqliteAuditStore::open(path.clone())?))
            }
            AuditBackendKind::Postgres { url } => {
                Ok(Box::new(PostgresAuditStore::new(url.clone())))
            }
        }
    }

    /// Build the full engine from this configuration (REQ-038/040).
    ///
    /// `http` is required when `delivery_url` is set — the transport is
    /// built here so the caller never sees transport details.
    pub fn engine(&self, http: Option<Box<dyn AuditHttp>>) -> Result<AuditEngine, AuditError> {
        let backend = self.backend()?;
        let delivery = match &self.delivery_url {
            Some(url) => {
                let client = http
                    .ok_or_else(|| AuditError::Io("delivery_url set but no AuditHttp client".into()))?;
                Some(Box::new(HttpAuditTransport::with_boxed_client(url.clone(), client))
                    as Box<dyn AuditTransport>)
            }
            None => None,
        };
        Ok(AuditEngine::new(
            backend,
            delivery,
            self.retention_records,
        ))
    }
}

/// The audit service (ARCH-AUDIT, REQ-016): domain-scoped, immutable,
/// hash-chained audit on a pluggable durable store (REQ-036/037/038).
#[links_to("REQ-016", component = "ARCH-AUDIT")]
#[links_to("REQ-036", component = "ARCH-AUDIT")]
#[links_to("REQ-037", component = "ARCH-AUDIT")]
#[links_to("REQ-038", component = "ARCH-AUDIT")]
pub struct AuditEngine {
    backend: Box<dyn AuditBackend>,
    delivery: Option<Box<dyn AuditTransport>>,
    retention: u64,
}

impl AuditEngine {
    /// Assemble the engine over a ready backend.
    pub fn new(
        backend: Box<dyn AuditBackend>,
        delivery: Option<Box<dyn AuditTransport>>,
        retention: u64,
    ) -> Self {
        Self {
            backend,
            delivery,
            retention,
        }
    }

    /// Append an action to the immutable log (REQ-016/036/037) and, when a
    /// delivery target is configured, push the record out (REQ-040).
    ///
    /// `result` carries the outcome: `"ok"` for success, `"denied: …"` /
    /// `"unauthorized: …"` / `"error: …"` for failures — failed and denied
    /// actions are audited too, so the log is a complete account of what was
    /// attempted and what happened.
    pub async fn append(
        &self,
        domain: AuditDomain,
        actor: &str,
        action: &str,
        resource: &str,
        detail: &str,
        result: &str,
    ) -> Result<AuditRecord, AuditError> {
        let head = self.backend.head(domain).await?;
        let (generation, seq, prev_hash) = match head {
            Some(head) => (head.generation, head.seq + 1, head.hash),
            None => (0, 0, "0".repeat(64)),
        };
        let ts_ms = now_ms();
        let record = AuditRecord {
            domain,
            generation,
            seq,
            actor: actor.to_string(),
            action: action.to_string(),
            resource: resource.to_string(),
            detail: detail.to_string(),
            result: result.to_string(),
            ts_ms,
            prev_hash: prev_hash.clone(),
            hash: crate::record::digest(
                &prev_hash,
                domain,
                generation,
                seq,
                actor,
                action,
                resource,
                detail,
                result,
                ts_ms,
            ),
        };

        // Persist first — the log is the source of truth.
        self.backend.append(record.clone()).await?;

        // Then push out, best-effort (REQ-040): a failed delivery is logged,
        // never rolled back against the durable record.
        if let Some(transport) = &self.delivery {
            if let Err(e) = transport.deliver(&record) {
                tracing::warn!(%e, "audit delivery failed (record is persisted)");
            }
        }
        Ok(record)
    }

    /// Query the audit log (REQ-039).
    pub async fn query(&self, filters: &AuditFilters) -> Result<Vec<AuditRecord>, AuditError> {
        self.backend.query(filters).await
    }

    /// All records, in chain order (a convenience for tests and tooling).
    pub async fn records(&self) -> Result<Vec<AuditRecord>, AuditError> {
        self.backend.query(&AuditFilters::default()).await
    }

    /// Verify the hash chains (immutability check, REQ-016).
    pub async fn verify(&self) -> Result<(), AuditError> {
        let records = self.records().await?;
        verify_records(&records)
    }

    /// Enforce retention: rotate each domain's oldest records beyond the
    /// bound out of the active log (REQ-041). Returns the count rotated.
    pub async fn rotate(&self) -> Result<u64, AuditError> {
        let started = Instant::now();
        let rotated = self.backend.rotate(self.retention).await?;
        tracing::debug!(rotated, elapsed_ms = started.elapsed().as_millis(), "audit retention applied");
        Ok(rotated)
    }

    /// The number of stored records (all domains).
    pub async fn len(&self) -> Result<u64, AuditError> {
        self.backend.len().await
    }

    /// The retention bound for this engine (bounded by P-AUDIT-RETENTION).
    pub fn retention(&self) -> u64 {
        self.retention
    }

    /// Whether a delivery target is configured (REQ-040).
    pub fn delivery_configured(&self) -> bool {
        self.delivery.is_some()
    }
}
