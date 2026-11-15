//! Append-only, hash-chained audit log (REQ-016).

use sha2::{Digest, Sha256};

use mbse::links_to;
use mbse::mbse_exempt;

/// Maximum latency for an audit flush to the durable store, in
/// milliseconds (P-AUDIT-FLUSH-LATENCY, bounded by REQ-016).
#[links_to("REQ-016", parameter = "P-AUDIT-FLUSH-LATENCY", value = 100.0)]
pub const AUDIT_FLUSH_BUDGET_MS: u64 = 100;

/// One immutable audit record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[mbse_exempt("data type — not a model node")]
pub struct AuditRecord {
    pub seq: u64,
    pub actor: String,
    pub action: String,
    pub resource: String,
    pub detail: String,
    pub ts_ms: u128,
    /// Hash of the previous record (genesis is 64 zeros).
    pub prev_hash: String,
    /// `sha256(prev_hash | seq | actor | action | resource | detail | ts_ms)`.
    pub hash: String,
}

/// Audit failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum AuditError {
    #[error("hash chain broken at record {seq}: expected {expected}, got {actual}")]
    ChainBroken {
        seq: u64,
        expected: String,
        actual: String,
    },
    #[error("durable store error: {0}")]
    Io(String),
}

/// The immutable audit log (REQ-016): every action made to a device is
/// appended; records are chained so any tampering is detectable.
#[links_to("REQ-016", component = "ARCH-AUDIT")]
pub struct AuditLog {
    records: Vec<AuditRecord>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self { records: Vec::new() }
    }

    /// Append an action to the immutable log (REQ-016).
    pub fn append(
        &mut self,
        actor: impl Into<String>,
        action: impl Into<String>,
        resource: impl Into<String>,
        detail: impl Into<String>,
    ) -> AuditRecord {
        let prev_hash = self
            .records
            .last()
            .map(|r| r.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        let seq = self.records.len() as u64;
        let (actor, action, resource, detail) =
            (actor.into(), action.into(), resource.into(), detail.into());
        let ts_ms = now_ms();
        let hash = digest(&prev_hash, seq, &actor, &action, &resource, &detail, ts_ms);
        let record = AuditRecord {
            seq,
            actor,
            action,
            resource,
            detail,
            ts_ms,
            prev_hash,
            hash,
        };
        tracing::debug!(seq = record.seq, "audit record appended");
        self.records.push(record.clone());
        record
    }

    /// Verify the whole hash chain (immutability check, REQ-016).
    pub fn verify(&self) -> Result<(), AuditError> {
        verify_records(&self.records)
    }

    /// Persist the log to a durable store (JSON lines). Returns the
    /// flush duration; compare against `AUDIT_FLUSH_BUDGET_MS`
    /// (P-AUDIT-FLUSH-LATENCY).
    pub fn flush(&self, path: impl AsRef<std::path::Path>) -> Result<std::time::Duration, AuditError> {
        let started = std::time::Instant::now();
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        use std::io::Write;
        for record in &self.records {
            serde_json::to_writer(&mut file, record)
                .map_err(|e| AuditError::Io(e.to_string()))?;
            writeln!(file).map_err(|e| AuditError::Io(e.to_string()))?;
        }
        file.flush().map_err(|e| AuditError::Io(e.to_string()))?;
        let elapsed = started.elapsed();
        tracing::debug!(?elapsed, "audit log flushed");
        Ok(elapsed)
    }

    /// The records, in append order.
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Default for AuditLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a record slice's hash chain (exposed so callers — and tests —
/// can check external copies) (REQ-016).
#[links_to("REQ-016", component = "ARCH-AUDIT")]
pub fn verify_records(records: &[AuditRecord]) -> Result<(), AuditError> {
    let mut prev_hash = "0".repeat(64);
    for (i, record) in records.iter().enumerate() {
        if record.prev_hash != prev_hash || record.seq != i as u64 {
            return Err(AuditError::ChainBroken {
                seq: i as u64,
                expected: prev_hash,
                actual: record.prev_hash.clone(),
            });
        }
        let expected = digest(
            &record.prev_hash,
            record.seq,
            &record.actor,
            &record.action,
            &record.resource,
            &record.detail,
            record.ts_ms,
        );
        if record.hash != expected {
            return Err(AuditError::ChainBroken {
                seq: record.seq,
                expected,
                actual: record.hash.clone(),
            });
        }
        prev_hash = record.hash.clone();
    }
    Ok(())
}

fn digest(
    prev_hash: &str,
    seq: u64,
    actor: &str,
    action: &str,
    resource: &str,
    detail: &str,
    ts_ms: u128,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(seq.to_le_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(resource.as_bytes());
    hasher.update(detail.as_bytes());
    hasher.update(ts_ms.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
