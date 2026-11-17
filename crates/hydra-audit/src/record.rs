//! Audit records, domains, filters, and chain verification.
//!
//! REQ-016 (the immutable log), REQ-036/REQ-037 (domain-scoped records),
//! REQ-039 (query filters).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use mbse::links_to;
use mbse::mbse_exempt;

/// Which plane an audited action belongs to (REQ-036 / REQ-037).
///
/// - `ControlPlane` — the "who did what" log: operator and management-layer
///   actions (catalog, fleets, discovery config) (REQ-036).
/// - `DataPlane` — the per-device operation log: what was done to a specific
///   device (config read/write, commands) (REQ-037).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[mbse_exempt("data type — not a model node")]
pub enum AuditDomain {
    ControlPlane,
    DataPlane,
}

impl AuditDomain {
    /// The storage form of the domain.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditDomain::ControlPlane => "control",
            AuditDomain::DataPlane => "data",
        }
    }

    /// Parse the storage form of the domain.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "control" => Some(AuditDomain::ControlPlane),
            "data" => Some(AuditDomain::DataPlane),
            _ => None,
        }
    }
}

/// One immutable audit record (REQ-016).
///
/// Records form a SHA-256 hash chain per domain: each record's `prev_hash`
/// is the hash of the previous record in the same domain (the domain's first
/// record chains from 64 zeros). Retention rotation (REQ-041) may truncate
/// the oldest records of a domain; the surviving head's `prev_hash` then
/// references a record that no longer exists, which `verify_records` accepts
/// by design (internal links and every self-hash are still checked).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[mbse_exempt("data type — not a model node")]
pub struct AuditRecord {
    pub domain: AuditDomain,
    /// Rotation generation (0 = the active log).
    pub generation: u64,
    /// Sequence within the domain's active chain.
    pub seq: u64,
    /// Who performed the action (the principal, or "system").
    pub actor: String,
    /// The action (e.g. `catalog:create`, `device:reboot`).
    pub action: String,
    /// The resource the action was made on.
    pub resource: String,
    /// Free-form context (e.g. "via control plane", "discovered at 10.1.1.5").
    pub detail: String,
    /// The outcome: `"ok"`, or `"denied: …"` / `"error: …"` / `"unauthorized: …"`.
    pub result: String,
    /// Milliseconds since the Unix epoch (fits i64 for ~290,000 years).
    pub ts_ms: u64,
    /// Hash of the previous record in the domain's chain (genesis is 64 zeros).
    pub prev_hash: String,
    /// `sha256(prev_hash | domain | generation | seq | actor | action | resource | detail | result | ts_ms)`.
    pub hash: String,
}

/// Filters for querying the audit log (REQ-039): by domain, actor, action,
/// resource prefix, and time range. All fields optional; `None` = no filter.
#[derive(Debug, Clone, Default)]
#[mbse_exempt("data type — not a model node")]
pub struct AuditFilters {
    pub domain: Option<AuditDomain>,
    pub actor: Option<String>,
    pub action: Option<String>,
    /// Match resources starting with this prefix (e.g. `devices/dev-1`).
    pub resource_prefix: Option<String>,
    pub since_ms: Option<u64>,
    pub until_ms: Option<u64>,
    pub limit: Option<u32>,
}

/// Audit failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum AuditError {
    #[error("hash chain broken at {domain:?} seq {seq}: expected {expected}, got {actual}")]
    ChainBroken {
        domain: AuditDomain,
        seq: u64,
        expected: String,
        actual: String,
    },
    #[error("durable store error: {0}")]
    Io(String),
}

/// The record digest (the chain link) — the integrity primitive that makes
/// the log tamper-evident (REQ-016).
#[links_to("REQ-016", component = "ARCH-AUDIT")]
pub fn digest(
    prev_hash: &str,
    domain: AuditDomain,
    generation: u64,
    seq: u64,
    actor: &str,
    action: &str,
    resource: &str,
    detail: &str,
    result: &str,
    ts_ms: u64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(domain.as_str().as_bytes());
    hasher.update(generation.to_le_bytes());
    hasher.update(seq.to_le_bytes());
    hasher.update(actor.as_bytes());
    hasher.update(action.as_bytes());
    hasher.update(resource.as_bytes());
    hasher.update(detail.as_bytes());
    hasher.update(result.as_bytes());
    hasher.update(ts_ms.to_le_bytes());
    hex::encode(hasher.finalize())
}

/// Verify a record slice's hash chain (exposed so callers — and tests — can
/// check external copies) (REQ-016).
///
/// Records are grouped by domain and ordered by (generation, seq). Every
/// record's self-digest must match, and every record after the first in its
/// domain must link to the previous record's hash. The domain's first record
/// is exempt from a genesis check: after retention rotation (REQ-041) its
/// `prev_hash` may reference a truncated record, by design.
#[links_to("REQ-016", component = "ARCH-AUDIT")]
pub fn verify_records(records: &[AuditRecord]) -> Result<(), AuditError> {
    let mut groups: BTreeMap<AuditDomain, Vec<&AuditRecord>> = BTreeMap::new();
    for record in records {
        groups.entry(record.domain).or_default().push(record);
    }
    for (domain, mut group) in groups {
        group.sort_by(|a, b| (a.generation, a.seq).cmp(&(b.generation, b.seq)));
        for (i, record) in group.iter().enumerate() {
            if i > 0 && record.prev_hash != group[i - 1].hash {
                return Err(AuditError::ChainBroken {
                    domain,
                    seq: record.seq,
                    expected: group[i - 1].hash.clone(),
                    actual: record.prev_hash.clone(),
                });
            }
            let expected = digest(
                &record.prev_hash,
                record.domain,
                record.generation,
                record.seq,
                &record.actor,
                &record.action,
                &record.resource,
                &record.detail,
                &record.result,
                record.ts_ms,
            );
            if record.hash != expected {
                return Err(AuditError::ChainBroken {
                    domain,
                    seq: record.seq,
                    expected,
                    actual: record.hash.clone(),
                });
            }
        }
    }
    Ok(())
}

/// The current wall-clock time in ms since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
