//! Audit persistence backends (REQ-038) — the pluggable, configurable
//! durable store for the audit log:
//! - `SqliteAuditStore` (ARCH-AUDIT-SQLITE) — single-node / edge.
//! - `PostgresAuditStore` (ARCH-AUDIT-POSTGRES) — multi-node / production.
//!
//! The engine (ARCH-AUDIT) only sees the `AuditBackend` trait, so the
//! persistence mechanism is swappable at startup without touching the
//! audit logic.

use async_trait::async_trait;
use tokio::sync::Mutex;

use crate::record::{verify_records, AuditDomain, AuditError, AuditFilters, AuditRecord};

use mbse::links_to;

/// Maximum latency for an audit write to the durable store, in
/// milliseconds (P-AUDIT-FLUSH-LATENCY, constrained by REQ-038).
#[links_to("REQ-038", parameter = "P-AUDIT-FLUSH-LATENCY", value = 100.0)]
pub const AUDIT_FLUSH_BUDGET_MS: u64 = 100;

/// Default retention: the maximum number of records kept in a domain's
/// active log before rotation (P-AUDIT-RETENTION, constrained by REQ-041).
#[links_to("REQ-041", parameter = "P-AUDIT-RETENTION", value = 10000.0)]
pub const AUDIT_RETENTION_RECORDS: u64 = 10000;

/// The pluggable persistence boundary (REQ-038, ARCH-AUDIT).
///
/// Backends are append-only: there is no remove/clear API. The only way
/// records leave the active log is explicit retention rotation (REQ-041).
#[links_to("REQ-038", component = "ARCH-AUDIT")]
#[async_trait]
pub trait AuditBackend: Send + Sync {
    /// The head of a domain's active chain (its latest record), if any.
    async fn head(&self, domain: AuditDomain) -> Result<Option<AuditRecord>, AuditError>;

    /// Append a record to the domain's chain.
    async fn append(&self, record: AuditRecord) -> Result<(), AuditError>;

    /// Query records by filter, in chain order (domain, generation, seq)
    /// (REQ-039).
    async fn query(&self, filters: &AuditFilters) -> Result<Vec<AuditRecord>, AuditError>;

    /// Verify the hash chains of all stored records (REQ-016).
    async fn verify(&self) -> Result<(), AuditError>;

    /// Rotate each domain's oldest records out of the active log beyond
    /// `retention` (REQ-041). Returns the number of records rotated.
    async fn rotate(&self, retention: u64) -> Result<u64, AuditError>;

    /// The number of stored records (all domains).
    async fn len(&self) -> Result<u64, AuditError>;
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    generation INTEGER NOT NULL DEFAULT 0,
    seq INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    detail TEXT NOT NULL,
    result TEXT NOT NULL,
    ts_ms INTEGER NOT NULL,
    prev_hash TEXT NOT NULL,
    hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_domain_seq ON audit_records(domain, generation, seq);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_records(actor);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_records(action);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_records(ts_ms);
"#;

#[links_to("REQ-038", component = "ARCH-AUDIT-SQLITE")]
#[links_to("REQ-039", component = "ARCH-AUDIT-SQLITE")]
fn record_from_row(row: &rusqlite::Row) -> rusqlite::Result<AuditRecord> {
    let domain: String = row.get(0)?;
    let ts_ms: i64 = row.get(8)?;
    Ok(AuditRecord {
        domain: AuditDomain::parse(&domain)
            .ok_or_else(|| rusqlite::Error::InvalidColumnName(domain.to_string()))?,
        generation: row.get(1)?,
        seq: row.get(2)?,
        actor: row.get(3)?,
        action: row.get(4)?,
        resource: row.get(5)?,
        detail: row.get(6)?,
        result: row.get(7)?,
        ts_ms: u64::try_from(ts_ms).map_err(|_| rusqlite::Error::InvalidColumnType(
            8,
            "ts_ms".into(),
            rusqlite::types::Type::Integer,
        ))?,
        prev_hash: row.get(9)?,
        hash: row.get(10)?,
    })
}

/// SQLite audit store (ARCH-AUDIT-SQLITE): the queryable, durable local
/// store for single-node / edge deployments (REQ-038/039/041).
///
/// Single shared connection; `rusqlite::Connection` is `Send` but not
/// `Sync`, so it is guarded by a mutex — and shared so `:memory:`
/// databases persist across operations.
#[links_to("REQ-038", component = "ARCH-AUDIT-SQLITE")]
#[links_to("REQ-039", component = "ARCH-AUDIT-SQLITE")]
#[links_to("REQ-041", component = "ARCH-AUDIT-SQLITE")]
pub struct SqliteAuditStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqliteAuditStore {
    /// Open (or create) the store and ensure the schema exists.
    ///
    /// WAL mode + `synchronous=NORMAL` (the same edge-profile durability
    /// trade-off as `hydra-catalog`): durable with far cheaper appends —
    /// the difference between clearing and missing the flush budget
    /// (P-AUDIT-FLUSH-LATENCY).
    pub fn open(path: impl Into<String>) -> Result<Self, AuditError> {
        let conn = rusqlite::Connection::open(path.into())
            .map_err(|e| AuditError::Io(e.to_string()))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| AuditError::Io(e.to_string()))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| AuditError::Io(e.to_string()))?;
        conn.execute_batch(SCHEMA)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl AuditBackend for SqliteAuditStore {
    async fn head(&self, domain: AuditDomain) -> Result<Option<AuditRecord>, AuditError> {
        let conn = self.conn.lock().await;
        let result = conn.query_row(
            "SELECT domain, generation, seq, actor, action, resource, detail, result, ts_ms, prev_hash, hash
             FROM audit_records WHERE domain = ?1
             ORDER BY generation DESC, seq DESC LIMIT 1",
            [domain.as_str()],
            record_from_row,
        );
        Ok(match result {
            Ok(record) => Some(record),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(AuditError::Io(e.to_string())),
        })
    }

    async fn append(&self, record: AuditRecord) -> Result<(), AuditError> {
        let conn = self.conn.lock().await;
        conn.execute(
            "INSERT INTO audit_records
                (domain, generation, seq, actor, action, resource, detail, result, ts_ms, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                record.domain.as_str(),
                record.generation,
                record.seq,
                record.actor,
                record.action,
                record.resource,
                record.detail,
                record.result,
                record.ts_ms as i64,
                record.prev_hash,
                record.hash,
            ],
        )
        .map_err(|e| AuditError::Io(e.to_string()))?;
        tracing::debug!(
            domain = record.domain.as_str(),
            seq = record.seq,
            "audit record appended"
        );
        Ok(())
    }

    async fn query(&self, filters: &AuditFilters) -> Result<Vec<AuditRecord>, AuditError> {
        let conn = self.conn.lock().await;

        let mut conditions: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql + Send>> = Vec::new();
        if let Some(domain) = filters.domain {
            conditions.push("domain = ?".to_string());
            params.push(Box::new(domain.as_str().to_string()));
        }
        if let Some(actor) = &filters.actor {
            conditions.push("actor = ?".to_string());
            params.push(Box::new(actor.clone()));
        }
        if let Some(action) = &filters.action {
            conditions.push("action = ?".to_string());
            params.push(Box::new(action.clone()));
        }
        if let Some(prefix) = &filters.resource_prefix {
            conditions.push("resource LIKE ?".to_string());
            params.push(Box::new(format!("{prefix}%")));
        }
        if let Some(since) = filters.since_ms {
            conditions.push("ts_ms >= ?".to_string());
            params.push(Box::new(since as i64));
        }
        if let Some(until) = filters.until_ms {
            conditions.push("ts_ms <= ?".to_string());
            params.push(Box::new(until as i64));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" AND "))
        };
        let mut query = format!(
            "SELECT domain, generation, seq, actor, action, resource, detail, result, ts_ms, prev_hash, hash
             FROM audit_records{where_clause}
             ORDER BY domain ASC, generation ASC, seq ASC"
        );
        if let Some(limit) = filters.limit {
            query.push_str(&format!(" LIMIT {limit}"));
        }

        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params.into_iter()), record_from_row)
            .map_err(|e| AuditError::Io(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(rows)
    }

    async fn verify(&self) -> Result<(), AuditError> {
        let records = self.query(&AuditFilters::default()).await?;
        verify_records(&records)
    }

    async fn rotate(&self, retention: u64) -> Result<u64, AuditError> {
        let conn = self.conn.lock().await;
        let mut rotated = 0u64;
        for domain in ["control", "data"] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM audit_records WHERE domain = ?1",
                    [domain],
                    |row| row.get(0),
                )
                .map_err(|e| AuditError::Io(e.to_string()))?;
            let retention_i = i64::try_from(retention).unwrap_or(i64::MAX);
            if count > retention_i {
                let excess = count - retention_i;
                // The oldest records in the domain (lowest generation, then
                // seq) leave the active log (REQ-041).
                let mut stmt = conn
                    .prepare(
                        "SELECT id FROM audit_records WHERE domain = ?1
                         ORDER BY generation ASC, seq ASC LIMIT ?2",
                    )
                    .map_err(|e| AuditError::Io(e.to_string()))?;
                let collected = stmt
                    .query_map(rusqlite::params![domain, excess], |row| row.get(0))
                    .map_err(|e| AuditError::Io(e.to_string()))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| AuditError::Io(e.to_string()))?;
                let ids: Vec<i64> = collected;
                for id in &ids {
                    conn.execute("DELETE FROM audit_records WHERE id = ?1", [id])
                        .map_err(|e| AuditError::Io(e.to_string()))?;
                }
                rotated += u64::try_from(excess).unwrap_or(0);
                tracing::info!(domain, excess, "audit records rotated out of the active log");
            }
        }
        Ok(rotated)
    }

    async fn len(&self) -> Result<u64, AuditError> {
        let conn = self.conn.lock().await;
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_records", [], |row| row.get(0))
            .map_err(|e| AuditError::Io(e.to_string()))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

/// PostgreSQL audit store (ARCH-AUDIT-POSTGRES): the multi-node /
/// production persistence target (REQ-038).
///
/// A stub: the boundary is real (config selects it, the engine talks only
/// to the trait), the implementation is not wired yet.
#[links_to("REQ-038", component = "ARCH-AUDIT-POSTGRES")]
pub struct PostgresAuditStore {
    /// Kept for the (yet unimplemented) pool configuration.
    #[allow(dead_code)]
    connection_url: String,
}

impl PostgresAuditStore {
    pub fn new(connection_url: impl Into<String>) -> Self {
        Self {
            connection_url: connection_url.into(),
        }
    }
}

#[async_trait]
impl AuditBackend for PostgresAuditStore {
    async fn head(&self, _domain: AuditDomain) -> Result<Option<AuditRecord>, AuditError> {
        Err(AuditError::Io("not implemented".into()))
    }

    async fn append(&self, _record: AuditRecord) -> Result<(), AuditError> {
        Err(AuditError::Io("not implemented".into()))
    }

    async fn query(&self, _filters: &AuditFilters) -> Result<Vec<AuditRecord>, AuditError> {
        Err(AuditError::Io("not implemented".into()))
    }

    async fn verify(&self) -> Result<(), AuditError> {
        Err(AuditError::Io("not implemented".into()))
    }

    async fn rotate(&self, _retention: u64) -> Result<u64, AuditError> {
        Err(AuditError::Io("not implemented".into()))
    }

    async fn len(&self) -> Result<u64, AuditError> {
        Err(AuditError::Io("not implemented".into()))
    }
}
