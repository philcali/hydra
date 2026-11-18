//! Tests for hydra-audit — verifies REQ-016 and REQ-036..REQ-041 via
//! `#[links_to]`.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::backend::SqliteAuditStore;
use crate::delivery::{
    CallbackAuditTransport, HttpAuditTransport, RecordingAuditHttp, AuditTransport,
};
use crate::engine::AuditEngine;
use crate::record::{
    verify_records, now_ms, AuditDomain, AuditError, AuditFilters,
};

use mbse::links_to;

mbse_graph::collect_test!();

static TEST_NO: AtomicU64 = AtomicU64::new(0);

#[mbse::mbse_exempt("test helper — not a model node")]
fn next_test_no() -> u64 {
    TEST_NO.fetch_add(1, Ordering::SeqCst)
}

#[mbse::mbse_exempt("test helper — not a model node")]
fn temp_path(ext: &str) -> String {
    std::env::temp_dir()
        .join(format!("hydra-audit-{}-{}.{}", std::process::id(), next_test_no(), ext))
        .to_string_lossy()
        .to_string()
}

#[mbse::mbse_exempt("test helper — not a model node")]
fn engine(retention: u64) -> AuditEngine {
    let path = temp_path("db");
    let _ = std::fs::remove_file(&path);
    let store = SqliteAuditStore::open(&path).unwrap();
    AuditEngine::new(Box::new(store), None, retention)
}

// ── REQ-016: the immutable, hash-chained log ────────────────────────────

/// Verifies REQ-016: actions are recorded and the hash chain verifies.
#[links_to("REQ-016")]
#[tokio::test]
async fn test_append_builds_chain() {
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created device", "ok")
        .await
        .unwrap();
    audit
        .append(AuditDomain::ControlPlane, "alice", "fleet:join", "fleet/prod", "dev-1 → prod", "ok")
        .await
        .unwrap();
    audit
        .append(AuditDomain::DataPlane, "bob", "device:reboot", "devices/dev-1", "operator request", "ok")
        .await
        .unwrap();

    let records = audit.records().await.unwrap();
    assert_eq!(records.len(), 3);
    audit.verify().await.unwrap();

    // Each control-plane record chains to the previous one.
    let control: Vec<_> = records
        .iter()
        .filter(|r| r.domain == AuditDomain::ControlPlane)
        .cloned()
        .collect();
    assert_eq!(control[0].prev_hash, "0".repeat(64));
    assert_eq!(control[1].prev_hash, control[0].hash);
}

/// Verifies REQ-016: tampering with any record is detected.
#[links_to("REQ-016")]
#[tokio::test]
async fn test_tamper_detected() {
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created device", "ok")
        .await
        .unwrap();
    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:delete", "catalog/devices/dev-1", "deleted device", "ok")
        .await
        .unwrap();

    let mut records = audit.records().await.unwrap();
    records[0].action = "catalog:review".into(); // forged action
    match verify_records(&records) {
        Err(AuditError::ChainBroken { seq: 0, .. }) => {}
        other => panic!("expected chain break at record 0, got {other:?}"),
    }

    // Forging a *link* (record 1's prev_hash) is caught too.
    let mut records = audit.records().await.unwrap();
    records[1].prev_hash = "f".repeat(64);
    match verify_records(&records) {
        Err(AuditError::ChainBroken { seq: 1, .. }) => {}
        other => panic!("expected chain break at record 1, got {other:?}"),
    }
}

// ── REQ-036: control-plane audit ────────────────────────────────────────

/// Verifies REQ-036: a control-plane action is recorded in the control
/// domain with actor, action, resource, and the outcome.
#[links_to("REQ-036")]
#[tokio::test]
async fn test_control_plane_action_audited() {
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    let record = audit
        .append(
            AuditDomain::ControlPlane,
            "alice",
            "catalog:create",
            "catalog/devices/dev-1",
            "via control plane",
            "ok",
        )
        .await
        .unwrap();
    assert_eq!(record.domain, AuditDomain::ControlPlane);
    assert_eq!(record.actor, "alice");
    assert_eq!(record.action, "catalog:create");
    assert_eq!(record.result, "ok");

    let records = audit
        .query(&AuditFilters {
            domain: Some(AuditDomain::ControlPlane),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    audit.verify().await.unwrap();
}

// ── REQ-037: data-plane audit ───────────────────────────────────────────

/// Verifies REQ-037: a data-plane operation on a specific device is
/// recorded in the data domain, including failed operations.
#[links_to("REQ-037")]
#[tokio::test]
async fn test_data_plane_operation_audited() {
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    audit
        .append(AuditDomain::DataPlane, "alice", "device:set-config", "devices/dev-2/config", "via data plane", "ok")
        .await
        .unwrap();
    // A failed operation is audited with its failure result — the log is a
    // complete account of what was attempted and what happened.
    let failed = audit
        .append(AuditDomain::DataPlane, "bob", "device:reboot", "devices/dev-3", "via data plane", "error: driver timeout")
        .await
        .unwrap();
    assert_eq!(failed.domain, AuditDomain::DataPlane);
    assert!(failed.result.starts_with("error:"));

    let data = audit
        .query(&AuditFilters {
            domain: Some(AuditDomain::DataPlane),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data[0].actor, "alice");
    assert_eq!(data[1].resource, "devices/dev-3");
    audit.verify().await.unwrap();
}

// ── REQ-038: pluggable, configurable persistence ────────────────────────

/// Verifies REQ-038: records are durable — they survive a close/reopen of
/// the store, and the chain continues from where it left off.
#[links_to("REQ-038")]
#[tokio::test]
async fn test_records_survive_reopen() {
    let path = temp_path("db");
    let _ = std::fs::remove_file(&path);

    // First session: append two control-plane records.
    let head_hash = {
        let store = SqliteAuditStore::open(&path).unwrap();
        let audit = AuditEngine::new(Box::new(store), None, 100);
        audit
            .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created", "ok")
            .await
            .unwrap();
        let record = audit
            .append(AuditDomain::ControlPlane, "alice", "catalog:read", "catalog/devices/dev-1", "reviewed", "ok")
            .await
            .unwrap();
        audit.verify().await.unwrap();
        record.hash
    };

    // Second session: reopen the same store — the records are still there…
    let store = SqliteAuditStore::open(&path).unwrap();
    let audit = AuditEngine::new(Box::new(store), None, 100);
    let records = audit.records().await.unwrap();
    assert_eq!(records.len(), 2);
    audit.verify().await.unwrap();

    // …and the chain continues from the previous head.
    let continued = audit
        .append(AuditDomain::ControlPlane, "bob", "catalog:update", "catalog/devices/dev-1", "updated", "ok")
        .await
        .unwrap();
    assert_eq!(continued.prev_hash, head_hash);
    audit.verify().await.unwrap();
    let _ = std::fs::remove_file(&path);
}

/// Verifies REQ-038 (P-AUDIT-FLUSH-LATENCY): a batch of writes stays
/// within the flush budget.
#[links_to("REQ-038")]
#[tokio::test]
async fn test_write_batch_within_flush_budget() {
    use crate::backend::AUDIT_FLUSH_BUDGET_MS;
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    let started = std::time::Instant::now();
    for i in 0..50 {
        audit
            .append(
                AuditDomain::ControlPlane,
                "system",
                "catalog:create",
                &format!("catalog/devices/dev-{i}"),
                "batch",
                "ok",
            )
            .await
            .unwrap();
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed.as_millis() <= u128::from(AUDIT_FLUSH_BUDGET_MS),
        "50 audit writes took {}ms, budget {}ms",
        elapsed.as_millis(),
        AUDIT_FLUSH_BUDGET_MS
    );
}

/// Verifies REQ-038: the persistence backend is a config selection —
/// Postgres is a first-class option at the boundary (stub, not wired).
#[links_to("REQ-038")]
#[tokio::test]
async fn test_backend_selection_is_a_config_choice() {
    use crate::engine::AuditBackendKind;
    use crate::engine::AuditConfig;

    // SQLite is the default config (give it a fresh path).
    let mut default_config = AuditConfig::default();
    if let AuditBackendKind::Sqlite { path } = &mut default_config.backend {
        *path = temp_path("db");
    }
    let default_engine = default_config.engine(None).unwrap();
    default_engine
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created", "ok")
        .await
        .unwrap();
    assert_eq!(default_engine.len().await.unwrap(), 1);

    // Postgres is selectable at the boundary — the call surfaces as a
    // precise "not implemented" from the backend, not a silent fallback.
    let postgres_config = AuditConfig {
        backend: AuditBackendKind::Postgres {
            url: "postgres://hydra:secret@localhost/hydra".into(),
        },
        ..Default::default()
    };
    let engine = postgres_config.engine(None).unwrap();
    match engine
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "x", "y", "ok")
        .await
    {
        Err(AuditError::Io(msg)) => assert!(msg.contains("not implemented")),
        other => panic!("expected not-implemented error, got {other:?}"),
    }
}

// ── REQ-039: queryable audit log ────────────────────────────────────────

/// Verifies REQ-039: records are queryable by domain, actor, action,
/// resource prefix, and time range.
#[links_to("REQ-039")]
#[tokio::test]
async fn test_query_by_actor_action_time() {
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created", "ok")
        .await
        .unwrap();
    audit
        .append(AuditDomain::ControlPlane, "bob", "catalog:delete", "catalog/devices/dev-2", "deleted", "ok")
        .await
        .unwrap();
    audit
        .append(AuditDomain::DataPlane, "alice", "device:reboot", "devices/dev-1", "rebooted", "ok")
        .await
        .unwrap();

    // By actor.
    let alice = audit
        .query(&AuditFilters { actor: Some("alice".into()), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(alice.len(), 2);

    // By action.
    let deletes = audit
        .query(&AuditFilters { action: Some("catalog:delete".into()), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(deletes.len(), 1);
    assert_eq!(deletes[0].actor, "bob");

    // By resource prefix.
    let dev1 = audit
        .query(&AuditFilters { resource_prefix: Some("catalog/devices/dev-1".into()), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(dev1.len(), 1);

    // By time range: everything is within [0, now+1s]; nothing is after.
    let now = now_ms();
    let recent = audit
        .query(&AuditFilters { since_ms: Some(0), until_ms: Some(now + 1000), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(recent.len(), 3);
    let future = audit
        .query(&AuditFilters { since_ms: Some(now + 1_000_000), ..Default::default() })
        .await
        .unwrap();
    assert!(future.is_empty());

    // With a limit.
    let limited = audit
        .query(&AuditFilters { limit: Some(2), ..Default::default() })
        .await
        .unwrap();
    assert_eq!(limited.len(), 2);
}

// ── REQ-040: delivery (push audits out) ─────────────────────────────────

/// Verifies REQ-040: with a callback target configured, every appended
/// record is pushed out.
#[links_to("REQ-040")]
#[tokio::test]
async fn test_callback_delivery_receives_records() {
    use std::sync::{Arc, Mutex};

    let pushed: Arc<Mutex<Vec<crate::record::AuditRecord>>> =
        Arc::new(Mutex::new(Vec::new()));
    let sink = pushed.clone();
    let transport = CallbackAuditTransport::new(move |record: crate::record::AuditRecord| {
        sink.lock().unwrap().push(record);
    });
    let audit = engine(AUDIT_RETENTION_DEFAULT);
    // Rebuild with the delivery target.
    let path = temp_path("db");
    let _ = std::fs::remove_file(&path);
    let store = SqliteAuditStore::open(&path).unwrap();
    let audit = AuditEngine::new(Box::new(store), Some(Box::new(transport)), 100);
    assert!(audit.delivery_configured());

    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created", "ok")
        .await
        .unwrap();
    audit
        .append(AuditDomain::DataPlane, "bob", "device:reboot", "devices/dev-1", "rebooted", "ok")
        .await
        .unwrap();

    let pushed = pushed.lock().unwrap();
    assert_eq!(pushed.len(), 2);
    assert_eq!(pushed[0].action, "catalog:create");
    assert_eq!(pushed[1].domain, AuditDomain::DataPlane);
    drop(pushed);
    let _ = std::fs::remove_file(&path);
}

/// Verifies REQ-040: with an HTTP target, records are serialized to JSON
/// and POSTed to the endpoint through the pluggable client.
#[links_to("REQ-040")]
#[tokio::test]
async fn test_http_delivery_posts_json() {
    let sink = std::sync::Arc::new(RecordingAuditHttp::new(200));
    let transport =
        HttpAuditTransport::new("https://siem.example/audit", sink.clone());
    let path = temp_path("db");
    let _ = std::fs::remove_file(&path);
    let store = SqliteAuditStore::open(&path).unwrap();
    let audit = AuditEngine::new(Box::new(store), Some(Box::new(transport)), 100);

    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created", "ok")
        .await
        .unwrap();

    let requests = sink.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].0, "https://siem.example/audit");
    assert!(requests[0].1.contains("catalog:create"));
    assert!(requests[0].1.contains("\"ControlPlane\""));
    drop(requests);
    let _ = std::fs::remove_file(&path);
}

/// Verifies REQ-040: a failing delivery endpoint is reported (the record
/// is persisted regardless — delivery is best-effort).
#[links_to("REQ-040")]
#[tokio::test]
async fn test_delivery_failure_reported() {
    let sink = RecordingAuditHttp::new(500);
    let transport = HttpAuditTransport::new("https://siem.example/audit", sink);
    let path = temp_path("db");
    let _ = std::fs::remove_file(&path);
    let store = SqliteAuditStore::open(&path).unwrap();
    let audit = AuditEngine::new(Box::new(store), Some(Box::new(transport)), 100);

    // The append succeeds (the record is persisted)…
    audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-1", "created", "ok")
        .await
        .unwrap();
    assert_eq!(audit.len().await.unwrap(), 1);
    // …but the transport itself reports the failed push.
    let record = audit.records().await.unwrap().pop().unwrap();
    let transport = HttpAuditTransport::new("https://siem.example/audit", RecordingAuditHttp::new(500));
    let err = transport.deliver(&record).unwrap_err();
    assert!(err.to_string().contains("500"));
    let _ = std::fs::remove_file(&path);
}

// ── REQ-041: retention ──────────────────────────────────────────────────

/// Verifies REQ-041: rotation enforces the bound — a domain's oldest
/// records leave the active log, the survivors stay a valid chain, and new
/// records continue that chain (from the surviving head, seq 7 → 8).
#[links_to("REQ-041")]
#[tokio::test]
async fn test_rotation_enforces_retention() {
    let audit = engine(5); // retention bound of 5 records
    for i in 0..8 {
        audit
            .append(
                AuditDomain::ControlPlane,
                "system",
                "catalog:create",
                &format!("catalog/devices/dev-{i}"),
                "batch",
                "ok",
            )
            .await
            .unwrap();
    }
    assert_eq!(audit.len().await.unwrap(), 8);

    let rotated = audit.rotate().await.unwrap();
    assert_eq!(rotated, 3);
    assert_eq!(audit.len().await.unwrap(), 5);

    // The surviving chain is still verifiable, and appends continue it.
    audit.verify().await.unwrap();
    let head = audit
        .append(AuditDomain::ControlPlane, "alice", "catalog:create", "catalog/devices/dev-new", "created", "ok")
        .await
        .unwrap();
    assert_eq!(head.seq, 8); // continues after the surviving head (seq 7)
    audit.verify().await.unwrap();
}

const AUDIT_RETENTION_DEFAULT: u64 = 1000;
