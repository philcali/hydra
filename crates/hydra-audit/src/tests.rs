//! Tests for hydra-audit — verifies requirements via `#[links_to]`.

use crate::log::{verify_records, AuditError, AuditLog};

use mbse::links_to;

mbse_graph::collect_test!();

/// Verifies REQ-016: actions are recorded and the hash chain verifies.
#[links_to("REQ-016")]
#[test]
fn test_append_builds_chain() {
    let mut log = AuditLog::new();
    log.append("alice", "catalog:create", "catalog/devices/dev-1", "created device");
    log.append("alice", "fleet:join", "fleet/prod", "dev-1 → prod");
    log.append("bob", "device:reboot", "catalog/devices/dev-1", "operator request");

    assert_eq!(log.len(), 3);
    log.verify().unwrap();

    // Each record chains to the previous one.
    let records = log.records().to_vec();
    assert_eq!(records[0].prev_hash, "0".repeat(64));
    assert_eq!(records[1].prev_hash, records[0].hash);
    assert_eq!(records[2].prev_hash, records[1].hash);
}

/// Verifies REQ-016: tampering with any record breaks the chain.
#[links_to("REQ-016")]
#[test]
fn test_tamper_detected() {
    let mut log = AuditLog::new();
    log.append("alice", "catalog:create", "catalog/devices/dev-1", "created device");
    log.append("alice", "catalog:delete", "catalog/devices/dev-1", "deleted device");

    let mut records = log.records().to_vec();
    records[0].action = "catalog:review".into(); // forged action
    match verify_records(&records) {
        Err(AuditError::ChainBroken { seq: 0, .. }) => {}
        other => panic!("expected chain break at record 0, got {other:?}"),
    }

    // Forging a *link* (record 1's prev_hash) is caught too.
    let mut records = log.records().to_vec();
    records[1].prev_hash = "f".repeat(64);
    match verify_records(&records) {
        Err(AuditError::ChainBroken { seq: 1, .. }) => {}
        other => panic!("expected chain break at record 1, got {other:?}"),
    }
}

/// Verifies REQ-016: the log flushes to a durable store and the records
/// survive a round trip.
#[links_to("REQ-016")]
#[test]
fn test_flush_roundtrip() {
    let mut log = AuditLog::new();
    log.append("alice", "catalog:create", "catalog/devices/dev-1", "created device");
    log.append("alice", "device:reboot", "catalog/devices/dev-1", "reboot");

    let path = std::env::temp_dir().join(format!("hydra-audit-test-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    log.flush(&path).unwrap();

    let content = std::fs::read_to_string(&path).unwrap();
    let round_tripped: Vec<crate::log::AuditRecord> = content
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    assert_eq!(round_tripped.len(), 2);
    assert_eq!(round_tripped[0].action, "catalog:create");
    let _ = std::fs::remove_file(&path);
}

/// Verifies REQ-016 (P-AUDIT-FLUSH-LATENCY): a flush stays within the
/// budget.
#[links_to("REQ-016")]
#[test]
fn test_flush_within_budget() {
    let mut log = AuditLog::new();
    for i in 0..50 {
        log.append("system", "catalog:create", &format!("catalog/devices/dev-{i}"), "batch");
    }
    let path = std::env::temp_dir().join(format!("hydra-audit-budget-{}.jsonl", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let elapsed = log.flush(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert!(
        elapsed.as_millis() <= u128::from(crate::log::AUDIT_FLUSH_BUDGET_MS),
        "flush took {}ms, budget {}ms",
        elapsed.as_millis(),
        crate::log::AUDIT_FLUSH_BUDGET_MS
    );
}
