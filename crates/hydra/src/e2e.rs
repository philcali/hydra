//! End-to-end CONOPS tests for the Hydra system.
//!
//! These live in the lib (not `tests/`) so they are part of the test target
//! the MBSE checker registers, and they exercise the **whole stack** —
//! discovery → stream → provisioning → catalog → telemetry → fan-out →
//! fleet flows → degradation → audit — the way the CONOPS describe it.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hydra_audit::AuditDomain;
use hydra_catalog::{Device, DeviceFilters};
use hydra_discovery::{DiscoveredDevice, DiscoveryConfig, MdnsSource};
use hydra_drivers::{
    DegradationState, Driver, DriverOp, FallbackAction, ModbusDriver, SensorDriver, SimDevice,
};
use hydra_telemetry::{collector::TELEM_INTERVAL_S, DeliveryTarget, FanOutService, MetricEvent, MetricKind, MetricStream};

use crate::flow::{FleetFlowOp, FlowResult};
use crate::system::{HydraConfig, HydraSystem};

use mbse::links_to;
use mbse::mbse_exempt;

static TEST_NO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[mbse_exempt("test helper — not a model node")]
fn fresh_paths() -> (String, String) {
    let test_no = TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let db = std::env::temp_dir()
        .join(format!("hydra-e2e-root-{}-{}.db", std::process::id(), test_no));
    let audit = std::env::temp_dir()
        .join(format!("hydra-e2e-audit-{}-{}.db", std::process::id(), test_no));
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&audit);
    (db.to_string_lossy().to_string(), audit.to_string_lossy().to_string())
}

#[mbse_exempt("test helper — not a model node")]
async fn system() -> HydraSystem {
    system_with_seed(|_| Ok(())).await
}

/// Bootstrap over a catalog that is pre-seeded in a **single transaction**.
///
/// `create_device` commits (and fsyncs) per call; at 1000 devices that is
/// 1000 fsyncs just to lay down the fixture. A single-transaction seed
/// costs one commit and is the standard way to keep scale fixtures cheap.
/// (The file — not `:memory:` — must be used, because `bootstrap` opens the
/// catalog path from several independent connections.)
#[mbse_exempt("test helper — not a model node")]
async fn system_with_seed(
    seed: impl FnOnce(&mut rusqlite::Connection) -> rusqlite::Result<()>,
) -> HydraSystem {
    let (db_path, audit_db_path) = fresh_paths();
    hydra_catalog::SqliteStore::new(db_path.clone())
        .init()
        .await
        .unwrap();
    {
        let mut conn = rusqlite::Connection::open(&db_path).expect("open seed db");
        seed(&mut conn).expect("seed the catalog");
    }
    let config = HydraConfig {
        db_path,
        audit_db_path,
        ..Default::default()
    };
    HydraSystem::bootstrap(config).await.unwrap()
}

/// A registered delivery target (an external subscriber, CONOPS-006) fed by
/// the stream→fan-out bridge (REQ-030).
#[mbse_exempt("test helper — not a model node")]
struct Observer {
    received: Arc<Mutex<Vec<MetricEvent>>>,
    handle: tokio::task::JoinHandle<()>,
}

#[mbse_exempt("test helper — not a model node")]
impl Observer {
    fn start(stream: &MetricStream) -> Self {
        let received = Arc::new(Mutex::new(Vec::new()));
        let to_cb = received.clone();
        let mut fanout = FanOutService::new();
        fanout.register(DeliveryTarget::new(
            "e2e-observer",
            Vec::new(), // empty scope = all devices
            move |e| {
                to_cb.lock().unwrap().push(e);
            },
        ));
        let stream = stream.clone();
        let handle = tokio::spawn(async move {
            fanout.pump(&stream).await
        });
        Self { received, handle }
    }
}

#[mbse_exempt("test helper — not a model node")]
async fn wait_for(received: &Mutex<Vec<MetricEvent>>, n: usize, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if received.lock().unwrap().len() >= n {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    received.lock().unwrap().len() >= n
}

#[mbse_exempt("test helper — not a model node")]
fn found(address: &str, device_type: &str, vendor: &str) -> DiscoveredDevice {
    DiscoveredDevice {
        address: address.into(),
        device_type: device_type.into(),
        vendor: vendor.into(),
        capabilities: vec!["config".into()],
    }
}

/// The golden path across the CONOPS, end to end:
///
/// - **CONOPS-007** — discovery (filtered by a managed config, REQ-032)
///   scans the edge network (REQ-008), emits `DeviceDiscovered` events on
///   the stream (REQ-033), and the provisioner provisions each — registered
///   in the catalog with its driver bound and assigned to a fleet by the
///   data-driven policy (REQ-034/035) — with the action audited (REQ-036).
/// - **CONOPS-002** — an on-boarded device is registered, matched to a
///   driver, wired for per-device telemetry (REQ-026), and audited.
/// - **CONOPS-006** — telemetry points (REQ-015) reach the registered
///   delivery target through fan-out (REQ-027/030).
/// - **CONOPS-003** — a fleet flow writes config (REQ-010) to every
///   device whose driver has the fidelity (REQ-018); the rest are reported,
///   and every attempt is audited (REQ-036/037).
/// - **CONOPS-004** — repeated driver failure trips degradation with the
///   graceful fallback (REQ-012), emits a stream event (REQ-015), and is
///   audited in the data domain (REQ-037).
///
/// At the end the hash-chained audit log verifies.
#[links_to("REQ-008")]
#[links_to("REQ-010")]
#[links_to("REQ-012")]
#[links_to("REQ-015")]
#[links_to("REQ-018")]
#[links_to("REQ-026")]
#[links_to("REQ-027")]
#[links_to("REQ-030")]
#[links_to("REQ-032")]
#[links_to("REQ-033")]
#[links_to("REQ-034")]
#[links_to("REQ-035")]
#[links_to("REQ-036")]
#[links_to("REQ-037")]
#[tokio::test]
async fn test_e2e_golden_path() {
    let mut sys = system().await;
    let obs = Observer::start(&sys.stream);

    // The bridge subscribes on its first poll — wait for that so every
    // later publish is guaranteed to be delivered (the provisioner is
    // subscriber #1 from bootstrap).
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while sys.stream.subscriber_count() < 2 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        sys.stream.subscriber_count() >= 2,
        "the fan-out bridge never subscribed"
    );

    // Prove the stream → fan-out → observer chain is live before any CONOPS
    // phase publishes real events (REQ-027/030).
    sys.stream
        .publish(MetricKind::DeviceRecovered, "e2e-handshake")
        .unwrap();
    assert!(
        wait_for(&obs.received, 1, Duration::from_secs(2)).await,
        "observer did not receive the handshake event"
    );

    // ── CONOPS-007: discovery → provisioning ────────────────────────────
    // REQ-032: the control plane manages the discovery config; discovery
    // consumes it to filter what it matches.
    sys.discovery = sys.discovery.with_config(DiscoveryConfig {
        id: "e2e-edge-acme-plc".into(),
        name: "edge acme PLCs".into(),
        interval_ms: hydra_discovery::engine::DISCOVERY_INTERVAL_S * 1000,
        vendor: Some("acme".into()),
        device_type: Some("plc".into()),
    });
    // The edge network: two in-scope acme PLCs, one out-of-scope siemens.
    sys.discovery.add_source(MdnsSource::new(vec![
        found("10.0.0.11", "plc", "acme"),
        found("10.0.0.12", "plc", "acme"),
        found("10.0.0.13", "plc", "siemens"),
    ]));

    let provisioned = sys.run_discovery_cycle().await;
    assert_eq!(provisioned, 2, "only the in-scope acme PLCs are provisioned");
    assert_eq!(sys.discovery.seen().len(), 3, "the siemens device was seen, then filtered");

    // REQ-034: the provisioner registered the devices in the shared catalog.
    let all = sys.catalog.list_devices(Default::default()).await.unwrap();
    let ids: Vec<_> = all.iter().map(|d| d.id.as_str()).collect();
    assert!(ids.contains(&"10.0.0.11") && ids.contains(&"10.0.0.12"));
    assert!(!ids.contains(&"10.0.0.13"), "filtered device must not be provisioned");

    // REQ-035: fleet assignment is policy-driven — the bootstrap default fleet.
    let edge = sys
        .catalog
        .list_devices(DeviceFilters {
            fleet_id: Some("edge".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(edge.len(), 2, "the two provisioned acme PLCs are in the policy fleet");

    // CONOPS-002's "begin telemetry collection": provisioned devices are
    // wired for per-device telemetry (REQ-026).
    let bound = sys.telemetry.devices();
    assert!(bound.contains(&"10.0.0.11") && bound.contains(&"10.0.0.12"));

    // REQ-036: the provisioning actions are audited in the control domain.
    let recs = sys.audit.records().await.unwrap();
    let prov: Vec<_> = recs.iter().filter(|r| r.action == "provisioning:register").collect();
    assert_eq!(prov.len(), 2);
    assert!(prov.iter().all(|r| r.domain == AuditDomain::ControlPlane && r.result == "ok"));

    // REQ-033 + REQ-027: discovery events reached the registered target.
    let acme_discovered = || {
        obs.received
            .lock()
            .unwrap()
            .iter()
            .filter(|e| matches!(&e.kind, MetricKind::DeviceDiscovered { vendor, .. } if vendor == "acme"))
            .count()
    };
    assert!(
        wait_for(&obs.received, 1 + 2, Duration::from_secs(2)).await,
        "observer missed the discovery events; got {:?}",
        obs.received.lock().unwrap().iter().map(|e| &e.kind).collect::<Vec<_>>()
    );
    assert_eq!(acme_discovered(), 2);

    // ── CONOPS-002: onboarding (register, match driver, audit) ──────────
    let siemens_id = sys.onboard(found("10.1.1.21", "plc", "siemens")).await.unwrap();
    let sensor_id = sys
        .onboard(found("10.1.1.22", "sensor", "senselab"))
        .await
        .unwrap();
    assert_ne!(siemens_id, sensor_id, "distinct onboards mint distinct devices");
    let siemens_dev = sys.catalog.get_device(&siemens_id).await.unwrap().unwrap();
    assert_eq!(
        siemens_dev.metadata["address"],
        "10.1.1.21",
        "the on-boarded device carries its discovered address"
    );
    sys.fleets.add_to_fleet(&siemens_id, "edge").await.unwrap();
    sys.fleets.add_to_fleet(&sensor_id, "edge").await.unwrap();

    // The fleet now spans all three fidelity tiers (REQ-018).
    let edge = sys
        .catalog
        .list_devices(DeviceFilters {
            fleet_id: Some("edge".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(edge.len(), 4);

    // ── CONOPS-006: telemetry reaches the registered delivery target ────
    // A seeded sensor bound through the per-device pull (REQ-026).
    let sim = Arc::new(SimDevice::new(0));
    sim.raw.lock().unwrap().insert("temp_c".into(), serde_json::json!(21.5));
    sys.bind_telemetry("e2e-sensor-1", Arc::new(SensorDriver::new(sim)) as Arc<dyn Driver>);

    let points = sys.collect_telemetry().await;
    assert!(
        points.iter().any(|p| p.device == "e2e-sensor-1" && p.metric == "temp_c" && p.value == 21.5),
        "expected the seeded sensor's point in {:?}",
        points
    );
    // REQ-015/027: the point crossed the stream to the delivery target.
    assert!(
        wait_for(&obs.received, 1 + 2 + 1, Duration::from_secs(2)).await,
        "observer missed the telemetry point"
    );
    assert!(obs
        .received
        .lock()
        .unwrap()
        .iter()
        .any(|e| matches!(&e.kind, MetricKind::Point(p) if p.device == "e2e-sensor-1" && p.metric == "temp_c")));

    // ── CONOPS-003: fleet flows with the fidelity gate ──────────────────
    // Set the fleet's output: every config-fidelity device applies it…
    let cfg = FleetFlowOp::SetConfig {
        values: BTreeMap::from([("output".to_string(), serde_json::json!(42))]),
    };
    let set_outcomes = sys.dispatch_fleet_flow("edge", &cfg).await;
    assert_eq!(set_outcomes.len(), 4, "one outcome per fleet device");
    let set_result = |id: &str| set_outcomes.iter().find(|o| o.device_id == id).unwrap().result.clone();
    assert_eq!(set_result("10.0.0.11"), FlowResult::Applied); // acme, full fidelity
    assert_eq!(set_result("10.0.0.12"), FlowResult::Applied);
    assert_eq!(set_result(&siemens_id), FlowResult::Applied); // siemens, config fidelity
    assert!(
        matches!(set_result(&sensor_id), FlowResult::RejectedFidelity { required: DriverOp::ConfigWrite }),
        "the telemetry-only sensor is rejected by fidelity, not skipped"
    );

    // …and a command: only the full-fidelity drivers apply it.
    let reboot = FleetFlowOp::Command { name: "reboot".into() };
    let cmd_outcomes = sys.dispatch_fleet_flow("edge", &reboot).await;
    let cmd_result = |id: &str| cmd_outcomes.iter().find(|o| o.device_id == id).unwrap().result.clone();
    assert_eq!(cmd_result("10.0.0.11"), FlowResult::Applied);
    assert_eq!(cmd_result("10.0.0.12"), FlowResult::Applied);
    assert!(matches!(cmd_result(&siemens_id), FlowResult::RejectedFidelity { required: DriverOp::Command }));
    assert!(matches!(cmd_result(&sensor_id), FlowResult::RejectedFidelity { required: DriverOp::Command }));

    // REQ-036/037: every flow attempt is audited in the data domain,
    // success and fidelity rejection alike.
    let recs = sys.audit.records().await.unwrap();
    let set_audits: Vec<_> = recs.iter().filter(|r| r.action == "fleet:set-config").collect();
    assert_eq!(set_audits.len(), 4);
    assert_eq!(set_audits.iter().filter(|r| r.result == "ok").count(), 3);
    assert_eq!(set_audits.iter().filter(|r| r.result != "ok").count(), 1);
    assert!(set_audits.iter().all(|r| r.domain == AuditDomain::DataPlane && r.actor == "operator"));
    let cmd_audits: Vec<_> = recs.iter().filter(|r| r.action == "fleet:command").collect();
    assert_eq!(cmd_audits.len(), 4);
    assert_eq!(cmd_audits.iter().filter(|r| r.result == "ok").count(), 2);
    assert_eq!(cmd_audits.iter().filter(|r| r.result != "ok").count(), 2);

    // ── CONOPS-004: degradation → event → data-domain audit ─────────────
    let victim = "10.0.0.11";
    assert!(!sys.on_driver_failure(victim).await, "first failure records only");
    assert!(sys.on_driver_failure(victim).await, "second failure trips degradation");
    assert_eq!(sys.degradation.state(victim), DegradationState::Degraded);
    assert_eq!(
        sys.degradation.fallback(victim),
        Some(FallbackAction::ServeCachedConfig),
        "the graceful fallback is active"
    );
    assert!(
        wait_for(&obs.received, 1 + 2 + 1 + 1, Duration::from_secs(2)).await,
        "observer missed the DeviceUnhealthy event"
    );
    assert!(obs
        .received
        .lock()
        .unwrap()
        .iter()
        .any(|e| e.device == victim && matches!(e.kind, MetricKind::DeviceUnhealthy { .. })));

    // REQ-037: the degradation is in the data-domain audit log.
    let recs = sys.audit.records().await.unwrap();
    assert!(recs
        .iter()
        .any(|r| r.action == "degradation:activate" && r.resource == victim && r.domain == AuditDomain::DataPlane));

    // The hash-chained audit log verifies over the whole run…
    sys.audit.verify().await.unwrap();
    // …and the system's health snapshot is consistent with it.
    let status = sys.status().await.unwrap();
    assert_eq!(status.devices_in_catalog, 4);
    assert_eq!(status.drivers_registered, 3);
    assert_eq!(status.degraded_devices, 1);
    let _ = obs.handle;
}

/// Verifies REQ-014 (CONOPS-005): the system scales to
/// P-SCALE-DEVICE-COUNT = 1000 devices — the catalog holds exactly 1000
/// (and rejects the 1001st at the bound), and a full per-device telemetry
/// sweep of all 1000 completes inside one telemetry interval
/// (P-TELEM-INTERVAL = 30s).
#[links_to("REQ-014")]
#[tokio::test]
async fn test_e2e_scale_to_a_thousand_devices() {
    let n = hydra_catalog::MAX_DEVICES_PER_NODE;
    assert_eq!(n, 1000, "the code bound must match P-SCALE-DEVICE-COUNT");

    // Seed 1000 devices across two vendor/type pairs (one transaction, one
    // commit — see `system_with_seed`).
    let mut sys = system_with_seed(|conn| {
        let tx = conn.transaction()?;
        for i in 0..n {
            let (device_type, vendor) = if i % 2 == 0 {
                ("plc", "acme")
            } else {
                ("sensor", "senselab")
            };
            tx.execute(
                "INSERT INTO devices (id, name, device_type, vendor, status, metadata)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    format!("dev-{i}"),
                    format!("device {i}"),
                    device_type,
                    vendor,
                    "active",
                    r#"{"pool":"e2e-scale"}"#,
                ],
            )?;
        }
        tx.commit()
    })
    .await;
    assert_eq!(sys.status().await.unwrap().devices_in_catalog, n);

    // The 1001st is rejected at the capacity bound.
    let overflow = sys
        .catalog
        .create_device(Device {
            id: "dev-overflow".into(),
            name: "overflow".into(),
            device_type: "plc".into(),
            vendor: "acme".into(),
            status: "active".into(),
            fleet_ids: vec!["edge".into()],
            metadata: serde_json::json!({}),
        })
        .await;
    let overflow_err = overflow.expect_err("the 1001st device must be rejected");
    assert!(
        overflow_err.to_string().to_lowercase().contains("capacity"),
        "expected the capacity bound, got: {overflow_err}"
    );

    // Bind a seeded driver per device and sweep all of them (REQ-026 at
    // scale), timing the sweep against the telemetry interval budget.
    for i in 0..n {
        let sim = Arc::new(SimDevice::new(0));
        sim.raw
            .lock()
            .unwrap()
            .insert("load".into(), serde_json::json!(50.0 + i as f64 / 1000.0));
        let driver: Arc<dyn Driver> = if i % 2 == 0 {
            Arc::new(ModbusDriver::new(sim)) as Arc<dyn Driver>
        } else {
            Arc::new(SensorDriver::new(sim)) as Arc<dyn Driver>
        };
        sys.bind_telemetry(format!("dev-{i}"), driver);
    }

    let start = std::time::Instant::now();
    let points = sys.collect_telemetry().await;
    let elapsed = start.elapsed();

    let devices: std::collections::HashSet<&str> =
        points.iter().map(|p| p.device.as_str()).collect();
    assert_eq!(devices.len(), n, "every one of the 1000 devices must contribute telemetry");
    assert!(
        points.iter().all(|p| p.metric == "load" && (40.0..=60.0).contains(&p.value)),
        "scale-sweep points must be the seeded 'load' metric"
    );
    assert!(
        elapsed < Duration::from_secs(TELEM_INTERVAL_S),
        "a full 1000-device sweep must fit in one telemetry interval (P-TELEM-INTERVAL = {TELEM_INTERVAL_S}s); took {elapsed:?}"
    );
}
