//! CONOPS flow tests for the Hydra system (ARCH-SYS-MGMT).

use crate::system::{HydraConfig, HydraSystem};

use std::sync::Arc;

use hydra_audit::AuditDomain;
use hydra_discovery::DiscoveredDevice;
use hydra_drivers::{DegradationState, Driver, FallbackAction, SensorDriver, SimDevice};
use hydra_telemetry::MetricKind;

use mbse::links_to;

mbse_graph::collect_test!();

static TEST_NO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[mbse::mbse_exempt("test helper — not a model node")]
async fn system() -> HydraSystem {
    let test_no = TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let config = HydraConfig {
        db_path: std::env::temp_dir()
            .join(format!("hydra-root-test-{}-{}.db", std::process::id(), test_no))
            .to_string_lossy()
            .to_string(),
        audit_db_path: std::env::temp_dir()
            .join(format!("hydra-audit-{}-{}.db", std::process::id(), test_no))
            .to_string_lossy()
            .to_string(),
        ..Default::default()
    };
    let _ = std::fs::remove_file(&config.db_path);
    let _ = std::fs::remove_file(&config.audit_db_path);
    HydraSystem::bootstrap(config).await.unwrap()
}

#[mbse::mbse_exempt("test helper — not a model node")]
fn found_plc(address: &str, vendor: &str) -> DiscoveredDevice {
    DiscoveredDevice {
        address: address.into(),
        device_type: "plc".into(),
        vendor: vendor.into(),
        capabilities: vec!["config".into()],
    }
}

/// Verifies REQ-008 (CONOPS-002): a discovered device is registered in
/// the catalog, matched to a driver, and the action is audited in the
/// control domain (REQ-036).
#[links_to("REQ-008")]
#[tokio::test]
async fn test_onboard_discovered_device() {
    let mut sys = system().await;
    let id = sys.onboard(found_plc("10.1.1.5", "acme")).await.unwrap();

    let device = sys.catalog.get_device(&id).await.unwrap().unwrap();
    assert_eq!(device.status, "discovered");
    let records = sys.audit.records().await.unwrap();
    assert!(records
        .iter()
        .any(|r| r.action == "catalog:register" && r.domain == AuditDomain::ControlPlane));
}

/// Verifies REQ-011 (CONOPS-002): a device of an unmatchable vendor
/// fails onboarding with a precise error.
#[links_to("REQ-011")]
#[tokio::test]
async fn test_onboard_unmatched_driver() {
    let mut sys = system().await;
    let err = sys.onboard(found_plc("10.1.1.6", "unknown")).await.unwrap_err();
    assert!(matches!(err, crate::system::SystemError::DriverNotMatched(_, _)));
}

/// Verifies REQ-012 (CONOPS-004): repeated loss of control trips
/// degradation with the graceful fallback.
#[links_to("REQ-012")]
#[tokio::test]
async fn test_degradation_trips() {
    let mut sys = system().await;
    assert!(!sys.on_driver_failure("plc/acme").await);
    assert!(sys.on_driver_failure("plc/acme").await);
    assert_eq!(sys.degradation.state("plc/acme"), DegradationState::Degraded);
    assert_eq!(
        sys.degradation.fallback("plc/acme"),
        Some(FallbackAction::ServeCachedConfig)
    );
}

/// Verifies REQ-015 (CONOPS-004): degradation emits a metric stream
/// event for reactive integration.
#[links_to("REQ-015")]
#[tokio::test]
async fn test_degradation_emits_metric_event() {
    let mut sys = system().await;
    let mut rx = sys.stream.subscribe();
    sys.on_driver_failure("plc/acme").await;
    sys.on_driver_failure("plc/acme").await; // trips

    let event = rx.recv().await.unwrap();
    assert_eq!(event.device, "plc/acme");
    assert!(matches!(event.kind, MetricKind::DeviceUnhealthy { .. }));
}

/// Verifies REQ-037 (CONOPS-004): the degradation is recorded in the
/// data-domain audit log — the immutable, hash-chained chain holds.
#[links_to("REQ-037")]
#[tokio::test]
async fn test_degradation_is_audited() {
    let mut sys = system().await;
    sys.on_driver_failure("plc/acme").await;
    sys.on_driver_failure("plc/acme").await;

    sys.audit.verify().await.unwrap();
    assert!(sys
        .audit
        .records()
        .await
        .unwrap()
        .iter()
        .any(|r| r.action == "degradation:activate"
            && r.actor == "system"
            && r.domain == AuditDomain::DataPlane));
}

/// Verifies REQ-014 (CONOPS-005): the system reports a health snapshot
/// for scaling coordination.
#[links_to("REQ-014")]
#[tokio::test]
async fn test_status_snapshot() {
    let mut sys = system().await;
    sys.onboard(found_plc("10.1.1.7", "siemens")).await.unwrap();

    let status = sys.status().await.unwrap();
    assert_eq!(status.devices_in_catalog, 1);
    assert_eq!(status.drivers_registered, 3); // acme + siemens + senselab sensor
    assert_eq!(status.degraded_devices, 0);
}

/// Verifies REQ-026 (CONOPS-002): onboarding a device wires it for
/// per-device telemetry — the hook into the device registry.
#[links_to("REQ-026")]
#[tokio::test]
async fn test_onboard_binds_per_device_telemetry() {
    let mut sys = system().await;
    let id = sys.onboard(found_plc("10.1.1.5", "acme")).await.unwrap();

    assert_eq!(sys.telemetry.len(), 1);
    assert!(sys.telemetry.devices().contains(&id.as_str()));
}

/// Verifies REQ-026 (system): a device bound to its driver contributes its
/// telemetry through the per-device pull into the metric stream.
#[links_to("REQ-026")]
#[tokio::test]
async fn test_collect_telemetry_pulls_per_device() {
    let mut sys = system().await;
    let sensor = Arc::new(SimDevice::new(0));
    {
        let mut raw = sensor.raw.lock().unwrap();
        raw.insert("temp_c".into(), serde_json::json!(21.5));
    }
    sys.bind_telemetry("sensor-1", Arc::new(SensorDriver::new(sensor)) as Arc<dyn Driver>);

    let points = sys.collect_telemetry().await;
    assert!(points
        .iter()
        .any(|p| p.device == "sensor-1" && p.metric == "temp_c" && p.value == 21.5));
}

/// Verifies REQ-034: a consumer reacts to a discovery event to drive the
/// provisioning workflow — register the device, bind its driver, and assign
/// it to the policy fleet.
#[links_to("REQ-034")]
#[tokio::test]
async fn test_provisioner_provisions_discovered_device() {
    use crate::provisioning::{FleetPolicy, Provisioner};
    use hydra_catalog::{CatalogService, FleetManager, SqliteStore};
    use hydra_drivers::{DriverRegistry, ModbusDriver};

    let test_no = TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("hydra-prov-{}-{}.db", std::process::id(), test_no))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);

    let store = SqliteStore::new(path.clone());
    store.init().await.unwrap();
    let catalog = CatalogService::new(store);

    let fleet_store = SqliteStore::new(path.clone());
    fleet_store.init().await.unwrap();
    let fleets = FleetManager::new(fleet_store);

    let mut registry = DriverRegistry::new();
    registry
        .register(Arc::new(ModbusDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
        .unwrap();

    let provisioner =
        Provisioner::new(catalog, fleets, registry, FleetPolicy::new("prod"));

    let event = hydra_telemetry::MetricEvent {
        kind: MetricKind::DeviceDiscovered {
            vendor: "acme".into(),
            device_type: "plc".into(),
        },
        device: "10.1.1.77".into(),
        ts_ms: 0,
    };

    let provisioned = provisioner.handle_discovered(&event).await.unwrap();
    assert_eq!(provisioned.device_id, "10.1.1.77"); // registered
    assert_eq!(provisioned.fleet_id, "prod"); // assigned to the policy fleet
    assert!(provisioned.driver_bound); // acme/plc has a driver
}

/// Verifies REQ-034: the consumer only reacts to discovery events — other
/// event kinds are ignored.
#[links_to("REQ-034")]
#[tokio::test]
async fn test_provisioner_ignores_non_discovery_events() {
    use crate::provisioning::{FleetPolicy, ProvisionError, Provisioner};
    use hydra_catalog::{CatalogService, FleetManager, SqliteStore};
    use hydra_drivers::DriverRegistry;

    let test_no = TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("hydra-prov2-{}-{}.db", std::process::id(), test_no))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);

    let store = SqliteStore::new(path.clone());
    store.init().await.unwrap();
    let fleet_store = SqliteStore::new(path.clone());
    fleet_store.init().await.unwrap();

    let provisioner = Provisioner::new(
        CatalogService::new(store),
        FleetManager::new(fleet_store),
        DriverRegistry::new(),
        FleetPolicy::new("prod"),
    );

    let recovered = hydra_telemetry::MetricEvent {
        kind: MetricKind::DeviceRecovered,
        device: "10.1.1.78".into(),
        ts_ms: 0,
    };
    assert!(matches!(
        provisioner.handle_discovered(&recovered).await,
        Err(ProvisionError::NotADiscoveryEvent)
    ));
}

/// Verifies REQ-035: the fleet a device is assigned to is determined by a
/// data-driven policy (vendor/type → fleet), with a default fallback.
#[links_to("REQ-035")]
#[tokio::test]
async fn test_fleet_assignment_is_policy_driven() {
    use crate::provisioning::{FleetPolicy, FleetRule, Provisioner};
    use hydra_catalog::{CatalogService, FleetManager, SqliteStore};
    use hydra_drivers::DriverRegistry;

    let test_no = TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let path = std::env::temp_dir()
        .join(format!("hydra-prov3-{}-{}.db", std::process::id(), test_no))
        .to_string_lossy()
        .to_string();
    let _ = std::fs::remove_file(&path);

    let store = SqliteStore::new(path.clone());
    store.init().await.unwrap();
    let fleet_store = SqliteStore::new(path.clone());
    fleet_store.init().await.unwrap();

    // acme PLCs → "plc-fleet"; everything else → default "misc-fleet".
    let policy = FleetPolicy::new("misc-fleet").add_rule(FleetRule {
        vendor: Some("acme".into()),
        device_type: Some("plc".into()),
        fleet_id: "plc-fleet".into(),
    });

    let provisioner = Provisioner::new(
        CatalogService::new(store),
        FleetManager::new(fleet_store),
        DriverRegistry::new(),
        policy,
    );

    // An acme PLC routes to the specific fleet…
    let plc = hydra_telemetry::MetricEvent {
        kind: MetricKind::DeviceDiscovered {
            vendor: "acme".into(),
            device_type: "plc".into(),
        },
        device: "10.9.9.1".into(),
        ts_ms: 0,
    };
    assert_eq!(provisioner.handle_discovered(&plc).await.unwrap().fleet_id, "plc-fleet");

    // A siemens sensor falls back to the default fleet.
    let sensor = hydra_telemetry::MetricEvent {
        kind: MetricKind::DeviceDiscovered {
            vendor: "siemens".into(),
            device_type: "sensor".into(),
        },
        device: "10.9.9.2".into(),
        ts_ms: 0,
    };
    assert_eq!(
        provisioner.handle_discovered(&sensor).await.unwrap().fleet_id,
        "misc-fleet"
    );
}

/// Verifies CONOPS-007 (the real loop): a discovery scan emits a discovery
/// event on the stream, and the provisioner reacts to provision it —
/// registered in the shared catalog and assigned to a fleet per policy.
#[links_to("REQ-034")]
#[tokio::test]
async fn test_discovery_loop_provisions_devices() {
    use hydra_catalog::DeviceFilters;
    use hydra_discovery::{MdnsSource, ScanSource};

    let mut sys = system().await;
    // A simulated device on the edge network.
    sys.discovery
        .add_source(MdnsSource::new(vec![found_plc("10.7.7.1", "acme")]));

    // Run one loop cycle: discovery scans + emits → provisioner provisions.
    let provisioned = sys.run_discovery_cycle().await;
    assert_eq!(provisioned, 1);

    // The device is registered in the shared catalog…
    let device = sys.catalog.get_device("10.7.7.1").await.unwrap().unwrap();
    assert_eq!(device.vendor, "acme");
    // …and assigned to the "edge" fleet by the provisioner's policy.
    let in_edge = sys
        .catalog
        .list_devices(DeviceFilters {
            fleet_id: Some("edge".into()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(in_edge.iter().any(|d| d.id == "10.7.7.1"));
}
