//! CONOPS flow tests for the Hydra system (ARCH-SYS-MGMT).

use crate::system::{HydraConfig, HydraSystem};

use std::sync::Arc;

use hydra_discovery::DiscoveredDevice;
use hydra_drivers::{DegradationState, Driver, FallbackAction, SensorDriver, SimDevice};
use hydra_telemetry::MetricKind;

use mbse::links_to;

mbse_graph::collect_test!();

static TEST_NO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

async fn system() -> HydraSystem {
    let test_no = TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let config = HydraConfig {
        db_path: std::env::temp_dir()
            .join(format!("hydra-root-test-{}-{}.db", std::process::id(), test_no))
            .to_string_lossy()
            .to_string(),
        ..Default::default()
    };
    let _ = std::fs::remove_file(&config.db_path);
    HydraSystem::bootstrap(config).await.unwrap()
}

fn found_plc(address: &str, vendor: &str) -> DiscoveredDevice {
    DiscoveredDevice {
        address: address.into(),
        device_type: "plc".into(),
        vendor: vendor.into(),
        capabilities: vec!["config".into()],
    }
}

/// Verifies REQ-008 (CONOPS-002): a discovered device is registered in
/// the catalog, matched to a driver, and the action is audited.
#[links_to("REQ-008")]
#[tokio::test]
async fn test_onboard_discovered_device() {
    let mut sys = system().await;
    let id = sys.onboard(found_plc("10.1.1.5", "acme")).await.unwrap();

    let device = sys.catalog.get_device(&id).await.unwrap().unwrap();
    assert_eq!(device.status, "discovered");
    assert!(sys
        .audit
        .records()
        .iter()
        .any(|r| r.action == "catalog:register"));
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
    assert!(!sys.on_driver_failure("plc/acme"));
    assert!(sys.on_driver_failure("plc/acme"));
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
    sys.on_driver_failure("plc/acme");
    sys.on_driver_failure("plc/acme"); // trips

    let event = rx.recv().await.unwrap();
    assert_eq!(event.device, "plc/acme");
    assert!(matches!(event.kind, MetricKind::DeviceUnhealthy { .. }));
}

/// Verifies REQ-016 (CONOPS-004): the degradation is recorded in the
/// immutable audit log.
#[links_to("REQ-016")]
#[tokio::test]
async fn test_degradation_is_audited() {
    let mut sys = system().await;
    sys.on_driver_failure("plc/acme");
    sys.on_driver_failure("plc/acme");

    sys.audit.verify().unwrap();
    assert!(sys
        .audit
        .records()
        .iter()
        .any(|r| r.action == "degradation:activate" && r.actor == "system"));
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
