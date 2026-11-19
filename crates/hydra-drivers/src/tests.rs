//! Tests for hydra-drivers — verifies requirements via `#[links_to]`.

use std::sync::Arc;

use crate::bus::DeviceComm;
use crate::degradation::{DegradationManager, DegradationState, FallbackAction};
use crate::driver::{DeviceConfig, Driver, DriverError};
use crate::registry::DriverRegistry;
use crate::sim::{ModbusDriver, OpcUaDriver, SensorDriver, SimDevice};
use crate::driver::{DriverCapabilities, DriverOp};

use mbse::links_to;

mbse_graph::collect_test!();

#[mbse::mbse_exempt("test helper — not a model node")]
fn run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(fut)
}

#[mbse::mbse_exempt("test helper — not a model node")]
fn online_device(latency_ms: u64) -> Arc<SimDevice> {
    Arc::new(SimDevice::new(latency_ms))
}

/// Verifies REQ-009: retrieving device configuration through the bus.
#[links_to("REQ-009")]
#[test]
fn test_get_config() {
    let device = online_device(0);
    let mut registry = DriverRegistry::new();
    registry
        .register(Arc::new(ModbusDriver::new(device.clone())) as Arc<dyn Driver>)
        .unwrap();
    let comm = DeviceComm::new(registry);

    let config = run(comm.get_config("plc", "acme")).unwrap();
    assert!(config.values.is_empty());
}

/// Verifies REQ-010: setting device configuration, then reading it back.
#[links_to("REQ-010")]
#[test]
fn test_set_config_roundtrip() {
    let device = online_device(0);
    let mut registry = DriverRegistry::new();
    registry
        .register(Arc::new(ModbusDriver::new(device)) as Arc<dyn Driver>)
        .unwrap();
    let comm = DeviceComm::new(registry);

    let config = DeviceConfig::default().with("output", serde_json::json!(42));
    run(comm.set_config("plc", "acme", &config)).unwrap();
    let read_back = run(comm.get_config("plc", "acme")).unwrap();
    assert_eq!(read_back.values["output"], 42);
}

/// Verifies REQ-011: heterogeneous vendors behind one interface —
/// acme (MODBUS) and siemens (OPC-UA) PLCs both resolve and round-trip.
#[links_to("REQ-011")]
#[test]
fn test_heterogeneous_vendors() {
    let mut registry = DriverRegistry::new();
    registry
        .register(Arc::new(ModbusDriver::new(online_device(0))) as Arc<dyn Driver>)
        .unwrap();
    registry
        .register(Arc::new(OpcUaDriver::new(online_device(0))) as Arc<dyn Driver>)
        .unwrap();
    let comm = DeviceComm::new(registry);

    let config = DeviceConfig::default().with("mode", serde_json::json!("auto"));
    run(comm.set_config("plc", "acme", &config)).unwrap();
    run(comm.set_config("plc", "siemens", &config)).unwrap();

    assert_eq!(run(comm.get_config("plc", "acme")).unwrap().values["mode"], "auto");
    assert_eq!(run(comm.get_config("plc", "siemens")).unwrap().values["mode"], "auto");
}

/// Verifies REQ-011: unknown vendor/type is not resolved.
#[links_to("REQ-011")]
#[test]
fn test_unresolved_driver() {
    let comm = DeviceComm::new(DriverRegistry::new());
    let err = run(comm.get_config("plc", "nope")).unwrap_err();
    assert!(matches!(err, DriverError::NotResolved { .. }));
}

/// Verifies REQ-012: a device that exceeds P-DRIVER-TIMEOUT degrades to
/// the graceful fallback after the failure threshold.
#[links_to("REQ-012")]
#[test]
fn test_degradation_on_timeout() {
    let device = online_device(300); // slower than the 50ms budget below
    let mut registry = DriverRegistry::new();
    registry
        .register(Arc::new(ModbusDriver::new(device)) as Arc<dyn Driver>)
        .unwrap();
    let comm = DeviceComm::new(registry).with_timeout(50);

    let mut mgr = DegradationManager::new(2);
    for _ in 0..2 {
        let err = run(comm.get_config("plc", "acme")).unwrap_err();
        assert!(matches!(err, DriverError::Timeout));
        mgr.record("plc/acme", false);
    }

    assert_eq!(mgr.state("plc/acme"), DegradationState::Degraded);
    assert_eq!(mgr.fallback("plc/acme"), Some(FallbackAction::ServeCachedConfig));
}

/// Verifies REQ-012: recovery clears degradation.
#[links_to("REQ-012")]
#[test]
fn test_recovery_clears_degradation() {
    let mut mgr = DegradationManager::new(2);
    mgr.record("dev", false);
    mgr.record("dev", false);
    assert_eq!(mgr.state("dev"), DegradationState::Degraded);
    mgr.record("dev", true);
    assert_eq!(mgr.state("dev"), DegradationState::Healthy);
    assert_eq!(mgr.fallback("dev"), None);
}

/// Verifies REQ-018: drivers declare their fidelity — the fleet spans
/// the tiers (full, config, telemetry-only).
#[links_to("REQ-018")]
#[test]
fn test_fidelity_tiers_declared() {
    let full = ModbusDriver::new(online_device(0)).capabilities();
    assert!(full.supports(DriverOp::Command));
    assert!(full.supports(DriverOp::ConfigWrite));

    let config_level = OpcUaDriver::new(online_device(0)).capabilities();
    assert!(config_level.supports(DriverOp::ConfigWrite));
    assert!(!config_level.supports(DriverOp::Command));

    let floor = SensorDriver::new(online_device(0)).capabilities();
    assert_eq!(floor, DriverCapabilities::telemetry_only());
    assert!(!floor.supports(DriverOp::ConfigRead));
}

/// Verifies REQ-018: a driver without the command fidelity rejects
/// commands even when called directly (the capability is a contract,
/// not just a gate).
#[links_to("REQ-018")]
#[test]
fn test_fidelity_rejected_at_driver() {
    let sensor = SensorDriver::new(online_device(0));
    let err = run(sensor.command("reboot")).unwrap_err();
    assert!(matches!(err, DriverError::Rejected(_)));
}

/// The registry's slot guard rejects a (type,vendor) registration beyond
/// its capacity. This is a code-level guard on *driver slots* — device
/// scale (REQ-014 → P-SCALE-DEVICE-COUNT) is enforced in the catalog and
/// verified by the e2e scale test.
#[mbse::mbse_exempt("code-level driver-slot guard — not a model node; device scale (REQ-014) is verified by the e2e scale test")]
#[test]
fn test_capacity_enforced() {
    let mut registry = DriverRegistry::with_capacity(2);
    registry
        .register(Arc::new(ModbusDriver::new(online_device(0))) as Arc<dyn Driver>)
        .unwrap();
    registry
        .register(Arc::new(OpcUaDriver::new(online_device(0))) as Arc<dyn Driver>)
        .unwrap();
    let err = registry
        .register(Arc::new(ModbusDriver::new(online_device(0))) as Arc<dyn Driver>)
        .unwrap_err();
    assert!(matches!(err, DriverError::CapacityExceeded));
    assert_eq!(registry.capacity(), 2);
}

/// Verifies REQ-026 (driver side): the telemetry fidelity op is now
/// readable — a telemetry-only sensor (the REQ-018 floor) reports its
/// metrics, and an offline device reports unreachable (CONOPS-004).
#[links_to("REQ-026")]
#[test]
fn test_driver_telemetry_reads_metrics() {
    // A telemetry-only sensor (REQ-018 floor) can now actually be read.
    let sensor = Arc::new(SimDevice::new(0));
    {
        let mut raw = sensor.raw.lock().unwrap();
        raw.insert("temp_c".into(), serde_json::json!(21.5));
        raw.insert("humidity_pct".into(), serde_json::json!(48.0));
    }
    let drv = SensorDriver::new(sensor);
    let metrics = run(drv.telemetry()).unwrap();
    assert!(metrics.iter().any(|m| m.name == "temp_c" && m.value == 21.5));
    assert!(metrics.iter().any(|m| m.name == "humidity_pct" && m.value == 48.0));

    // An offline device's telemetry read is unreachable (degradation path).
    let offline = Arc::new(SimDevice::new(0));
    offline.go_offline();
    let drv = SensorDriver::new(offline);
    let err = run(drv.telemetry()).unwrap_err();
    assert!(matches!(err, DriverError::Unreachable));
}
