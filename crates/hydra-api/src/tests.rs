//! Tests for hydra-api — verifies REQ-004/REQ-018 through the split
//! control-plane (`ApiGateway`) and data-plane (`DataPlaneGateway`) gateways.

use crate::gateway::{ApiError, ApiGateway, DataPlaneGateway, DeviceOperation, Operation};

use std::sync::Arc;

use hydra_audit::AuditLog;
use hydra_auth::{AclEngine, AuthService, CertProvider, IdentityPool, OidcProvider};
use hydra_catalog::{CatalogService, Device, FleetManager, SqliteStore};
use hydra_discovery::DiscoveryConfigStore;
use hydra_drivers::{
    DeviceComm, Driver, DriverRegistry, ModbusDriver, OpcUaDriver, SensorDriver, SimDevice,
};

use mbse::links_to;

mbse_graph::collect_test!();

const ISSUER: &str = "https://id.hydra.internal";
const AUDIENCE: &str = "hydra-api";
const NOW: u64 = 1_700_000_000;
const FUTURE: u64 = 4_102_444_800;

fn claims(roles: &[&str]) -> String {
    serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "exp": FUTURE,
        "roles": roles,
    })
    .to_string()
}

fn run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(fut)
}

static TEST_NO: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn next_test_no() -> u64 {
    TEST_NO.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
}

/// Shared auth: OIDC for operators, certificates for devices, ACL for all
/// three planes' actions.
fn auth() -> AuthService {
    let acl = AclEngine::new()
        .allow_role("operator", "catalog:*", "catalog/devices*")
        .allow_role("operator", "fleet:*", "fleet/*")
        .allow_role("operator", "device:*", "devices/*")
        .allow_role("operator", "discovery:*", "discovery*");
    let pool = IdentityPool::new()
        .register(OidcProvider::new(ISSUER, AUDIENCE))
        .register(CertProvider::new("device/"));
    AuthService::new(pool, acl)
}

/// Control-plane gateway (catalog + fleet ops) over a fresh durable store.
async fn control_gateway() -> ApiGateway {
    let n = next_test_no();
    let path = std::env::temp_dir()
        .join(format!("hydra-api-c-{}-{}.db", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    let path_str = path.to_string_lossy().to_string();
    let store = SqliteStore::new(path_str.clone());
    store.init().await.unwrap();
    let catalog = CatalogService::new(store);
    let fleet_store = SqliteStore::new(path_str);
    fleet_store.init().await.unwrap();
    let fleets = FleetManager::new(fleet_store);
    ApiGateway::new(auth(), catalog, fleets, DiscoveryConfigStore::new(), AuditLog::new())
}

/// Data-plane gateway (device ops) over a fresh store, with one device
/// already created for the given (type, vendor). Returns the gateway and the
/// device id.
async fn data_gateway(device_type: &str, vendor: &str) -> (DataPlaneGateway, String) {
    let n = next_test_no();
    let path = std::env::temp_dir()
        .join(format!("hydra-api-d-{}-{}.db", std::process::id(), n));
    let _ = std::fs::remove_file(&path);
    let path_str = path.to_string_lossy().to_string();
    let store = SqliteStore::new(path_str.clone());
    store.init().await.unwrap();
    let catalog = CatalogService::new(store);

    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let created = catalog
        .create_device(Device {
            id: format!("dev-{}-{}-{}", std::process::id(), n, ns),
            name: "Fidelity Test".into(),
            device_type: device_type.into(),
            vendor: vendor.into(),
            status: "active".into(),
            fleet_ids: vec![],
            metadata: serde_json::json!({}),
        })
        .await
        .unwrap();
    let id = created.id;

    // The device fleet: full-fidelity acme PLC, config-fidelity siemens PLC,
    // telemetry-only senselab sensor (REQ-018 tiers).
    let mut registry = DriverRegistry::new();
    registry
        .register(Arc::new(ModbusDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
        .unwrap();
    registry
        .register(Arc::new(OpcUaDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
        .unwrap();
    registry
        .register(Arc::new(SensorDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
        .unwrap();
    let comm = DeviceComm::new(registry);

    (DataPlaneGateway::new(auth(), catalog, comm, AuditLog::new()), id)
}

// ── Control plane (ARCH-CTRL-GW) — REQ-004 ─────────────────────────────

/// Verifies REQ-004 (control plane): an authorized operator creates and
/// lists devices.
#[links_to("REQ-004")]
#[test]
fn test_operator_creates_and_lists() {
    let mut gw = run(control_gateway());
    let token = claims(&["operator"]);

    let created = run(gw.handle(
        &token,
        Operation::CreateDevice {
            name: "Edge Switch A".into(),
            device_type: "switch".into(),
            vendor: "acme".into(),
        },
        NOW,
    ))
    .unwrap();
    assert!(created["name"] == "Edge Switch A");

    let listed = run(gw.handle(&token, Operation::ListDevices, NOW)).unwrap();
    let arr = listed.as_array().expect("list is an array");
    assert!(arr.iter().any(|d| d["name"] == "Edge Switch A"));
}

/// Verifies REQ-004 (control plane): device fleet operations.
#[links_to("REQ-004")]
#[test]
fn test_operator_joins_fleet() {
    let mut gw = run(control_gateway());
    let token = claims(&["operator"]);

    let created = run(gw.handle(
        &token,
        Operation::CreateDevice {
            name: "PLC-7".into(),
            device_type: "plc".into(),
            vendor: "siemens".into(),
        },
        NOW,
    ))
    .unwrap();
    let device_id = created["id"].as_str().unwrap().to_string();

    let joined = run(gw.handle(
        &token,
        Operation::AddToFleet {
            device_id,
            fleet_id: "prod".into(),
        },
        NOW,
    ))
    .unwrap();
    assert!(joined["joined"] == true);
}

/// Verifies REQ-004 (control plane): unauthenticated requests are rejected.
#[links_to("REQ-004")]
#[test]
fn test_unauthenticated_rejected() {
    let mut gw = run(control_gateway());
    let err = run(gw.handle("not-a-token", Operation::ListDevices, NOW))
        .unwrap_err();
    assert!(matches!(err, ApiError::Unauthorized(_)));
}

/// Verifies REQ-004 (control plane): an authenticated principal without the
/// role is forbidden (ACL scoping, REQ-002/003).
#[links_to("REQ-004")]
#[test]
fn test_forbidden_rejected() {
    let mut gw = run(control_gateway());
    let viewer = claims(&["viewer"]);
    let err = run(gw.handle(
        &viewer,
        Operation::CreateDevice {
            name: "Nope".into(),
            device_type: "plc".into(),
            vendor: "acme".into(),
        },
        NOW,
    ))
    .unwrap_err();
    assert!(matches!(err, ApiError::Forbidden(_)));
}

/// Verifies REQ-016 (control plane): every device action is audited, with a
/// verifiable chain.
#[links_to("REQ-016")]
#[test]
fn test_actions_are_audited() {
    let mut gw = run(control_gateway());
    let token = claims(&["operator"]);
    run(gw.handle(
        &token,
        Operation::CreateDevice {
            name: "Audited".into(),
            device_type: "switch".into(),
            vendor: "acme".into(),
        },
        NOW,
    ))
    .unwrap();

    let audit = gw.audit();
    assert_eq!(audit.len(), 1);
    audit.verify().unwrap();
    assert_eq!(audit.records()[0].actor, "alice");
    assert_eq!(audit.records()[0].action, "catalog:create");
}

/// Verifies REQ-032 (control plane): discovery configurations are first-class
/// resources the operator can create and read back.
#[links_to("REQ-032")]
#[test]
fn test_control_plane_manages_discovery_config() {
    use hydra_discovery::DiscoveryConfig;

    let mut gw = run(control_gateway());
    let token = claims(&["operator"]);

    let config = DiscoveryConfig {
        id: "cfg-edge".into(),
        name: "Edge subnet scan".into(),
        interval_ms: 30_000,
        vendor: Some("acme".into()),
        device_type: None,
    };
    let set = run(gw.handle(
        &token,
        Operation::SetDiscoveryConfig {
            config: config.clone(),
        },
        NOW,
    ))
    .unwrap();
    assert_eq!(set["id"], "cfg-edge");

    let got = run(gw.handle(
        &token,
        Operation::GetDiscoveryConfig {
            id: "cfg-edge".into(),
        },
        NOW,
    ))
    .unwrap();
    assert_eq!(got["vendor"], "acme");

    let list = run(gw.handle(&token, Operation::ListDiscoveryConfigs, NOW)).unwrap();
    let arr = list.as_array().expect("list");
    assert!(arr.iter().any(|c| c["id"] == "cfg-edge"));
}

// ── Data plane (ARCH-DATA-GW) — REQ-018 fidelity ───────────────────────

/// Verifies REQ-018 (data plane): the gateway refuses operations outside a
/// driver's fidelity — a telemetry-only sensor has no config read.
#[links_to("REQ-018")]
#[tokio::test]
async fn test_fidelity_floor_refuses_config() {
    let (mut gw, id) = data_gateway("sensor", "senselab").await;
    let token = claims(&["operator"]);

    let err = gw
        .handle(&token, DeviceOperation::GetDeviceConfig { id }, NOW)
        .await
        .unwrap_err();
    match err {
        ApiError::NotSupported(op) => assert!(op.contains("ConfigRead")),
        other => panic!("expected NotSupported, got {other:?}"),
    }
}

/// Verifies REQ-018 (data plane): partial fidelity — the siemens PLC serves
/// config but refuses commands.
#[links_to("REQ-018")]
#[tokio::test]
async fn test_partial_fidelity_refuses_command() {
    let (mut gw, id) = data_gateway("plc", "siemens").await;
    let token = claims(&["operator"]);

    // Config read is within fidelity...
    let config = gw
        .handle(
            &token,
            DeviceOperation::GetDeviceConfig { id: id.clone() },
            NOW,
        )
        .await
        .unwrap();
    assert!(config.get("values").is_some());

    // ...but a command is not.
    let err = gw
        .handle(&token, DeviceOperation::RebootDevice { id }, NOW)
        .await
        .unwrap_err();
    match err {
        ApiError::NotSupported(op) => assert!(op.contains("Command")),
        other => panic!("expected NotSupported, got {other:?}"),
    }
}

/// Verifies REQ-018 (data plane): full fidelity — the acme PLC serves config
/// and commands through the data plane.
#[links_to("REQ-018")]
#[tokio::test]
async fn test_full_fidelity_allows_operations() {
    let (mut gw, id) = data_gateway("plc", "acme").await;
    let token = claims(&["operator"]);

    let values = serde_json::json!({ "output": 42 }).as_object().unwrap().clone();
    gw.handle(
        &token,
        DeviceOperation::SetDeviceConfig {
            id: id.clone(),
            values,
        },
        NOW,
    )
    .await
    .unwrap();
    let config = gw
        .handle(&token, DeviceOperation::GetDeviceConfig { id: id.clone() }, NOW)
        .await
        .unwrap();
    assert_eq!(config["values"]["output"], 42);

    let rebooted = gw
        .handle(&token, DeviceOperation::RebootDevice { id }, NOW)
        .await
        .unwrap();
    assert_eq!(rebooted["rebooted"], true);
}

/// Verifies REQ-018 (data plane): a catalog device with no driver is
/// manageable in the catalog but not operable.
#[links_to("REQ-018")]
#[tokio::test]
async fn test_no_driver_cannot_operate() {
    let (mut gw, id) = data_gateway("plc", "mystery-vendor").await;
    let token = claims(&["operator"]);

    let err = gw
        .handle(&token, DeviceOperation::GetDeviceConfig { id }, NOW)
        .await
        .unwrap_err();
    assert!(matches!(err, ApiError::NoDriver(_, _)));
}
