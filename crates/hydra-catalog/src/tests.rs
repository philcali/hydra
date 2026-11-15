//! Tests for hydra-catalog — verifies requirements via `#[links_to]`.

use super::*;
use crate::storage::{Device, DeviceFilters, DiscoveryInfo, PostgresStore, SqliteStore};
use mbse::links_to;

mbse_graph::collect_test!();

/// Verifies REQ-005: queryable device catalog (list_devices).
#[links_to("REQ-005")]
#[test]
fn test_list_devices_empty() {
    let store = SqliteStore::new(":memory:");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        store.init().await.unwrap();
        let svc = CatalogService::new(store);
        let devices = svc.list_devices(DeviceFilters::default()).await.unwrap();
        assert!(devices.is_empty());
    });
}

/// Verifies REQ-006: fleet grouping (add_to_fleet).
#[links_to("REQ-006")]
#[test]
fn test_add_to_fleet() {
    let store = SqliteStore::new(":memory:");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        store.init().await.unwrap();
        let device = Device {
            id: "dev-1".into(),
            name: "Fleet Member".into(),
            device_type: "switch".into(),
            vendor: "test".into(),
            status: "active".into(),
            fleet_ids: vec![],
            metadata: serde_json::json!({}),
        };
        store.create_device(device).await.unwrap();
        let fm = FleetManager::new(store);
        fm.add_to_fleet("dev-1", "fleet-1").await.unwrap();
        let fleets = fm.list_fleets().await.unwrap();
        assert!(fleets.iter().any(|f| f.id == "fleet-1"));
    });
}

/// Verifies REQ-008: device discovery (register_device).
#[links_to("REQ-008")]
#[test]
fn test_discovery_register() {
    let store = SqliteStore::new(":memory:");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        store.init().await.unwrap();
        let de = DiscoveryEngine::new(store, 60);
        let info = DiscoveryInfo {
            address: "192.168.1.1".into(),
            device_type: "switch".into(),
            vendor: "test".into(),
            capabilities: vec!["config".into()],
        };
        let device = de.register_device(info).await.unwrap();
        assert_eq!(device.status, "discovered");
        assert_eq!(device.metadata["address"], "192.168.1.1");
    });
}

/// Verifies REQ-014: storage interface (DeviceStore trait).
/// Tests that both implementations satisfy the trait.
#[links_to("REQ-014")]
#[test]
fn test_sqlite_store_implements_device_store() {
    let store = SqliteStore::new(":memory:");
    // Compile-time check: SqliteStore must implement DeviceStore
    let _: &dyn DeviceStore = &store;
}

/// Verifies REQ-014: PostgresStore implements DeviceStore.
#[links_to("REQ-014")]
#[test]
fn test_postgres_store_implements_device_store() {
    let store = PostgresStore::new("postgres://localhost/test");
    let _: &dyn DeviceStore = &store;
}

/// Verifies REQ-007: catalog management (create + read back).
#[links_to("REQ-007")]
#[test]
fn test_create_device() {
    let store = SqliteStore::new(":memory:");
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        store.init().await.unwrap();
        let svc = CatalogService::new(store);
        let device = Device {
            id: "dev-1".into(),
            name: "Test Device".into(),
            device_type: "switch".into(),
            vendor: "test".into(),
            status: "active".into(),
            fleet_ids: vec![],
            metadata: serde_json::json!({}),
        };
        let created = svc.create_device(device).await.unwrap();
        assert_eq!(created.id, "dev-1");
        let read_back = svc.get_device("dev-1").await.unwrap().unwrap();
        assert_eq!(read_back.name, "Test Device");
    });
}
