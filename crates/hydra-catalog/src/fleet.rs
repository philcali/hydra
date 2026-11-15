//! Fleet management (ARCH-FLEET component).
//!
/// Satisfies REQ-006: ability to group devices into categories called fleets.

use mbse::links_to;

/// Fleet manager (ARCH-FLEET component).
/// 
/// Groups devices into categories ("fleets") for bulk operations.
#[links_to("REQ-006", component = "ARCH-FLEET")]
pub struct FleetManager {
    store: Box<dyn crate::storage::DeviceStore + Send + Sync>,
}

impl FleetManager {
    /// Create a new fleet manager.
    pub fn new(store: impl crate::storage::DeviceStore + Send + Sync + 'static) -> Self {
        Self {
            store: Box::new(store),
        }
    }

    /// Add a device to a fleet.
    pub async fn add_to_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), crate::storage::StoreError> {
        self.store.add_to_fleet(device_id, fleet_id).await
    }

    /// Remove a device from a fleet.
    pub async fn remove_from_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), crate::storage::StoreError> {
        self.store.remove_from_fleet(device_id, fleet_id).await
    }

    /// List all fleets with device counts.
    pub async fn list_fleets(&self) -> Result<Vec<crate::storage::Fleet>, crate::storage::StoreError> {
        self.store.list_fleets().await
    }
}
