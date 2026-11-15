//! Driver registry (REQ-011) with the per-node device capacity
//! bound (REQ-014 → P-SCALE-DEVICE-COUNT).

use std::sync::Arc;

use crate::driver::{Driver, DriverError};

use mbse::links_to;

/// Maximum devices per Hydra cluster node (P-SCALE-DEVICE-COUNT,
/// bounded by REQ-014). Enforced by `DriverRegistry::register`.
#[links_to("REQ-014", parameter = "P-SCALE-DEVICE-COUNT", value = 1000.0)]
pub const MAX_DEVICES_PER_NODE: usize = 1000;

/// Registry of heterogeneous drivers, keyed by `(device_type, vendor)`
/// (REQ-011). Enforces the per-node device capacity (REQ-014).
#[links_to("REQ-011", component = "ARCH-DRIVERS")]
#[links_to("REQ-014", component = "ARCH-DRIVERS")]
pub struct DriverRegistry {
    drivers: std::collections::HashMap<(String, String), Arc<dyn Driver>>,
    capacity: usize,
}

impl DriverRegistry {
    /// New registry with the model's capacity (`MAX_DEVICES_PER_NODE`).
    pub fn new() -> Self {
        Self {
            drivers: std::collections::HashMap::new(),
            capacity: MAX_DEVICES_PER_NODE,
        }
    }

    /// New registry with an explicit per-node capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            drivers: std::collections::HashMap::new(),
            capacity,
        }
    }

    /// Register a driver for its `(device_type, vendor)` slot.
    pub fn register(&mut self, driver: Arc<dyn Driver>) -> Result<(), DriverError> {
        if self.drivers.len() >= self.capacity {
            return Err(DriverError::CapacityExceeded);
        }
        self.drivers
            .insert((driver.device_type().to_string(), driver.vendor().to_string()), driver);
        Ok(())
    }

    /// Resolve a driver for a device type / vendor (REQ-011).
    pub fn resolve(&self, device_type: &str, vendor: &str) -> Result<Arc<dyn Driver>, DriverError> {
        self.drivers
            .get(&(device_type.to_string(), vendor.to_string()))
            .cloned()
            .ok_or_else(|| DriverError::NotResolved {
                device_type: device_type.to_string(),
                vendor: vendor.to_string(),
            })
    }

    /// Number of registered drivers.
    pub fn len(&self) -> usize {
        self.drivers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.drivers.is_empty()
    }

    /// The per-node capacity in force (P-SCALE-DEVICE-COUNT).
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}
