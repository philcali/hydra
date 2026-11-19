//! Driver registry (REQ-011).
//!
//! Note: the registry is keyed by `(device_type, vendor)`, so its capacity
//! bounds the number of **driver slots** — a code-level guard, *not* the
//! device scale bound. P-SCALE-DEVICE-COUNT (REQ-014) counts devices and
//! is enforced in the catalog (`hydra_catalog::storage::MAX_DEVICES_PER_NODE`).

use std::sync::Arc;

use crate::driver::{Driver, DriverError};

use mbse::links_to;
use mbse::mbse_exempt;

/// Maximum driver slots in a registry (code-level guard). This is *not*
/// the device scale bound — see the module docs.
#[mbse_exempt("code-level guard on (type,vendor) driver slots — not a model node; device scale is P-SCALE-DEVICE-COUNT, enforced in the catalog")]
pub const MAX_DRIVER_SLOTS: usize = 1000;

/// Registry of heterogeneous drivers, keyed by `(device_type, vendor)`
/// (REQ-011).
#[links_to("REQ-011", component = "ARCH-DRIVERS")]
pub struct DriverRegistry {
    drivers: std::collections::HashMap<(String, String), Arc<dyn Driver>>,
    capacity: usize,
}

impl DriverRegistry {
    /// New registry with the default slot capacity (`MAX_DRIVER_SLOTS`).
    pub fn new() -> Self {
        Self {
            drivers: std::collections::HashMap::new(),
            capacity: MAX_DRIVER_SLOTS,
        }
    }

    /// New registry with an explicit slot capacity.
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

    /// The driver-slot capacity in force (code-level guard; see module docs).
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Default for DriverRegistry {
    fn default() -> Self {
        Self::new()
    }
}
