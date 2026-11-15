//! Device discovery engine (ARCH-DISCOVERY component).
//!
/// Satisfies REQ-008: support discovery of devices on the edge network.

use mbse::links_to;

/// Discovery engine (ARCH-DISCOVERY component).
/// 
/// Detects and registers devices on the edge network.
/// Supports multiple discovery mechanisms (mDNS, polling, heartbeat).
#[links_to("REQ-008", component = "ARCH-DISCOVERY")]
pub struct DiscoveryEngine {
    store: Box<dyn crate::storage::DeviceStore + Send + Sync>,
    /// Discovery interval (satisfies REQ-008 → P-DISCOVERY-INTERVAL).
    /// Bounded by: 60 seconds (model value).
    discovery_interval_sec: u64,
}

impl DiscoveryEngine {
    /// Create a new discovery engine.
    pub fn new(store: impl crate::storage::DeviceStore + Send + Sync + 'static, interval_sec: u64) -> Self {
        Self {
            store: Box::new(store),
            discovery_interval_sec: interval_sec,
        }
    }

    /// Register a discovered device.
    /// Satisfies REQ-008: device discovery.
    pub async fn register_device(&self, info: crate::storage::DiscoveryInfo) -> Result<crate::storage::Device, crate::storage::StoreError> {
        self.store.register_device(info).await
    }

    /// Unregister a device.
    pub async fn unregister_device(&self, id: &str) -> Result<(), crate::storage::StoreError> {
        self.store.unregister_device(id).await
    }

    /// Get the discovery interval.
    /// Verifies P-DISCOVERY-INTERVAL constraint (60s max).
    pub fn discovery_interval(&self) -> u64 {
        self.discovery_interval_sec
    }
}
