//! Discovery configuration (REQ-032) — a first-class resource.
//!
//! A `DiscoveryConfig` is managed by the control plane and consumed by
//! discovery: it defines the scan cadence (bounded by P-DISCOVERY-INTERVAL)
//! and the vendor/type filter for what discovery matches. It is **not** a
//! fleet property — fleet assignment is a downstream workflow (REQ-034), so
//! one config can drive discovery for a pool that many fleets draw from.

use mbse::links_to;

/// A discovery configuration — a first-class resource (REQ-032).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[links_to("REQ-032", component = "ARCH-DISCOVERY")]
pub struct DiscoveryConfig {
    pub id: String,
    pub name: String,
    /// Scan cadence in milliseconds (bounded by P-DISCOVERY-INTERVAL).
    pub interval_ms: u64,
    /// Only match devices of this vendor. **None = any vendor.**
    pub vendor: Option<String>,
    /// Only match devices of this type. **None = any type.**
    pub device_type: Option<String>,
}

impl DiscoveryConfig {
    /// Whether a discovered (vendor, type) pair matches this config's filter.
    pub fn matches(&self, vendor: &str, device_type: &str) -> bool {
        let vendor_ok = self
            .vendor
            .as_deref()
            .map(|v| v == vendor)
            .unwrap_or(true);
        let type_ok = self
            .device_type
            .as_deref()
            .map(|t| t == device_type)
            .unwrap_or(true);
        vendor_ok && type_ok
    }
}

/// A store of discovery configurations (REQ-032) — first-class resources the
/// control plane manages (create/read/update) and discovery consumes.
#[derive(Default)]
#[links_to("REQ-032", component = "ARCH-DISCOVERY")]
pub struct DiscoveryConfigStore {
    configs: std::sync::Mutex<Vec<DiscoveryConfig>>,
}

impl DiscoveryConfigStore {
    pub fn new() -> Self {
        Self {
            configs: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Create (or replace) a configuration. Returns the stored copy.
    pub fn upsert(&self, config: DiscoveryConfig) -> DiscoveryConfig {
        let mut configs = self.configs.lock().unwrap();
        if let Some(slot) = configs.iter_mut().find(|c| c.id == config.id) {
            *slot = config.clone();
        } else {
            configs.push(config.clone());
        }
        config
    }

    /// Read a configuration by id.
    pub fn get(&self, id: &str) -> Option<DiscoveryConfig> {
        self.configs.lock().unwrap().iter().find(|c| c.id == id).cloned()
    }

    /// List all configurations.
    pub fn list(&self) -> Vec<DiscoveryConfig> {
        self.configs.lock().unwrap().clone()
    }

    /// Number of stored configurations.
    pub fn len(&self) -> usize {
        self.configs.lock().unwrap().len()
    }
}
