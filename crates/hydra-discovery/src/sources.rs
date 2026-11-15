//! Edge-network scan sources (REQ-008).
//!
//! mDNS, subnet poll, and heartbeat are all `ScanSource`s; simulated
//! implementations keep the pipeline testable without a network.

use mbse::links_to;
use mbse::mbse_exempt;

/// A device detected on the edge network (REQ-008).
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub struct DiscoveredDevice {
    pub address: String,
    pub device_type: String,
    pub vendor: String,
    pub capabilities: Vec<String>,
}

/// A discovery mechanism on the edge network (REQ-008).
#[links_to("REQ-008", component = "ARCH-DISCOVERY")]
#[async_trait::async_trait]
pub trait ScanSource: Send + Sync {
    /// One scan pass: the devices currently visible via this mechanism.
    async fn scan(&self) -> Vec<DiscoveredDevice>;
}

/// mDNS-based discovery (devices advertise themselves).
#[links_to("REQ-008", component = "ARCH-DISCOVERY")]
pub struct MdnsSource {
    visible: Vec<DiscoveredDevice>,
}

impl MdnsSource {
    pub fn new(visible: Vec<DiscoveredDevice>) -> Self {
        Self { visible }
    }
}

#[async_trait::async_trait]
impl ScanSource for MdnsSource {
    async fn scan(&self) -> Vec<DiscoveredDevice> {
        self.visible.clone()
    }
}

/// Subnet poll-based discovery (the engine probes the edge subnet).
#[links_to("REQ-008", component = "ARCH-DISCOVERY")]
pub struct PollSource {
    visible: Vec<DiscoveredDevice>,
}

impl PollSource {
    pub fn new(visible: Vec<DiscoveredDevice>) -> Self {
        Self { visible }
    }
}

#[async_trait::async_trait]
impl ScanSource for PollSource {
    async fn scan(&self) -> Vec<DiscoveredDevice> {
        self.visible.clone()
    }
}
