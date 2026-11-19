//! Provisioning workflow (REQ-034/REQ-035, ARCH-PROVISIONING).
//!
//! A data-plane **consumer**: reacts to `DeviceDiscovered` events on the
//! metric stream and drives the provisioning workflow — register the device,
//! bind its driver, assign it to a fleet. The fleet is chosen by a
//! **data-driven assignment policy** (REQ-035), so routing lives here (the
//! workflow), not in discovery.

use hydra_catalog::{CatalogService, Device, FleetManager};
use hydra_drivers::DriverRegistry;
use hydra_telemetry::{MetricEvent, MetricKind, MetricStream};

use mbse::links_to;
use mbse::mbse_exempt;

/// The outcome of provisioning a discovered device.
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub struct Provisioned {
    pub device_id: String,
    pub fleet_id: String,
    /// Whether a driver was found for the device (bound).
    pub driver_bound: bool,
}

/// A provisioning failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum ProvisionError {
    #[error("not a discovery event")]
    NotADiscoveryEvent,
    #[error("catalog: {0}")]
    Catalog(String),
    #[error("fleet: {0}")]
    Fleet(String),
}

/// A fleet assignment rule (REQ-035): match a (vendor, type) pair to a fleet.
/// A `None` field is a wildcard (matches anything).
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub struct FleetRule {
    pub vendor: Option<String>,
    pub device_type: Option<String>,
    pub fleet_id: String,
}

/// A data-driven fleet assignment policy (REQ-035): ordered rules, first
/// match wins, with a default fallback fleet.
#[derive(Debug, Clone, PartialEq)]
#[links_to("REQ-035", component = "ARCH-PROVISIONING")]
pub struct FleetPolicy {
    rules: Vec<FleetRule>,
    default_fleet: String,
}

impl FleetPolicy {
    pub fn new(default_fleet: impl Into<String>) -> Self {
        Self {
            rules: Vec::new(),
            default_fleet: default_fleet.into(),
        }
    }

    /// Add a routing rule (evaluated in order; first match wins).
    pub fn add_rule(mut self, rule: FleetRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// The default fleet (when no rule matches).
    pub fn default_fleet(&self) -> &str {
        &self.default_fleet
    }

    /// Resolve the fleet for a (vendor, type) pair: first matching rule wins,
    /// else the default (REQ-035).
    pub fn resolve(&self, vendor: &str, device_type: &str) -> &str {
        for rule in &self.rules {
            let vendor_ok = rule
                .vendor
                .as_deref()
                .map(|v| v == vendor)
                .unwrap_or(true);
            let type_ok = rule
                .device_type
                .as_deref()
                .map(|t| t == device_type)
                .unwrap_or(true);
            if vendor_ok && type_ok {
                return &rule.fleet_id;
            }
        }
        &self.default_fleet
    }
}

/// A provisioning workflow (REQ-034/035): reacts to discovery events to
/// register the device, bind its driver, and assign it to a fleet per the
/// policy.
#[links_to("REQ-034", component = "ARCH-PROVISIONING")]
#[links_to("REQ-035", component = "ARCH-PROVISIONING")]
pub struct Provisioner {
    catalog: CatalogService,
    fleets: FleetManager,
    drivers: DriverRegistry,
    policy: FleetPolicy,
    /// The stream subscription (call `attach` before discovery publishes).
    receiver: Option<tokio::sync::broadcast::Receiver<MetricEvent>>,
}

impl Provisioner {
    pub fn new(
        catalog: CatalogService,
        fleets: FleetManager,
        drivers: DriverRegistry,
        policy: FleetPolicy,
    ) -> Self {
        Self {
            catalog,
            fleets,
            drivers,
            policy,
            receiver: None,
        }
    }

    /// The assignment policy (REQ-035).
    pub fn policy(&self) -> &FleetPolicy {
        &self.policy
    }

    /// Subscribe to the metric stream (call before discovery publishes).
    pub fn attach(&mut self, stream: &MetricStream) {
        self.receiver = Some(stream.subscribe());
    }

    /// React to a discovery event: register, bind driver, assign per policy
    /// (REQ-034/035).
    pub async fn handle_discovered(
        &self,
        event: &MetricEvent,
    ) -> Result<Provisioned, ProvisionError> {
        let (vendor, device_type) = match &event.kind {
            MetricKind::DeviceDiscovered { vendor, device_type } => {
                (vendor.clone(), device_type.clone())
            }
            _ => return Err(ProvisionError::NotADiscoveryEvent),
        };

        // REQ-035: resolve the fleet via the data-driven policy.
        let fleet_id = self.policy.resolve(&vendor, &device_type).to_string();

        // 1. Register the device in the catalog.
        let device = Device {
            id: event.device.clone(),
            name: format!("{} {}", device_type, vendor),
            device_type: device_type.clone(),
            vendor: vendor.clone(),
            status: "active".into(),
            fleet_ids: vec![fleet_id.clone()],
            metadata: serde_json::json!({ "discovered_via": "edge" }),
        };
        let created = self
            .catalog
            .create_device(device)
            .await
            .map_err(|e| ProvisionError::Catalog(e.to_string()))?;

        // 2. Bind (verify) the driver for the device.
        let driver_bound = self
            .drivers
            .resolve(&created.device_type, &created.vendor)
            .is_ok();

        // 3. Assign the device to the resolved fleet.
        self.fleets
            .add_to_fleet(&created.id, &fleet_id)
            .await
            .map_err(|e| ProvisionError::Fleet(e.to_string()))?;

        Ok(Provisioned {
            device_id: created.id,
            fleet_id,
            driver_bound,
        })
    }

    /// Process pending discovery events (non-blocking), provisioning each
    /// (REQ-034). Returns the devices provisioned in this cycle. Used for
    /// a single, testable loop cycle.
    pub async fn drain(&mut self) -> Vec<Provisioned> {
        let mut pending = Vec::new();
        if let Some(rx) = &mut self.receiver {
            while let Ok(event) = rx.try_recv() {
                pending.push(event);
            }
        }
        let mut provisioned = Vec::new();
        for event in pending {
            if matches!(event.kind, MetricKind::DeviceDiscovered { .. }) {
                if let Ok(p) = self.handle_discovered(&event).await {
                    provisioned.push(p);
                }
            }
        }
        provisioned
    }

    /// The infinite consumer loop (REQ-034): process events until the stream
    /// has no more senders.
    pub async fn run(&mut self) {
        loop {
            let event = {
                let Some(rx) = &mut self.receiver else {
                    return;
                };
                rx.recv().await
            };
            let Ok(event) = event else {
                return;
            };
            if matches!(event.kind, MetricKind::DeviceDiscovered { .. }) {
                let _ = self.handle_discovered(&event).await;
            }
        }
    }
}
