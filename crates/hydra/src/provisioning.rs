//! Provisioning workflow (REQ-034, ARCH-PROVISIONING).
//!
//! A data-plane **consumer**: reacts to `DeviceDiscovered` events on the
//! metric stream and drives the provisioning workflow — register the device,
//! bind its driver, assign it to a fleet. Fleet assignment lives *here*
//! (the policy), not in discovery — discovery stays fleet-agnostic.

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

/// A provisioning workflow (REQ-034): reacts to discovery events to register
/// the device, bind its driver, and assign it to the policy fleet.
#[links_to("REQ-034", component = "ARCH-PROVISIONING")]
pub struct Provisioner {
    catalog: CatalogService,
    fleets: FleetManager,
    drivers: DriverRegistry,
    /// The fleet to assign newly discovered devices to (the policy).
    fleet_id: String,
}

impl Provisioner {
    pub fn new(
        catalog: CatalogService,
        fleets: FleetManager,
        drivers: DriverRegistry,
        fleet_id: impl Into<String>,
    ) -> Self {
        Self {
            catalog,
            fleets,
            drivers,
            fleet_id: fleet_id.into(),
        }
    }

    /// The fleet this provisioner assigns discovered devices to (the policy).
    pub fn fleet_id(&self) -> &str {
        &self.fleet_id
    }

    /// React to a discovery event: register the device, bind its driver, and
    /// assign it to the fleet (REQ-034).
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

        // 1. Register the device in the catalog.
        let device = Device {
            id: event.device.clone(),
            name: format!("{} {}", device_type, vendor),
            device_type: device_type.clone(),
            vendor: vendor.clone(),
            status: "active".into(),
            fleet_ids: vec![self.fleet_id.clone()],
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

        // 3. Assign the device to the fleet (the policy).
        self.fleets
            .add_to_fleet(&created.id, &self.fleet_id)
            .await
            .map_err(|e| ProvisionError::Fleet(e.to_string()))?;

        Ok(Provisioned {
            device_id: created.id,
            fleet_id: self.fleet_id.clone(),
            driver_bound,
        })
    }

    /// The consumer loop (REQ-034): subscribe to the stream and react to
    /// `DeviceDiscovered` events. Runs until the stream has no more senders.
    pub async fn run(&self, stream: &MetricStream) {
        let mut rx = stream.subscribe();
        while let Ok(event) = rx.recv().await {
            if matches!(event.kind, MetricKind::DeviceDiscovered { .. }) {
                let _ = self.handle_discovered(&event).await;
            }
        }
    }
}
