//! Driver-backed telemetry source (REQ-026) — `ARCH-TELEMETRY`.
//!
//! The bridge between the device/driver layer (ARCH-DRIVERS) and the
//! telemetry collector (ARCH-TELEMETRY). REQ-013's poll model needs a way to
//! pull **per-device** telemetry through the drivers; this source holds a
//! device→driver binding per registered device and reads each one's current
//! metrics, tagging them with the device id.
//!
//! This is what makes the `telemetry_only()` fidelity floor (REQ-018)
//! actually readable: a telemetry-only sensor now contributes its readings.

use std::sync::Arc;

use hydra_drivers::Driver;

use crate::collector::TelemetrySource;
use crate::stream::{now_ms, TelemetryPoint};

use mbse::links_to;
use mbse::mbse_exempt;

/// A registered device bound to the driver that reads it (REQ-026).
#[derive(Clone)]
#[mbse_exempt("data type — not a model node")]
pub struct DeviceBinding {
    pub device: String,
    pub driver: Arc<dyn Driver>,
}

impl std::fmt::Debug for DeviceBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceBinding")
            .field("device", &self.device)
            .field("driver", &"<Driver>")
            .finish()
    }
}

/// Per-device telemetry source backed by drivers (REQ-026).
#[links_to("REQ-026", component = "ARCH-TELEMETRY")]
pub struct DriverTelemetrySource {
    devices: Vec<DeviceBinding>,
}

impl DriverTelemetrySource {
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Bind a device id to its driver in place (called at onboarding, CONOPS-002).
    pub fn attach(&mut self, device: impl Into<String>, driver: Arc<dyn Driver>) {
        self.devices.push(DeviceBinding {
            device: device.into(),
            driver,
        });
    }

    /// Bind a device id to its driver, returning `self` for chaining.
    pub fn add(mut self, device: impl Into<String>, driver: Arc<dyn Driver>) -> Self {
        self.attach(device, driver);
        self
    }

    /// Number of devices bound for telemetry.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// The device ids currently bound, in binding order.
    pub fn devices(&self) -> Vec<&str> {
        self.devices.iter().map(|b| b.device.as_str()).collect()
    }
}

impl Default for DriverTelemetrySource {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl TelemetrySource for DriverTelemetrySource {
    /// Pull every bound device's current metrics through its driver (REQ-026).
    ///
    /// A device whose driver can't be reached (offline, CONOPS-004) is skipped
    /// so one degraded device doesn't block the others.
    async fn collect(&self) -> Vec<TelemetryPoint> {
        let mut points = Vec::new();
        for b in &self.devices {
            if let Ok(metrics) = b.driver.telemetry().await {
                for m in metrics {
                    points.push(TelemetryPoint {
                        device: b.device.clone(),
                        metric: m.name,
                        value: m.value,
                        ts_ms: now_ms(),
                    });
                }
            }
        }
        points
    }
}
