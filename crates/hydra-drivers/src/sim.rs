//! Simulated device backends with two heterogeneous vendor drivers
//! (REQ-011): same logical device, different wire formats.
//!
//! `SimDevice` models a real device: it has a communication latency and
//! can drop out (→ REQ-012 degradation path).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::driver::{
    DeviceConfig, DeviceMetric, Driver, DriverCapabilities, DriverError, DriverOp, HealthState,
};

use mbse::links_to;
use mbse::mbse_exempt;

/// A simulated device on the wire.
#[derive(Debug, Default)]
#[mbse_exempt("test double — not a model node")]
pub struct SimDevice {
    pub latency_ms: u64,
    pub online: std::sync::Mutex<bool>,
    /// Raw vendor-specific state, as the vendor's protocol exposes it.
    pub raw: std::sync::Mutex<BTreeMap<String, serde_json::Value>>,
}

impl SimDevice {
    pub fn new(latency_ms: u64) -> Self {
        Self {
            latency_ms,
            online: std::sync::Mutex::new(true),
            raw: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// Simulate a device drop (CONOPS-004: loss of communication).
    pub fn go_offline(&self) {
        *self.online.lock().unwrap() = false;
    }

    async fn respond<T>(&self, work: impl FnOnce() -> T) -> Result<T, DriverError> {
        if *self.online.lock().unwrap() {
            tokio::time::sleep(std::time::Duration::from_millis(self.latency_ms)).await;
            Ok(work())
        } else {
            Err(DriverError::Unreachable)
        }
    }
}

/// MODBUS-flavored driver (vendor `acme`, type `plc`).
///
/// Raw register map: `"reg:<name>" → value`, normalized to `<name>`.
#[links_to("REQ-011", component = "ARCH-DRIVERS")]
pub struct ModbusDriver {
    device: Arc<SimDevice>,
}

impl ModbusDriver {
    pub fn new(device: Arc<SimDevice>) -> Self {
        Self { device }
    }
}

#[async_trait::async_trait]
impl Driver for ModbusDriver {
    fn device_type(&self) -> &'static str {
        "plc"
    }

    fn vendor(&self) -> &'static str {
        "acme"
    }

    async fn get_config(&self) -> Result<DeviceConfig, DriverError> {
        let raw = self.device.respond(|| self.device.raw.lock().unwrap().clone()).await?;
        let values = raw
            .into_iter()
            .map(|(k, v)| (k.strip_prefix("reg:").unwrap_or(&k).to_string(), v))
            .collect();
        Ok(DeviceConfig { values })
    }

    async fn telemetry(&self) -> Result<Vec<DeviceMetric>, DriverError> {
        let raw = self.device.respond(|| self.device.raw.lock().unwrap().clone()).await?;
        Ok(raw
            .into_iter()
            .filter_map(|(k, v)| {
                let name = k.strip_prefix("reg:").unwrap_or(&k).to_string();
                v.as_f64().map(|value| DeviceMetric { name, value })
            })
            .collect())
    }

    async fn set_config(&self, config: &DeviceConfig) -> Result<(), DriverError> {
        self.device
            .respond({
                let device = self.device.clone();
                let values = config.values.clone();
                move || {
                    let mut raw = device.raw.lock().unwrap();
                    for (k, v) in values {
                        raw.insert(format!("reg:{k}"), v);
                    }
                }
            })
            .await?;
        Ok(())
    }

    async fn command(&self, name: &str) -> Result<serde_json::Value, DriverError> {
        match name {
            "reboot" => {
                self.device.respond(|| ()).await?;
                Ok(serde_json::json!({ "rebooted": true, "driver": "acme-modbus" }))
            }
            other => Err(DriverError::Rejected(format!("unknown command: {other}"))),
        }
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::full()
    }

    async fn health(&self) -> HealthState {
        if *self.device.online.lock().unwrap() {
            HealthState::Online
        } else {
            HealthState::Offline
        }
    }
}

/// OPC-UA-flavored driver (vendor `siemens`, type `plc`).
///
/// Raw node map: `"ns=<n>;<name>" → value`, normalized to `<name>` —
/// a different wire format adapted to the same interface (REQ-011).
#[links_to("REQ-011", component = "ARCH-DRIVERS")]
pub struct OpcUaDriver {
    device: Arc<SimDevice>,
}

impl OpcUaDriver {
    pub fn new(device: Arc<SimDevice>) -> Self {
        Self { device }
    }
}

#[async_trait::async_trait]
impl Driver for OpcUaDriver {
    fn device_type(&self) -> &'static str {
        "plc"
    }

    fn vendor(&self) -> &'static str {
        "siemens"
    }

    async fn get_config(&self) -> Result<DeviceConfig, DriverError> {
        let raw = self.device.respond(|| self.device.raw.lock().unwrap().clone()).await?;
        let values = raw
            .into_iter()
            .map(|(k, v)| {
                let name = k
                    .rsplit_once(';')
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_else(|| k.to_string());
                (name, v)
            })
            .collect();
        Ok(DeviceConfig { values })
    }

    async fn telemetry(&self) -> Result<Vec<DeviceMetric>, DriverError> {
        let raw = self.device.respond(|| self.device.raw.lock().unwrap().clone()).await?;
        Ok(raw
            .into_iter()
            .filter_map(|(k, v)| {
                let name = k
                    .rsplit_once(';')
                    .map(|(_, n)| n.to_string())
                    .unwrap_or_else(|| k.to_string());
                v.as_f64().map(|value| DeviceMetric { name, value })
            })
            .collect())
    }

    async fn set_config(&self, config: &DeviceConfig) -> Result<(), DriverError> {
        self.device
            .respond({
                let device = self.device.clone();
                let values = config.values.clone();
                move || {
                    let mut raw = device.raw.lock().unwrap();
                    for (k, v) in values {
                        raw.insert(format!("ns=1;{k}"), v);
                    }
                }
            })
            .await?;
        Ok(())
    }

    async fn command(&self, _name: &str) -> Result<serde_json::Value, DriverError> {
        // Fidelity ceiling: this driver offers config, not commands (REQ-018).
        Err(DriverError::Rejected(
            "siemens OPC-UA driver does not expose device commands".into(),
        ))
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::new([
            DriverOp::Telemetry,
            DriverOp::ConfigRead,
            DriverOp::ConfigWrite,
        ])
    }

    async fn health(&self) -> HealthState {
        if *self.device.online.lock().unwrap() {
            HealthState::Online
        } else {
            HealthState::Offline
        }
    }
}

/// Telemetry-only sensor driver (vendor `senselab`, type `sensor`) — the
/// fidelity floor (REQ-018): the device can be observed, but not
/// configured or commanded. Models a vendor whose driver is not (yet)
/// fully implemented.
#[links_to("REQ-018", component = "ARCH-DRIVERS")]
#[links_to("REQ-011", component = "ARCH-DRIVERS")]
pub struct SensorDriver {
    device: Arc<SimDevice>,
}

impl SensorDriver {
    pub fn new(device: Arc<SimDevice>) -> Self {
        Self { device }
    }
}

#[async_trait::async_trait]
impl Driver for SensorDriver {
    fn device_type(&self) -> &'static str {
        "sensor"
    }

    fn vendor(&self) -> &'static str {
        "senselab"
    }

    async fn get_config(&self) -> Result<DeviceConfig, DriverError> {
        Err(DriverError::Rejected(
            "senselab sensor is telemetry-only (REQ-018 fidelity floor)".into(),
        ))
    }

    /// The sensor's one supported operation (REQ-018 floor): read its metrics.
    async fn telemetry(&self) -> Result<Vec<DeviceMetric>, DriverError> {
        let raw = self.device.respond(|| self.device.raw.lock().unwrap().clone()).await?;
        Ok(raw
            .into_iter()
            .filter_map(|(k, v)| v.as_f64().map(|value| DeviceMetric { name: k, value }))
            .collect())
    }

    async fn set_config(&self, _config: &DeviceConfig) -> Result<(), DriverError> {
        Err(DriverError::Rejected(
            "senselab sensor is telemetry-only (REQ-018 fidelity floor)".into(),
        ))
    }

    async fn command(&self, _name: &str) -> Result<serde_json::Value, DriverError> {
        Err(DriverError::Rejected(
            "senselab sensor is telemetry-only (REQ-018 fidelity floor)".into(),
        ))
    }

    fn capabilities(&self) -> DriverCapabilities {
        DriverCapabilities::telemetry_only()
    }

    async fn health(&self) -> HealthState {
        if *self.device.online.lock().unwrap() {
            HealthState::Online
        } else {
            HealthState::Offline
        }
    }
}
