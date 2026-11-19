//! Driver abstraction (ARCH-DRIVERS).
//!
//! REQ-009/010 — config read/write; REQ-011 — heterogeneous vendors.

use std::collections::BTreeMap;

use mbse::links_to;
use mbse::mbse_exempt;

/// Vendor-normalized device configuration (REQ-009 / REQ-010).
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[mbse_exempt("data type — not a model node")]
pub struct DeviceConfig {
    pub values: BTreeMap<String, serde_json::Value>,
}

impl DeviceConfig {
    pub fn with(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.values.insert(key.into(), value);
        self
    }
}

/// A single telemetry metric reading from a device (REQ-013 / REQ-026).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[mbse_exempt("data type — not a model node")]
pub struct DeviceMetric {
    pub name: String,
    pub value: f64,
}

/// A class of operation a driver can perform on a device (REQ-018).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[mbse_exempt("data type — not a model node")]
pub enum DriverOp {
    /// Observe: telemetry / health.
    Telemetry,
    /// Read the device configuration.
    ConfigRead,
    /// Write the device configuration.
    ConfigWrite,
    /// Execute a named command (reboot, factory reset, ...).
    Command,
}

/// The fidelity a driver offers: which `DriverOp`s it supports (REQ-018).
#[derive(Debug, Clone, PartialEq)]
#[links_to("REQ-018", component = "ARCH-DRIVERS")]
pub struct DriverCapabilities {
    ops: std::collections::BTreeSet<DriverOp>,
}

impl DriverCapabilities {
    pub fn new(ops: impl IntoIterator<Item = DriverOp>) -> Self {
        Self {
            ops: ops.into_iter().collect(),
        }
    }

    /// Fidelity floor: the device can be observed, not controlled.
    pub fn telemetry_only() -> Self {
        Self::new([DriverOp::Telemetry])
    }

    /// Full fidelity: observe, read, write, command.
    pub fn full() -> Self {
        Self::new([
            DriverOp::Telemetry,
            DriverOp::ConfigRead,
            DriverOp::ConfigWrite,
            DriverOp::Command,
        ])
    }

    /// Does this fidelity include the operation? (REQ-018)
    pub fn supports(&self, op: DriverOp) -> bool {
        self.ops.contains(&op)
    }

    /// The supported operations, in a stable order.
    pub fn ops(&self) -> Vec<DriverOp> {
        self.ops.iter().copied().collect()
    }
}

/// Device reachability as seen through a driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[mbse_exempt("data type — not a model node")]
pub enum HealthState {
    Online,
    Offline,
}

/// Driver communication failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum DriverError {
    #[error("communication with the device timed out (P-DRIVER-TIMEOUT)")]
    Timeout,
    #[error("device unreachable")]
    Unreachable,
    #[error("no driver registered for {device_type}/{vendor}")]
    NotResolved { device_type: String, vendor: String },
    #[error("driver registry at slot capacity")]
    CapacityExceeded,
    #[error("device rejected the configuration: {0}")]
    Rejected(String),
}

/// A driver adapts one heterogeneous device type/vendor to the common
/// Hydra config interface (REQ-011).
#[links_to("REQ-009", component = "ARCH-DRIVERS")]
#[links_to("REQ-010", component = "ARCH-DRIVERS")]
#[links_to("REQ-011", component = "ARCH-DRIVERS")]
#[links_to("REQ-018", component = "ARCH-DRIVERS")]
#[links_to("REQ-026", component = "ARCH-DRIVERS")]
#[async_trait::async_trait]
pub trait Driver: Send + Sync {
    /// Device type this driver speaks (`"plc"`, `"switch"`, ...).
    fn device_type(&self) -> &'static str;
    /// Vendor this driver adapts (`"acme"`, `"siemens"`, ...).
    fn vendor(&self) -> &'static str;

    /// Retrieve the device configuration (REQ-009).
    async fn get_config(&self) -> Result<DeviceConfig, DriverError>;

    /// Read the device's current telemetry metrics (REQ-026).
    ///
    /// This is the driver-side of the telemetry fidelity op (REQ-018): it is
    /// what makes `DriverOp::Telemetry` — and the `telemetry_only()` fidelity
    /// floor — actually exercisable. Drivers without that fidelity must
    /// reject. Returns `Unreachable` when the device is offline (CONOPS-004).
    async fn telemetry(&self) -> Result<Vec<DeviceMetric>, DriverError>;

    /// Set the device configuration (REQ-010).
    async fn set_config(&self, config: &DeviceConfig) -> Result<(), DriverError>;

    /// Execute a named command on the device (reboot, factory reset, ...).
    /// Meaningful only when `capabilities()` includes `DriverOp::Command`
    /// (REQ-018); drivers without that fidelity must reject.
    async fn command(&self, name: &str) -> Result<serde_json::Value, DriverError>;

    /// The fidelity this driver offers: which operations it supports (REQ-018).
    fn capabilities(&self) -> DriverCapabilities;

    /// Probe reachability.
    async fn health(&self) -> HealthState;
}
