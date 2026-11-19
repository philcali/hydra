//! Hydra driver framework (ARCH-DRIVERS).
//!
//! Maps to MBSE architecture:
//! - REQ-009 — retrieving device configuration
//! - REQ-010 — setting device configuration
//! - REQ-011 — communicating with heterogeneous device types and vendors
//! - REQ-012 — operation degradation when programmatic control is unavailable
//! - REQ-018 — per-driver fidelity: which operations a device supports
//! - P-DRIVER-TIMEOUT (parameter)

mbse_graph::collect_test!();

pub mod bus;
pub mod degradation;
pub mod driver;
pub mod registry;
pub mod sim;

pub use bus::DeviceComm;
pub use degradation::{DegradationManager, DegradationState, FallbackAction};
pub use driver::{
    DeviceConfig, DeviceMetric, Driver, DriverCapabilities, DriverError, DriverOp, HealthState,
};
pub use registry::DriverRegistry;
pub use sim::{ModbusDriver, OpcUaDriver, SensorDriver, SimDevice};

#[cfg(test)]
mod tests;
