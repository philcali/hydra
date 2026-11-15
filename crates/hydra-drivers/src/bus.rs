//! Device communication bus (REQ-009 / REQ-010), enforcing
//! P-DRIVER-TIMEOUT on every driver call.

use std::sync::Arc;
use std::time::Duration;

use crate::driver::{DeviceConfig, Driver, DriverError};
use crate::registry::DriverRegistry;

use mbse::links_to;

/// Maximum driver communication timeout before degradation activates
/// (P-DRIVER-TIMEOUT, bounded by REQ-012). Enforced by `DeviceComm`.
#[links_to("REQ-012", parameter = "P-DRIVER-TIMEOUT", value = 3000.0)]
pub const DRIVER_TIMEOUT_MS: u64 = 3000;

/// Communication bus: resolves the right driver (REQ-011) and enforces
/// P-DRIVER-TIMEOUT on config read (REQ-009) / write (REQ-010).
#[links_to("REQ-009", component = "ARCH-DRIVERS")]
#[links_to("REQ-010", component = "ARCH-DRIVERS")]
pub struct DeviceComm {
    registry: DriverRegistry,
    timeout_ms: u64,
}

impl DeviceComm {
    pub fn new(registry: DriverRegistry) -> Self {
        Self {
            registry,
            timeout_ms: DRIVER_TIMEOUT_MS,
        }
    }

    /// Override the timeout (default `DRIVER_TIMEOUT_MS`).
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Retrieve a device's configuration (REQ-009), under P-DRIVER-TIMEOUT.
    pub async fn get_config(&self, device_type: &str, vendor: &str) -> Result<DeviceConfig, DriverError> {
        let driver: Arc<dyn Driver> = self.registry.resolve(device_type, vendor)?;
        self.with_timeout_guard(driver.get_config()).await
    }

    /// Set a device's configuration (REQ-010), under P-DRIVER-TIMEOUT.
    pub async fn set_config(
        &self,
        device_type: &str,
        vendor: &str,
        config: &DeviceConfig,
    ) -> Result<(), DriverError> {
        let driver: Arc<dyn Driver> = self.registry.resolve(device_type, vendor)?;
        self.with_timeout_guard(driver.set_config(config)).await
    }

    /// The registry behind this bus (for status reporting).
    pub fn registry(&self) -> &DriverRegistry {
        &self.registry
    }

    /// Execute a named command on a device (REQ-018: meaningful only for
    /// drivers whose fidelity includes `DriverOp::Command`), under
    /// P-DRIVER-TIMEOUT.
    pub async fn command(
        &self,
        device_type: &str,
        vendor: &str,
        name: &str,
    ) -> Result<serde_json::Value, DriverError> {
        let driver: Arc<dyn Driver> = self.registry.resolve(device_type, vendor)?;
        self.with_timeout_guard(driver.command(name)).await
    }

    async fn with_timeout_guard<T>(&self, work: impl std::future::Future<Output = Result<T, DriverError>>)
        -> Result<T, DriverError>
    {
        match tokio::time::timeout(Duration::from_millis(self.timeout_ms), work).await {
            Ok(result) => result,
            Err(_) => Err(DriverError::Timeout),
        }
    }
}
