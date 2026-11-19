//! Fleet flows (CONOPS-003): operator-driven operations across a fleet.
//!
//! The system applies one operation to **every device in a fleet**, honoring
//! each device's driver fidelity (REQ-018): a device whose driver cannot
//! perform the operation is reported as `RejectedFidelity` — never silently
//! skipped — and every attempt is recorded in the data-plane audit log
//! (REQ-036/037).

use std::collections::{BTreeMap, BTreeSet};

use hydra_audit::AuditDomain;
use hydra_catalog::DeviceFilters;
use hydra_drivers::{DeviceConfig, DriverOp};

use crate::system::HydraSystem;

use mbse::links_to;
use mbse::mbse_exempt;

/// An operator-driven operation to apply across a fleet (CONOPS-003).
#[derive(Debug, Clone, PartialEq)]
#[links_to("REQ-010", component = "ARCH-SYS-MGMT")]
#[links_to("REQ-018", component = "ARCH-SYS-MGMT")]
pub enum FleetFlowOp {
    /// Set device configuration values (REQ-010: write the fleet's config).
    SetConfig { values: BTreeMap<String, serde_json::Value> },
    /// Execute a named command (reboot, factory reset, ...).
    Command { name: String },
}

impl FleetFlowOp {
    /// The driver operation this flow requires (the fidelity gate, REQ-018).
    pub fn required_op(&self) -> DriverOp {
        match self {
            FleetFlowOp::SetConfig { .. } => DriverOp::ConfigWrite,
            FleetFlowOp::Command { .. } => DriverOp::Command,
        }
    }

    /// The audit action name for this flow.
    pub fn action_name(&self) -> &'static str {
        match self {
            FleetFlowOp::SetConfig { .. } => "fleet:set-config",
            FleetFlowOp::Command { .. } => "fleet:command",
        }
    }
}

/// The per-device outcome of a fleet flow (REQ-018 fidelity is explicit).
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub enum FlowResult {
    /// The operation was applied on the device.
    Applied,
    /// The device's driver lacks the required fidelity (REQ-018) — rejected
    /// by design, not an error.
    RejectedFidelity { required: DriverOp },
    /// No driver was registered for the device's vendor/type.
    NoDriver,
    /// The operation was applied but failed (device offline, rejected, ...).
    Error(String),
}

/// The outcome of a fleet flow for one device.
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub struct FlowOutcome {
    pub device_id: String,
    pub vendor: String,
    pub device_type: String,
    pub result: FlowResult,
}

impl HydraSystem {
    /// CONOPS-003: apply a fleet flow to every device in `fleet_id`.
    ///
    /// For each device: resolve its driver, gate on the driver's fidelity
    /// (REQ-018), apply the operation, and record the attempt in the
    /// data-plane audit log (REQ-036). Devices whose driver lacks the
    /// required fidelity are reported, not skipped.
    pub async fn dispatch_fleet_flow(
        &mut self,
        fleet_id: &str,
        op: &FleetFlowOp,
    ) -> Vec<FlowOutcome> {
        // Devices in the fleet (dedupe: a device in several fleets appears
        // once in the fleet JOIN).
        let mut devices = self
            .catalog
            .list_devices(DeviceFilters {
                fleet_id: Some(fleet_id.to_string()),
                ..Default::default()
            })
            .await
            .unwrap_or_default();
        let mut seen = BTreeSet::new();
        devices.retain(|d| seen.insert(d.id.clone()));

        let mut outcomes = Vec::new();
        for dev in devices {
            let (result, audit_result) = match self.comm.registry().resolve(&dev.device_type, &dev.vendor)
            {
                Err(_) => (
                    FlowResult::NoDriver,
                    "error: no driver matched".to_string(),
                ),
                Ok(driver) if !driver.capabilities().supports(op.required_op()) => {
                    let required = op.required_op();
                    (
                        FlowResult::RejectedFidelity { required },
                        format!("error: fidelity — driver does not support {required:?}"),
                    )
                }
                Ok(driver) => {
                    let err = match op {
                        FleetFlowOp::SetConfig { values } => driver
                            .set_config(&DeviceConfig {
                                values: values.clone(),
                            })
                            .await
                            .err(),
                        FleetFlowOp::Command { name } => driver.command(name).await.err(),
                    };
                    match err {
                        None => (FlowResult::Applied, "ok".to_string()),
                        Some(e) => (FlowResult::Error(e.to_string()), format!("error: {e}")),
                    }
                }
            };

            // Record the attempt, success or not (REQ-036, data domain).
            let _ = self
                .audit
                .append(
                    AuditDomain::DataPlane,
                    "operator",
                    op.action_name(),
                    &format!("devices/{}", dev.id),
                    fleet_id,
                    &audit_result,
                )
                .await;

            outcomes.push(FlowOutcome {
                device_id: dev.id,
                vendor: dev.vendor,
                device_type: dev.device_type,
                result,
            });
        }
        outcomes
    }
}
