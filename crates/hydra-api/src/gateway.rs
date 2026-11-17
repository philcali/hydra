//! API gateway: the REQ-004 device-management surface, split by plane.
//!
//! The control/data split (fixing the "gateway conflation"):
//! - `ApiGateway` — **control plane** (ARCH-CTRL-GW): stateless management
//!   ops (catalog + fleet). Deliberately no device/driver access.
//! - `DataPlaneGateway` — **data plane** (ARCH-DATA-GW): device ops through
//!   their drivers, with fidelity enforcement (REQ-018). Scales independently.
//!
//! Audit (REQ-036/REQ-037): every request — allowed, denied, or failed — is
//! appended to the domain-scoped, hash-chained audit log: control-plane
//! actions into the control domain ("who did what"), data-plane operations
//! into the data domain ("what happened to which device"). The log is
//! queryable through the gateway (REQ-039) and lives on the pluggable
//! durable store configured at startup (REQ-038).

use hydra_audit::{AuditEngine, AuditDomain, AuditFilters};
use hydra_auth::{AuthService, Decision};
use hydra_catalog::{CatalogService, Device, DeviceFilters, DeviceUpdates, FleetManager};
use hydra_discovery::DiscoveryConfigStore;
use hydra_drivers::{DeviceComm, DriverError, DriverOp};

use mbse::links_to;
use mbse::mbse_exempt;

/// A control-plane management operation (REQ-004, ARCH-CTRL-GW).
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub enum Operation {
    ListDevices,
    GetDevice { id: String },
    CreateDevice {
        name: String,
        device_type: String,
        vendor: String,
    },
    SetDeviceStatus { id: String, status: String },
    AddToFleet { device_id: String, fleet_id: String },
    /// Create or update a discovery configuration resource (REQ-032).
    SetDiscoveryConfig { config: hydra_discovery::DiscoveryConfig },
    /// Read a discovery configuration resource (REQ-032).
    GetDiscoveryConfig { id: String },
    /// List discovery configuration resources (REQ-032).
    ListDiscoveryConfigs,
}

impl Operation {
    /// The ACL action for this operation.
    pub fn action(&self) -> &'static str {
        match self {
            Operation::ListDevices => "catalog:list",
            Operation::GetDevice { .. } => "catalog:get",
            Operation::CreateDevice { .. } => "catalog:create",
            Operation::SetDeviceStatus { .. } => "catalog:update",
            Operation::AddToFleet { .. } => "fleet:join",
            Operation::SetDiscoveryConfig { .. } => "discovery:set",
            Operation::GetDiscoveryConfig { .. } => "discovery:get",
            Operation::ListDiscoveryConfigs => "discovery:list",
        }
    }

    /// The ACL resource for this operation.
    pub fn resource(&self) -> String {
        match self {
            Operation::ListDevices => "catalog/devices".into(),
            Operation::GetDevice { id } => format!("catalog/devices/{id}"),
            Operation::CreateDevice { .. } => "catalog/devices".into(),
            Operation::SetDeviceStatus { id, .. } => format!("catalog/devices/{id}"),
            Operation::AddToFleet { fleet_id, .. } => format!("fleet/{fleet_id}"),
            Operation::SetDiscoveryConfig { config } => format!("discovery/{}", config.id),
            Operation::GetDiscoveryConfig { id } => format!("discovery/{id}"),
            Operation::ListDiscoveryConfigs => "discovery".into(),
        }
    }
}

/// A data-plane device operation (REQ-004, ARCH-DATA-GW), executed through
/// the device's driver with fidelity enforcement (REQ-018).
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub enum DeviceOperation {
    /// Read the live device configuration (REQ-018: requires `ConfigRead`).
    GetDeviceConfig { id: String },
    /// Write the live device configuration (REQ-018: requires `ConfigWrite`).
    SetDeviceConfig {
        id: String,
        values: serde_json::Map<String, serde_json::Value>,
    },
    /// Execute a command on the device (REQ-018: requires `Command`).
    RebootDevice { id: String },
}

impl DeviceOperation {
    /// The ACL action for this operation.
    pub fn action(&self) -> &'static str {
        match self {
            DeviceOperation::GetDeviceConfig { .. } => "device:get-config",
            DeviceOperation::SetDeviceConfig { .. } => "device:set-config",
            DeviceOperation::RebootDevice { .. } => "device:reboot",
        }
    }

    /// The driver fidelity this operation requires (REQ-018).
    pub fn required_fidelity(&self) -> DriverOp {
        match self {
            DeviceOperation::GetDeviceConfig { .. } => DriverOp::ConfigRead,
            DeviceOperation::SetDeviceConfig { .. } => DriverOp::ConfigWrite,
            DeviceOperation::RebootDevice { .. } => DriverOp::Command,
        }
    }

    /// The ACL resource for this operation.
    pub fn resource(&self) -> String {
        match self {
            DeviceOperation::GetDeviceConfig { id } => format!("devices/{id}/config"),
            DeviceOperation::SetDeviceConfig { id, .. } => format!("devices/{id}/config"),
            DeviceOperation::RebootDevice { id } => format!("devices/{id}"),
        }
    }
}

/// API failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum ApiError {
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("forbidden: {0}")]
    Forbidden(String),
    #[error("internal: {0}")]
    Internal(String),
    #[error("no driver for this device (type {0}, vendor {1})")]
    NoDriver(String, String),
    #[error("operation outside the device's driver fidelity: {0}")]
    NotSupported(String),
}

/// Control-plane API gateway (ARCH-CTRL-GW): stateless management ops (REQ-004).
///
/// Deliberately has **no** device/driver access — that is the data plane's
/// job (`DataPlaneGateway`), so the two planes can scale independently.
#[links_to("REQ-004", component = "ARCH-CTRL-GW")]
#[links_to("REQ-032", component = "ARCH-CTRL-GW")]
#[links_to("REQ-036", component = "ARCH-CTRL-GW")]
pub struct ApiGateway {
    auth: AuthService,
    catalog: CatalogService,
    fleets: FleetManager,
    /// Discovery configuration resources (REQ-032) — managed here, consumed
    /// by the data plane.
    config_store: DiscoveryConfigStore,
    /// The cross-system audit service (REQ-036): every control-plane action
    /// is appended to the control domain of the immutable log.
    audit: AuditEngine,
    created: u64,
}

impl ApiGateway {
    pub fn new(
        auth: AuthService,
        catalog: CatalogService,
        fleets: FleetManager,
        config_store: DiscoveryConfigStore,
        audit: AuditEngine,
    ) -> Self {
        Self {
            auth,
            catalog,
            fleets,
            config_store,
            audit,
            created: 0,
        }
    }

    /// Handle a control-plane request: authenticate → authorize → execute →
    /// audit (REQ-004/REQ-036). Denied and failed requests are audited
    /// too — with the failure as the outcome — so the log is a complete
    /// account of what was attempted.
    pub async fn handle(
        &mut self,
        token: &str,
        op: Operation,
        now_epoch: u64,
    ) -> Result<serde_json::Value, ApiError> {
        let action = op.action().to_string();
        let resource = op.resource();

        let identity = match self.auth.authenticate(token, now_epoch).await {
            Ok(identity) => identity,
            Err(e) => {
                self.audit
                    .append(
                        AuditDomain::ControlPlane,
                        "anonymous",
                        &action,
                        &resource,
                        "via control plane",
                        &format!("unauthorized: {e}"),
                    )
                    .await
                    .ok();
                return Err(ApiError::Unauthorized(e.to_string()));
            }
        };

        if self.auth.authorize(&identity, &action, &resource) != Decision::Allow {
            tracing::warn!(principal = %identity.principal, action = %action, "request forbidden by ACL");
            self.audit
                .append(
                    AuditDomain::ControlPlane,
                    &identity.principal,
                    &action,
                    &resource,
                    "via control plane",
                    &format!("denied: {action} on {resource}"),
                )
                .await
                .ok();
            return Err(ApiError::Forbidden(format!("{action} on {resource}")));
        }

        let result = match self.execute(&op).await {
            Ok(value) => {
                self.audit
                    .append(
                        AuditDomain::ControlPlane,
                        &identity.principal,
                        &action,
                        &resource,
                        "via control plane",
                        "ok",
                    )
                    .await
                    .ok();
                value
            }
            Err(e) => {
                self.audit
                    .append(
                        AuditDomain::ControlPlane,
                        &identity.principal,
                        &action,
                        &resource,
                        "via control plane",
                        &format!("error: {e}"),
                    )
                    .await
                    .ok();
                return Err(e);
            }
        };

        Ok(result)
    }

    /// The audit service (REQ-036/039): records can be verified or
    /// queried by domain, actor, action, resource, and time range.
    pub fn audit(&self) -> &AuditEngine {
        &self.audit
    }

    /// Query the control-plane audit log (REQ-039).
    pub async fn audit_query(&self, filters: &AuditFilters) -> Result<Vec<hydra_audit::AuditRecord>, hydra_audit::AuditError> {
        self.audit.query(filters).await
    }

    async fn execute(&mut self, op: &Operation) -> Result<serde_json::Value, ApiError> {
        match op {
            Operation::ListDevices => {
                let devices = self
                    .catalog
                    .list_devices(DeviceFilters::default())
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(serde_json::to_value(&devices).unwrap_or_default())
            }
            Operation::GetDevice { id } => {
                let device = self
                    .catalog
                    .get_device(id)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?
                    .ok_or_else(|| ApiError::Internal(format!("no such device: {id}")))?;
                Ok(serde_json::to_value(&device).unwrap_or_default())
            }
            Operation::CreateDevice { name, device_type, vendor } => {
                self.created += 1;
                let ns = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                let device = Device {
                    id: format!("dev-{}-{}-{}", std::process::id(), ns, self.created),
                    name: name.clone(),
                    device_type: device_type.clone(),
                    vendor: vendor.clone(),
                    status: "active".into(),
                    fleet_ids: vec![],
                    metadata: serde_json::json!({}),
                };
                let created = self
                    .catalog
                    .create_device(device)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(serde_json::to_value(&created).unwrap_or_default())
            }
            Operation::SetDeviceStatus { id, status } => {
                let updates = DeviceUpdates {
                    status: Some(status.clone()),
                    ..Default::default()
                };
                let updated = self
                    .catalog
                    .update_device(id, updates)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(serde_json::to_value(&updated).unwrap_or_default())
            }
            Operation::AddToFleet { device_id, fleet_id } => {
                self.fleets
                    .add_to_fleet(device_id, fleet_id)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(serde_json::json!({ "device_id": device_id, "fleet_id": fleet_id, "joined": true }))
            }
            // REQ-032: discovery configurations as first-class resources.
            Operation::SetDiscoveryConfig { config } => {
                let stored = self.config_store.upsert(config.clone());
                Ok(serde_json::to_value(&stored).unwrap_or_default())
            }
            Operation::GetDiscoveryConfig { id } => {
                let config = self
                    .config_store
                    .get(id)
                    .ok_or_else(|| ApiError::Internal(format!("no such discovery config: {id}")))?;
                Ok(serde_json::to_value(&config).unwrap_or_default())
            }
            Operation::ListDiscoveryConfigs => {
                Ok(serde_json::to_value(&self.config_store.list()).unwrap_or_default())
            }
        }
    }
}

/// Data-plane gateway (ARCH-DATA-GW): device ops through their drivers
/// (REQ-004), with fidelity enforcement (REQ-018).
///
/// This is the "talk to the device" surface — separate from the stateless
/// control plane, so it can scale independently.
#[links_to("REQ-004", component = "ARCH-DATA-GW")]
#[links_to("REQ-018", component = "ARCH-DATA-GW")]
#[links_to("REQ-037", component = "ARCH-DATA-GW")]
pub struct DataPlaneGateway {
    auth: AuthService,
    catalog: CatalogService,
    comm: DeviceComm,
    /// The cross-system audit service (REQ-037): every device operation —
    /// successful or failed — is appended to the data domain.
    audit: AuditEngine,
}

impl DataPlaneGateway {
    pub fn new(
        auth: AuthService,
        catalog: CatalogService,
        comm: DeviceComm,
        audit: AuditEngine,
    ) -> Self {
        Self {
            auth,
            catalog,
            comm,
            audit,
        }
    }

    /// Handle a data-plane request: authenticate → authorize → execute →
    /// audit (REQ-004/REQ-037), with fidelity enforcement (REQ-018).
    /// Denied and failed operations are audited too — the log must account
    /// for what was attempted on each device, not just what succeeded.
    pub async fn handle(
        &mut self,
        token: &str,
        op: DeviceOperation,
        now_epoch: u64,
    ) -> Result<serde_json::Value, ApiError> {
        let action = op.action().to_string();
        let resource = op.resource();

        let identity = match self.auth.authenticate(token, now_epoch).await {
            Ok(identity) => identity,
            Err(e) => {
                self.audit
                    .append(
                        AuditDomain::DataPlane,
                        "anonymous",
                        &action,
                        &resource,
                        "via data plane",
                        &format!("unauthorized: {e}"),
                    )
                    .await
                    .ok();
                return Err(ApiError::Unauthorized(e.to_string()));
            }
        };

        if self.auth.authorize(&identity, &action, &resource) != Decision::Allow {
            tracing::warn!(principal = %identity.principal, action = %action, "request forbidden by ACL");
            self.audit
                .append(
                    AuditDomain::DataPlane,
                    &identity.principal,
                    &action,
                    &resource,
                    "via data plane",
                    &format!("denied: {action} on {resource}"),
                )
                .await
                .ok();
            return Err(ApiError::Forbidden(format!("{action} on {resource}")));
        }

        let result = match self.execute(&op).await {
            Ok(value) => {
                self.audit
                    .append(
                        AuditDomain::DataPlane,
                        &identity.principal,
                        &action,
                        &resource,
                        "via data plane",
                        "ok",
                    )
                    .await
                    .ok();
                value
            }
            Err(e) => {
                self.audit
                    .append(
                        AuditDomain::DataPlane,
                        &identity.principal,
                        &action,
                        &resource,
                        "via data plane",
                        &format!("error: {e}"),
                    )
                    .await
                    .ok();
                return Err(e);
            }
        };

        Ok(result)
    }

    /// The audit service (REQ-037/039): device operations can be verified
    /// or queried by domain, actor, action, resource, and time range.
    pub fn audit(&self) -> &AuditEngine {
        &self.audit
    }

    /// Query the data-plane audit log (REQ-039).
    pub async fn audit_query(&self, filters: &AuditFilters) -> Result<Vec<hydra_audit::AuditRecord>, hydra_audit::AuditError> {
        self.audit.query(filters).await
    }

    async fn execute(&mut self, op: &DeviceOperation) -> Result<serde_json::Value, ApiError> {
        match op {
            DeviceOperation::GetDeviceConfig { id } => {
                let (device_type, vendor) = self.device_coordinates(id).await?;
                self.require_fidelity(&device_type, &vendor, op.required_fidelity())?;
                let config = self
                    .comm
                    .get_config(&device_type, &vendor)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(serde_json::to_value(&config).unwrap_or_default())
            }
            DeviceOperation::SetDeviceConfig { id, values } => {
                let (device_type, vendor) = self.device_coordinates(id).await?;
                self.require_fidelity(&device_type, &vendor, op.required_fidelity())?;
                let config = hydra_drivers::DeviceConfig {
                    values: values.clone().into_iter().collect(),
                };
                self.comm
                    .set_config(&device_type, &vendor, &config)
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(serde_json::json!({ "device_id": id, "values": values, "applied": true }))
            }
            DeviceOperation::RebootDevice { id } => {
                let (device_type, vendor) = self.device_coordinates(id).await?;
                self.require_fidelity(&device_type, &vendor, op.required_fidelity())?;
                let result = self
                    .comm
                    .command(&device_type, &vendor, "reboot")
                    .await
                    .map_err(|e| ApiError::Internal(e.to_string()))?;
                Ok(result)
            }
        }
    }

    /// The (device_type, vendor) coordinates of a catalog device.
    async fn device_coordinates(&self, id: &str) -> Result<(String, String), ApiError> {
        let device = self
            .catalog
            .get_device(id)
            .await
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::Internal(format!("no such device: {id}")))?;
        Ok((device.device_type, device.vendor))
    }

    /// REQ-018: the operation must be within the device driver's fidelity.
    fn require_fidelity(
        &self,
        device_type: &str,
        vendor: &str,
        op: DriverOp,
    ) -> Result<(), ApiError> {
        match self.comm.registry().resolve(device_type, vendor) {
            Ok(driver) => {
                if driver.capabilities().supports(op) {
                    Ok(())
                } else {
                    Err(ApiError::NotSupported(format!("{op:?}")))
                }
            }
            Err(DriverError::NotResolved { .. }) => Err(ApiError::NoDriver(
                device_type.to_string(),
                vendor.to_string(),
            )),
            Err(e) => Err(ApiError::Internal(e.to_string())),
        }
    }
}
