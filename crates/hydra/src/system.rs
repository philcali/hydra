//! The Hydra system (ARCH-SYS-MGMT): cluster configuration, health
//! monitoring, and scaling coordination across the services.

use std::sync::Arc;

use hydra_audit::AuditLog;
use hydra_auth::{AclEngine, AuthService, CertProvider, IdentityPool, OidcProvider};
use hydra_catalog::{CatalogService, DiscoveryInfo, FleetManager, SqliteStore};
use hydra_discovery::{DiscoveryService, DiscoveredDevice};
use hydra_drivers::{
    DegradationManager, DeviceComm, Driver, DriverRegistry, ModbusDriver, OpcUaDriver, SensorDriver,
    SimDevice,
};
use hydra_telemetry::{DriverTelemetrySource, MetricKind, MetricStream, TelemetryPoint, TelemetrySource};

use crate::provisioning::{FleetPolicy, Provisioner};

use mbse::links_to;
use mbse::mbse_exempt;

/// System configuration.
#[derive(Debug, Clone)]
#[mbse_exempt("data type — not a model node")]
pub struct HydraConfig {
    /// Durable store path shared by the catalog service and fleet manager.
    pub db_path: String,
    /// Discovery poll interval (bounded by P-DISCOVERY-INTERVAL).
    pub discovery_interval_ms: u64,
    /// Telemetry collection interval (bounded by P-TELEM-INTERVAL).
    pub telem_interval_ms: u64,
    /// Default OIDC issuer / audience for the control plane.
    pub oidc_issuer: String,
    pub oidc_audience: String,
}

impl Default for HydraConfig {
    fn default() -> Self {
        Self {
            db_path: "hydra.db".into(),
            discovery_interval_ms: hydra_discovery::engine::DISCOVERY_INTERVAL_S * 1000,
            telem_interval_ms: hydra_telemetry::collector::TELEM_INTERVAL_S * 1000,
            oidc_issuer: "https://id.hydra.internal".into(),
            oidc_audience: "hydra-api".into(),
        }
    }
}

/// System health snapshot (ARCH-SYS-MGMT: health monitoring).
#[derive(Debug, Clone)]
#[mbse_exempt("data type — not a model node")]
pub struct SystemStatus {
    pub devices_in_catalog: usize,
    pub drivers_registered: usize,
    pub degraded_devices: usize,
}

/// System failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum SystemError {
    #[error("store error: {0}")]
    Store(String),
    #[error("driver not matched for {0}/{1}")]
    DriverNotMatched(String, String),
}

/// The Hydra system: assembles auth, catalog, discovery, drivers,
/// telemetry, and audit; coordinates the CONOPS flows (ARCH-SYS-MGMT).
#[links_to("REQ-014", component = "ARCH-SYS-MGMT")]
pub struct HydraSystem {
    pub audit: AuditLog,
    pub stream: MetricStream,
    pub auth: AuthService,
    pub catalog: CatalogService,
    pub fleets: FleetManager,
    pub discovery: DiscoveryService,
    pub comm: DeviceComm,
    pub degradation: DegradationManager,
    /// Per-device telemetry pull: registered devices bound to their drivers
    /// (REQ-026).
    pub telemetry: DriverTelemetrySource,
    /// CONOPS-007: the discovery→provisioning consumer (REQ-034/035),
    /// subscribed to the metric stream.
    pub provisioner: Provisioner,
}

impl HydraSystem {
    /// Assemble the system from configuration.
    pub async fn bootstrap(config: HydraConfig) -> Result<Self, SystemError> {
        // Two connections to the same durable store: catalog + fleets.
        let store = SqliteStore::new(config.db_path.clone());
        store.init().await.map_err(|e| SystemError::Store(e.to_string()))?;
        let catalog = CatalogService::new(store);
        let fleet_store = SqliteStore::new(config.db_path.clone());
        fleet_store
            .init()
            .await
            .map_err(|e| SystemError::Store(e.to_string()))?;
        let fleets = FleetManager::new(fleet_store);

        // Identity pool: OIDC for operators, certificates for devices.
        let pool = IdentityPool::new()
            .register(OidcProvider::new(config.oidc_issuer.clone(), config.oidc_audience.clone()))
            .register(CertProvider::new("device/"));
        let acl = AclEngine::new()
            .allow_role("operator", "catalog:*", "catalog/devices*")
            .allow_role("operator", "fleet:*", "fleet/*")
            .allow_role("device", "telemetry:push", "telemetry/*");
        let auth = AuthService::new(pool, acl);

        // Driver framework: heterogeneous drivers for the known fleet,
        // spanning the fidelity tiers (REQ-018): full-fidelity acme PLC,
        // config-fidelity siemens PLC, telemetry-only senselab sensor.
        let mut registry = DriverRegistry::new();
        registry
            .register(Arc::new(ModbusDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
            .map_err(|e| SystemError::Store(e.to_string()))?;
        registry
            .register(Arc::new(OpcUaDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
            .map_err(|e| SystemError::Store(e.to_string()))?;
        registry
            .register(Arc::new(SensorDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
            .map_err(|e| SystemError::Store(e.to_string()))?;
        let comm = DeviceComm::new(registry);

        // The metric stream: discovery emits to it (REQ-033), the provisioner
        // consumes from it (REQ-034) — the decoupling point of CONOPS-007.
        let stream = MetricStream::default();

        // Discovery: mDNS on the edge network, attached to the stream so a
        // scan cycle emits `DeviceDiscovered` events.
        let discovery = DiscoveryService::new(vec![], config.discovery_interval_ms)
            .with_stream(stream.clone());

        // The provisioner (CONOPS-007): its own catalog/fleet (same durable
        // DB) + driver registry; subscribed to the stream *before* discovery
        // emits, so it receives the events.
        let prov_store = SqliteStore::new(config.db_path.clone());
        prov_store
            .init()
            .await
            .map_err(|e| SystemError::Store(e.to_string()))?;
        let prov_fleet_store = SqliteStore::new(config.db_path);
        prov_fleet_store
            .init()
            .await
            .map_err(|e| SystemError::Store(e.to_string()))?;
        let mut prov_registry = DriverRegistry::new();
        prov_registry
            .register(Arc::new(ModbusDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
            .map_err(|e| SystemError::Store(e.to_string()))?;
        prov_registry
            .register(Arc::new(OpcUaDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
            .map_err(|e| SystemError::Store(e.to_string()))?;
        prov_registry
            .register(Arc::new(SensorDriver::new(Arc::new(SimDevice::new(0)))) as Arc<dyn Driver>)
            .map_err(|e| SystemError::Store(e.to_string()))?;
        let mut provisioner = Provisioner::new(
            CatalogService::new(prov_store),
            FleetManager::new(prov_fleet_store),
            prov_registry,
            FleetPolicy::new("edge"),
        );
        provisioner.attach(&stream);

        Ok(Self {
            audit: AuditLog::new(),
            stream,
            auth,
            catalog,
            fleets,
            discovery,
            comm,
            degradation: DegradationManager::new(2),
            telemetry: DriverTelemetrySource::new(),
            provisioner,
        })
    }

    /// CONOPS-002: onboard a device discovered on the edge network —
    /// register it in the catalog, match a driver, and audit the action.
    pub async fn onboard(&mut self, found: DiscoveredDevice) -> Result<String, SystemError> {
        let device = self
            .catalog
            .register_device(DiscoveryInfo {
                address: found.address.clone(),
                device_type: found.device_type.clone(),
                vendor: found.vendor.clone(),
                capabilities: found.capabilities.clone(),
            })
            .await
            .map_err(|e| SystemError::Store(e.to_string()))?;

        // Match a driver for the device type / vendor (REQ-011).
        let driver = self
            .comm
            .registry()
            .resolve(&found.device_type, &found.vendor)
            .map_err(|_| SystemError::DriverNotMatched(found.device_type, found.vendor))?;

        // Bind the device to its driver for per-device telemetry polling
        // (REQ-026) — the "hook into the device registry for pulling metrics".
        self.telemetry.attach(device.id.clone(), driver);

        self.audit.append(
            "discovery",
            "catalog:register",
            &format!("catalog/devices/{}", device.id),
            &format!("discovered at {}", found.address),
        );
        Ok(device.id)
    }

    /// CONOPS-007: run one discovery→provisioning loop cycle. Discovery
    /// scans the edge network and emits `DeviceDiscovered` events to the
    /// stream (REQ-033); the provisioner — subscribed before the scan —
    /// reacts to each and provisions it (register, bind driver, assign fleet
    /// per policy; REQ-034/035). Returns the number of devices provisioned.
    pub async fn run_discovery_cycle(&mut self) -> usize {
        // Discovery scans and emits events to the stream.
        let _fresh = self.discovery.run_cycle().await;
        // The provisioner processes the pending discovery events.
        self.provisioner.drain().await
    }

    /// CONOPS-004: a driver lost communication with a device. Record the
    /// failure; on degradation, activate the graceful fallback, emit a
    /// metric stream event, and record the degradation.
    pub fn on_driver_failure(&mut self, device: &str) -> bool {
        let tripped = self.degradation.record(device, false);
        if tripped {
            let _ = self.stream.publish(
                MetricKind::DeviceUnhealthy {
                    reason: "driver communication lost".into(),
                },
                device,
            );
            self.audit.append(
                "system",
                "degradation:activate",
                device,
                "graceful fallback: serve cached config",
            );
        }
        tripped
    }

    /// CONOPS-004 (recovery): control restored; clear degradation and
    /// emit a recovery event.
    pub fn on_driver_recovery(&mut self, device: &str) -> bool {
        let was_degraded = self.degradation.state(device) == hydra_drivers::DegradationState::Degraded;
        self.degradation.record(device, true);
        if was_degraded {
            let _ = self
                .stream
                .publish(MetricKind::DeviceRecovered, device);
            self.audit.append("system", "degradation:clear", device, "control restored");
        }
        was_degraded
    }

    /// Health snapshot for monitoring (ARCH-SYS-MGMT).
    pub async fn status(&self) -> Result<SystemStatus, SystemError> {
        let devices = self
            .catalog
            .list_devices(Default::default())
            .await
            .map_err(|e| SystemError::Store(e.to_string()))?;
        Ok(SystemStatus {
            devices_in_catalog: devices.len(),
            drivers_registered: self.comm.registry().len(),
            degraded_devices: self.degradation.degraded_count(),
        })
    }

    /// Bind a device to its driver for per-device telemetry polling (REQ-026).
    pub fn bind_telemetry(&mut self, device: impl Into<String>, driver: Arc<dyn Driver>) {
        self.telemetry.attach(device, driver);
    }

    /// Poll telemetry for all bound devices through their drivers (REQ-026)
    /// and publish each point to the metric stream (REQ-015).
    pub async fn collect_telemetry(&self) -> Vec<TelemetryPoint> {
        let points = self.telemetry.collect().await;
        if self.stream.has_subscribers() {
            for p in &points {
                let _ = self.stream.publish(MetricKind::Point(p.clone()), &p.device);
            }
        }
        points
    }
}
