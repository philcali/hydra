//! Hydra device catalog service.
//!
//! Maps to MBSE architecture:
//! - ARCH-CATALOG-SVC → REQ-005, REQ-007
//! - ARCH-FLEET → REQ-006
//! - ARCH-DISCOVERY → REQ-008
//! - ARCH-CATALOG-STORE → depends_on ARCH-CATALOG-SVC

use mbse::links_to;

/// Maximum catalog sync lag across cluster nodes, in seconds (model
/// unit) (P-CATALOG-SYNC-LAG, bounded by REQ-014; model value 5).
#[links_to("REQ-014", parameter = "P-CATALOG-SYNC-LAG", value = 5.0)]
pub const CATALOG_SYNC_LAG_S: u64 = 5;

/// Device catalog service (ARCH-CATALOG-SVC component).
/// 
/// Provides queryable device catalog (REQ-005) and catalog management (REQ-007).
/// Backed by ARCH-CATALOG-STORE via the DeviceStore trait.
#[links_to("REQ-005", component = "ARCH-CATALOG-SVC")]
#[links_to("REQ-007", component = "ARCH-CATALOG-SVC")]
pub struct CatalogService {
    store: Box<dyn crate::storage::DeviceStore + Send + Sync>,
}

impl CatalogService {
    /// Create a new catalog service with the given store.
    pub fn new(store: impl crate::storage::DeviceStore + Send + Sync + 'static) -> Self {
        Self {
            store: Box::new(store),
        }
    }

    /// List devices with filters.
    /// Satisfies REQ-005: queryable device catalog.
    pub async fn list_devices(&self, filters: crate::storage::DeviceFilters) -> Result<Vec<crate::storage::Device>, CatalogError> {
        self.store.list_devices(filters).await
            .map_err(|e| CatalogError::Store(e.to_string()))
    }

    /// Get a single device by ID.
    pub async fn get_device(&self, id: &str) -> Result<Option<crate::storage::Device>, CatalogError> {
        self.store.get_device(id).await
            .map_err(|e| CatalogError::Store(e.to_string()))
    }

    /// Create a new device.
    /// Satisfies REQ-007: catalog management (create).
    pub async fn create_device(&self, device: crate::storage::Device) -> Result<crate::storage::Device, CatalogError> {
        self.store.create_device(device).await
            .map_err(|e| CatalogError::Store(e.to_string()))
    }

    /// Update an existing device.
    /// Satisfies REQ-007: catalog management (update).
    pub async fn update_device(&self, id: &str, updates: crate::storage::DeviceUpdates) -> Result<crate::storage::Device, CatalogError> {
        self.store.update_device(id, updates).await
            .map_err(|e| CatalogError::Store(e.to_string()))
    }

    /// Delete a device.
    /// Satisfies REQ-007: catalog management (delete).
    pub async fn delete_device(&self, id: &str) -> Result<(), CatalogError> {
        self.store.delete_device(id).await
            .map_err(|e| CatalogError::Store(e.to_string()))
    }

    /// Register a device discovered on the edge network.
    /// Satisfies REQ-008: discovery pipeline completion (CONOPS-002).
    pub async fn register_device(&self, info: crate::storage::DiscoveryInfo) -> Result<crate::storage::Device, CatalogError> {
        self.store.register_device(info).await
            .map_err(|e| CatalogError::Store(e.to_string()))
    }
}

/// Catalog service error.
#[derive(Debug, thiserror::Error)]
#[mbse::mbse_exempt("error type — not a model node")]
pub enum CatalogError {
    #[error("store error: {0}")]
    Store(String),
    #[error("device not found: {0}")]
    NotFound(String),
    #[error("validation error: {0}")]
    Validation(String),
}
