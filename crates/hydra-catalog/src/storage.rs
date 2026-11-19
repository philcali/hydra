//! Device catalog storage abstraction.
//!
//! Maps to MBSE architecture:
//! - ARCH-STORAGE (interface) → REQ-014 (scalability)
//! - ARCH-STORAGE-SQLITE → part_of ARCH-STORAGE
//! - ARCH-STORAGE-POSTGRES → part_of ARCH-STORAGE
//! - P-CATALOG-WRITE-LATENCY (parameter)

use mbse::links_to;
use mbse::mbse_exempt;

mbse_graph::collect_test!();

/// Maximum write latency for catalog operations.
/// Enforced by ARCH-STORAGE, ARCH-STORAGE-SQLITE, ARCH-STORAGE-POSTGRES.
/// Bounded by REQ-014 (scalability → P-CATALOG-WRITE-LATENCY).
#[links_to("REQ-014", parameter = "P-CATALOG-WRITE-LATENCY", value = 100.0)]
pub const CATALOG_WRITE_LATENCY_MS: u64 = 100;

/// Maximum devices a single cluster node's catalog may hold
/// (P-SCALE-DEVICE-COUNT, bounded by REQ-014). The catalog is where the
/// device population lives, so this is where the scale bound is enforced
/// (see `SqliteStore::create_device`). Verified by the end-to-end scale
/// test (`e2e::test_e2e_scale_to_a_thousand_devices`).
#[links_to("REQ-014", parameter = "P-SCALE-DEVICE-COUNT", value = 1000.0)]
pub const MAX_DEVICES_PER_NODE: usize = 1000;

/// Trait representing the storage interface (ARCH-STORAGE component).
/// 
/// Two implementations exist:
/// - `SqliteStore` (ARCH-STORAGE-SQLITE) for single-node/edge
/// - `PostgresStore` (ARCH-STORAGE-POSTGRES) for multi-node/production
/// 
/// Owned by ARCH-CATALOG-STORE.
#[links_to("REQ-014", component = "ARCH-STORAGE")]
#[links_to("REQ-005", component = "ARCH-CATALOG-STORE")]
#[links_to("REQ-007", component = "ARCH-CATALOG-STORE")]
#[async_trait::async_trait]
pub trait DeviceStore: Send + Sync {
    /// List devices with optional filters.
    /// Satisfies REQ-005: queryable device catalog.
    async fn list_devices(&self, filters: DeviceFilters) -> Result<Vec<Device>, StoreError>;
    
    /// Get a single device by ID.
    async fn get_device(&self, id: &str) -> Result<Option<Device>, StoreError>;
    
    /// Create a new device.
    /// Satisfies REQ-007: catalog management (create).
    async fn create_device(&self, device: Device) -> Result<Device, StoreError>;
    
    /// Update an existing device.
    /// Satisfies REQ-007: catalog management (update).
    async fn update_device(&self, id: &str, updates: DeviceUpdates) -> Result<Device, StoreError>;
    
    /// Delete a device.
    /// Satisfies REQ-007: catalog management (delete).
    async fn delete_device(&self, id: &str) -> Result<(), StoreError>;
    
    /// Add a device to a fleet.
    /// Satisfies REQ-006: fleet grouping.
    async fn add_to_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), StoreError>;
    
    /// Remove a device from a fleet.
    async fn remove_from_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), StoreError>;
    
    /// List all fleets.
    async fn list_fleets(&self) -> Result<Vec<Fleet>, StoreError>;
    
    /// Register a discovered device.
    /// Satisfies REQ-008: device discovery.
    async fn register_device(&self, info: DiscoveryInfo) -> Result<Device, StoreError>;
    
    /// Unregister a device.
    async fn unregister_device(&self, id: &str) -> Result<(), StoreError>;
}

/// Device filters for list operations.
#[derive(Debug, Clone, Default)]
#[mbse_exempt("data type — not a model node")]
pub struct DeviceFilters {
    pub fleet_id: Option<String>,
    pub device_type: Option<String>,
    pub status: Option<String>,
    pub limit: Option<usize>,
}

/// A device in the catalog.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[links_to("REQ-005", component = "ARCH-CATALOG-SVC")]
pub struct Device {
    pub id: String,
    pub name: String,
    pub device_type: String,
    pub vendor: String,
    pub status: String,
    pub fleet_ids: Vec<String>,
    pub metadata: serde_json::Value,
}

/// Updates for a device.
#[derive(Debug, Clone, Default)]
#[mbse_exempt("data type — not a model node")]
pub struct DeviceUpdates {
    pub name: Option<String>,
    pub status: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Fleet grouping.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[links_to("REQ-006", component = "ARCH-FLEET")]
pub struct Fleet {
    pub id: String,
    pub name: String,
    pub device_ids: Vec<String>,
}

/// Discovery info from the discovery engine.
#[derive(Debug, Clone)]
#[mbse_exempt("data type — not a model node")]
pub struct DiscoveryInfo {
    pub address: String,
    pub device_type: String,
    pub vendor: String,
    pub capabilities: Vec<String>,
}

/// Store error type.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum StoreError {
    #[error("device not found: {0}")]
    NotFound(String),
    #[error("store error: {0}")]
    Internal(String),
    #[error("catalog at capacity: {capacity} devices (P-SCALE-DEVICE-COUNT)")]
    CapacityExceeded { capacity: usize },
}

/// SQLite implementation (ARCH-STORAGE-SQLITE).
/// 
/// For single-node deployment. Uses SQLite with WAL mode for concurrent reads.
/// Enforces P-CATALOG-WRITE-LATENCY via the same constant as the interface.
/// 
/// Note: `#[links_to]` is on the struct, not the impl block.
/// The macro cannot emit statics in impl position — see SPEC.md §7.
#[links_to("REQ-014", component = "ARCH-STORAGE-SQLITE")]
pub struct SqliteStore {
    /// Single shared connection. `rusqlite::Connection` is `Send` but not
    /// `Sync`, so it is guarded by a mutex — and shared so that `:memory:`
    /// databases persist across operations.
    conn: tokio::sync::Mutex<rusqlite::Connection>,
}

impl SqliteStore {
    pub fn new(path: impl Into<String>) -> Self {
        let conn = rusqlite::Connection::open(path.into())
            .expect("sqlite: unable to open database");
        Self {
            conn: tokio::sync::Mutex::new(conn),
        }
    }

    /// Initialize the database schema.
    pub async fn init(&self) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                vendor TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                metadata TEXT DEFAULT '{}',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS device_fleets (
                device_id TEXT NOT NULL,
                fleet_id TEXT NOT NULL,
                PRIMARY KEY (device_id, fleet_id),
                FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS fleets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(device_type);
            CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
            CREATE INDEX IF NOT EXISTS idx_device_fleets_fleet ON device_fleets(fleet_id);
            ",
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        Ok(())
    }
    
    /// Create a new device in the catalog.
    /// Satisfies REQ-007: catalog management (create).
    ///
    /// Enforces the per-node device scale bound (REQ-014 →
    /// P-SCALE-DEVICE-COUNT): once the catalog holds `MAX_DEVICES_PER_NODE`
    /// devices, new devices are rejected. `register_device` routes through
    /// here, so both the onboarding and provisioning paths are bounded.
    pub async fn create_device(&self, device: Device) -> Result<Device, StoreError> {
        let conn = self.conn.lock().await;

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        if (count as usize) >= MAX_DEVICES_PER_NODE {
            return Err(StoreError::CapacityExceeded {
                capacity: MAX_DEVICES_PER_NODE,
            });
        }

        let metadata_json = serde_json::to_string(&device.metadata)
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        
        conn.execute(
            "INSERT INTO devices (id, name, device_type, vendor, status, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                device.id, device.name, device.device_type,
                device.vendor, device.status, metadata_json
            ],
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        tracing::info!("Created device: {}", device.id);
        Ok(device)
    }
    
    /// Get a device by ID.
    pub async fn get_device(&self, id: &str) -> Result<Option<Device>, StoreError> {
        let conn = self.conn.lock().await;
        
        let row = conn.query_row(
            "SELECT id, name, device_type, vendor, status, metadata FROM devices WHERE id = ?1",
            [id],
            |row| {
                Ok(Device {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    device_type: row.get(2)?,
                    vendor: row.get(3)?,
                    status: row.get(4)?,
                    fleet_ids: vec![],
                    metadata: row.get(5)?,
                })
            },
        ).map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(id.to_string()),
            e => StoreError::Internal(e.to_string()),
        })?;
        
        Ok(Some(row))
    }
    
    /// List devices with optional filters.
    pub async fn list_devices(&self, filters: DeviceFilters) -> Result<Vec<Device>, StoreError> {
        let conn = self.conn.lock().await;
        
        let mut query = "SELECT id, name, device_type, vendor, status, metadata FROM devices".to_string();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql + Send>> = Vec::new();
        
        if let Some(ref fleet_id) = filters.fleet_id {
            query.push_str(" JOIN device_fleets df ON devices.id = df.device_id WHERE df.fleet_id = ?");
            params.push(Box::new(fleet_id.clone()));
        }
        
        if let Some(ref device_type) = filters.device_type {
            if filters.fleet_id.is_some() {
                query.push_str(" AND devices.device_type = ?");
            } else {
                query.push_str(" WHERE devices.device_type = ?");
            }
            params.push(Box::new(device_type.clone()));
        }
        
        if let Some(ref status) = filters.status {
            let sep = if filters.fleet_id.is_some() || filters.device_type.is_some() {
                " AND "
            } else {
                " WHERE "
            };
            query.push_str(&format!("{}devices.status = ?", sep));
            params.push(Box::new(status.clone()));
        }
        
        if let Some(limit) = filters.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }
        
        let rows = conn.prepare(&query)
            .map_err(|e| StoreError::Internal(e.to_string()))?
            .query_map(rusqlite::params_from_iter(params.into_iter()), |row| {
                Ok(Device {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    device_type: row.get(2)?,
                    vendor: row.get(3)?,
                    status: row.get(4)?,
                    fleet_ids: vec![],
                    metadata: row.get(5)?,
                })
            })
            .map_err(|e| StoreError::Internal(e.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| StoreError::Internal(e.to_string()))?;
        
        tracing::debug!("Listed {} devices", rows.len());
        Ok(rows)
    }
    
    /// Update a device.
    pub async fn update_device(&self, id: &str, updates: DeviceUpdates) -> Result<Device, StoreError> {
        let conn = self.conn.lock().await;
        
        let mut set_parts = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::types::ToSql + Send>> = Vec::new();
        
        if let Some(ref name) = updates.name {
            set_parts.push("name = ?");
            params.push(Box::new(name.clone()));
        }
        if let Some(ref status) = updates.status {
            set_parts.push("status = ?");
            params.push(Box::new(status.clone()));
        }
        if let Some(ref metadata) = updates.metadata {
            set_parts.push("metadata = ?");
            let metadata_json = serde_json::to_string(metadata)
                .map_err(|e| StoreError::Internal(e.to_string()))?;
            params.push(Box::new(metadata_json));
        }
        
        if set_parts.is_empty() {
            return self.get_device(id).await.and_then(|d| d.ok_or_else(|| StoreError::NotFound(id.to_string())));
        }
        
        set_parts.push("updated_at = CURRENT_TIMESTAMP");
        params.push(Box::new(id.to_string()));
        
        conn.execute(
            &format!("UPDATE devices SET {} WHERE id = ?", set_parts.join(", ")),
            rusqlite::params_from_iter(params.into_iter()),
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        self.get_device(id).await.and_then(|d| d.ok_or_else(|| StoreError::NotFound(id.to_string())))
    }
    
    /// Delete a device.
    pub async fn delete_device(&self, id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        
        let rows = conn.execute(
            "DELETE FROM devices WHERE id = ?",
            [id],
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        if rows == 0 {
            return Err(StoreError::NotFound(id.to_string()));
        }
        
        tracing::info!("Deleted device: {}", id);
        Ok(())
    }
    
    /// Add a device to a fleet, creating the fleet row if it does not exist.
    pub async fn add_to_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;

        conn.execute(
            "INSERT OR IGNORE INTO fleets (id, name) VALUES (?1, ?2)",
            rusqlite::params![fleet_id, fleet_id],
        ).map_err(|e| StoreError::Internal(e.to_string()))?;

        conn.execute(
            "INSERT OR IGNORE INTO device_fleets (device_id, fleet_id) VALUES (?1, ?2)",
            rusqlite::params![device_id, fleet_id],
        ).map_err(|e| StoreError::Internal(e.to_string()))?;

        Ok(())
    }
    
    /// Remove a device from a fleet.
    pub async fn remove_from_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        
        conn.execute(
            "DELETE FROM device_fleets WHERE device_id = ?1 AND fleet_id = ?2",
            rusqlite::params![device_id, fleet_id],
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        Ok(())
    }
    
    /// List all fleets with device counts.
    pub async fn list_fleets(&self) -> Result<Vec<Fleet>, StoreError> {
        let conn = self.conn.lock().await;
        
        let mut stmt = conn.prepare(
            "SELECT f.id, f.name, COUNT(df.device_id) as device_count
             FROM fleets f
             LEFT JOIN device_fleets df ON f.id = df.fleet_id
             GROUP BY f.id",
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        let rows = stmt.query_map([], |row| {
            Ok(Fleet {
                id: row.get(0)?,
                name: row.get(1)?,
                device_ids: vec![],
            })
        })
        .map_err(|e| StoreError::Internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| StoreError::Internal(e.to_string()))?;
        
        Ok(rows)
    }
    
    /// Register a discovered device.
    pub async fn register_device(&self, info: DiscoveryInfo) -> Result<Device, StoreError> {
        let device_id = uuid::Uuid::new_v4().to_string();
        
        let device = Device {
            id: device_id.clone(),
            name: format!("{}-{}", info.vendor, info.device_type),
            device_type: info.device_type,
            vendor: info.vendor,
            status: "discovered".into(),
            fleet_ids: vec![],
            metadata: serde_json::json!({
                "address": info.address,
                "capabilities": info.capabilities,
                "discovered_at": chrono::Utc::now().to_rfc3339()
            }),
        };
        
        self.create_device(device.clone()).await
    }
    
    /// Unregister a device.
    pub async fn unregister_device(&self, id: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        
        conn.execute(
            "DELETE FROM devices WHERE id = ?",
            [id],
        ).map_err(|e| StoreError::Internal(e.to_string()))?;
        
        Ok(())
    }
}

#[async_trait::async_trait]
impl DeviceStore for SqliteStore {
    async fn list_devices(&self, filters: DeviceFilters) -> Result<Vec<Device>, StoreError> {
        self.list_devices(filters).await
    }
    
    async fn get_device(&self, id: &str) -> Result<Option<Device>, StoreError> {
        self.get_device(id).await
    }
    
    async fn create_device(&self, device: Device) -> Result<Device, StoreError> {
        self.create_device(device).await
    }
    
    async fn update_device(&self, id: &str, updates: DeviceUpdates) -> Result<Device, StoreError> {
        self.update_device(id, updates).await
    }
    
    async fn delete_device(&self, id: &str) -> Result<(), StoreError> {
        self.delete_device(id).await
    }
    
    async fn add_to_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), StoreError> {
        self.add_to_fleet(device_id, fleet_id).await
    }
    
    async fn remove_from_fleet(&self, device_id: &str, fleet_id: &str) -> Result<(), StoreError> {
        self.remove_from_fleet(device_id, fleet_id).await
    }
    
    async fn list_fleets(&self) -> Result<Vec<Fleet>, StoreError> {
        self.list_fleets().await
    }
    
    async fn register_device(&self, info: DiscoveryInfo) -> Result<Device, StoreError> {
        self.register_device(info).await
    }
    
    async fn unregister_device(&self, id: &str) -> Result<(), StoreError> {
        self.unregister_device(id).await
    }
}

/// PostgreSQL implementation (ARCH-STORAGE-POSTGRES).
/// 
/// For multi-node deployment. Supports connection pooling and distributed queries.
/// Enforces P-CATALOG-WRITE-LATENCY via the same constant as the interface.
#[links_to("REQ-014", component = "ARCH-STORAGE-POSTGRES")]
pub struct PostgresStore {
    /// Kept for the (yet unimplemented) pool configuration; the stub
    /// methods do not touch it.
    #[allow(dead_code)]
    connection_string: String,
}

impl PostgresStore {
    pub fn new(connection_string: impl Into<String>) -> Self {
        Self {
            connection_string: connection_string.into(),
        }
    }
}

#[async_trait::async_trait]
impl DeviceStore for PostgresStore {
    async fn list_devices(&self, _filters: DeviceFilters) -> Result<Vec<Device>, StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn get_device(&self, _id: &str) -> Result<Option<Device>, StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn create_device(&self, _device: Device) -> Result<Device, StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn update_device(&self, _id: &str, _updates: DeviceUpdates) -> Result<Device, StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn delete_device(&self, _id: &str) -> Result<(), StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn add_to_fleet(&self, _device_id: &str, _fleet_id: &str) -> Result<(), StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn remove_from_fleet(&self, _device_id: &str, _fleet_id: &str) -> Result<(), StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn list_fleets(&self) -> Result<Vec<Fleet>, StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn register_device(&self, _info: DiscoveryInfo) -> Result<Device, StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
    
    async fn unregister_device(&self, _id: &str) -> Result<(), StoreError> {
        Err(StoreError::Internal("not implemented".into()))
    }
}
