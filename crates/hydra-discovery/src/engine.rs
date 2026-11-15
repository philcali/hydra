//! Discovery service (REQ-008): scan cycles with dedup, enforcing
//! P-DISCOVERY-INTERVAL on the poll period.

use std::collections::HashSet;

use hydra_telemetry::{MetricKind, MetricStream};

use crate::config::DiscoveryConfig;
use crate::sources::{DiscoveredDevice, ScanSource};

use mbse::links_to;
use mbse::mbse_exempt;

/// Maximum interval between device discovery polls, in seconds (model
/// unit) (P-DISCOVERY-INTERVAL, bounded by REQ-008; model value 60).
#[links_to("REQ-008", parameter = "P-DISCOVERY-INTERVAL", value = 60.0)]
pub const DISCOVERY_INTERVAL_S: u64 = 60;

/// Discovery failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum DiscoveryError {
    #[error("discovery interval exceeds P-DISCOVERY-INTERVAL ({0}ms > {1}s)")]
    IntervalExceeded(u64, u64),
}

/// Discovery engine (REQ-008): runs scan sources each cycle and emits
/// only *new* devices (dedup by address across cycles).
///
/// Optionally consumes a `DiscoveryConfig` (REQ-032) to filter what it
/// matches, and emits a `DeviceDiscovered` event per new device (REQ-033).
#[links_to("REQ-008", component = "ARCH-DISCOVERY")]
#[links_to("REQ-033", component = "ARCH-DISCOVERY")]
pub struct DiscoveryService {
    sources: Vec<Box<dyn ScanSource>>,
    interval_ms: u64,
    seen: HashSet<String>,
    stream: Option<MetricStream>,
    filter: Option<DiscoveryConfig>,
}

impl DiscoveryService {
    pub fn new(sources: Vec<Box<dyn ScanSource>>, interval_ms: u64) -> Self {
        Self {
            sources,
            interval_ms,
            seen: HashSet::new(),
            stream: None,
            filter: None,
        }
    }

    /// Consume a discovery configuration (REQ-032): adopt its cadence and
    /// filter what discovery matches.
    pub fn with_config(mut self, config: DiscoveryConfig) -> Self {
        self.interval_ms = config.interval_ms;
        self.filter = Some(config);
        self
    }

    /// Attach the metric stream to emit `DeviceDiscovered` events (REQ-033).
    pub fn with_stream(mut self, stream: MetricStream) -> Self {
        self.stream = Some(stream);
        self
    }

    /// Register an additional scan source (mDNS, poll, heartbeat).
    pub fn add_source(&mut self, source: impl ScanSource + 'static) {
        self.sources.push(Box::new(source));
    }

    /// The configured poll interval.
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Check the interval against P-DISCOVERY-INTERVAL (model bound, seconds).
    pub fn validate_interval(&self) -> Result<(), DiscoveryError> {
        if self.interval_ms > DISCOVERY_INTERVAL_S * 1000 {
            Err(DiscoveryError::IntervalExceeded(
                self.interval_ms,
                DISCOVERY_INTERVAL_S,
            ))
        } else {
            Ok(())
        }
    }

    /// One scan cycle (REQ-008): union of all sources, deduped against
    /// everything seen so far, filtered by the config (REQ-032), and each new
    /// device emitted as a `DeviceDiscovered` event on the stream (REQ-033).
    pub async fn run_cycle(&mut self) -> Vec<DiscoveredDevice> {
        let mut fresh: Vec<DiscoveredDevice> = Vec::new();
        for source in &self.sources {
            for device in source.scan().await {
                if !self.seen.insert(device.address.clone()) {
                    continue; // already seen in a prior cycle
                }
                // REQ-032: only match devices within the config's filter.
                if let Some(config) = &self.filter {
                    if !config.matches(&device.vendor, &device.device_type) {
                        continue;
                    }
                }
                tracing::info!(
                    address = %device.address,
                    vendor = %device.vendor,
                    "device discovered on the edge network"
                );
                fresh.push(device);
            }
        }
        // REQ-033: emit a discovery event on the metric stream for each new device.
        for device in &fresh {
            if let Some(stream) = &self.stream {
                let _ = stream.publish(
                    MetricKind::DeviceDiscovered {
                        vendor: device.vendor.clone(),
                        device_type: device.device_type.clone(),
                    },
                    device.address.clone(),
                );
            }
        }
        fresh
    }

    /// Addresses seen so far.
    pub fn seen(&self) -> &HashSet<String> {
        &self.seen
    }

    /// Run scan cycles forever (until the runtime shuts down).
    pub async fn run(&mut self) {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_millis(self.interval_ms));
        loop {
            interval.tick().await;
            let _ = self.run_cycle().await;
        }
    }
}
