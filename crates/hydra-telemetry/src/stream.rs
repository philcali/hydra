//! Metric stream for reactive integration (REQ-015).
//!
//! P-METRIC-STREAM-LAG — maximum latency for metric stream event delivery.

use mbse::links_to;
use mbse::mbse_exempt;

/// Maximum latency for metric stream event delivery, in milliseconds
/// (P-METRIC-STREAM-LAG, bounded by REQ-015; model value 1000).
#[links_to("REQ-015", parameter = "P-METRIC-STREAM-LAG", value = 1000.0)]
pub const METRIC_STREAM_LAG_MS: u64 = 1000;

/// A single telemetry observation (REQ-013).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[mbse_exempt("data type — not a model node")]
pub struct TelemetryPoint {
    pub device: String,
    pub metric: String,
    pub value: f64,
    pub ts_ms: u128,
}

/// What happened on the metric stream (REQ-015).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[mbse_exempt("data type — not a model node")]
pub enum MetricKind {
    /// A telemetry point arrived (poll or push).
    Point(TelemetryPoint),
    /// A device went unhealthy (CONOPS-004).
    DeviceUnhealthy { reason: String },
    /// A device recovered.
    DeviceRecovered,
    /// A new device was discovered on the edge network (REQ-033).
    /// The device address is the event's `device` field; vendor/type are extra.
    DeviceDiscovered { vendor: String, device_type: String },
}

/// Milliseconds since the Unix epoch (monotonic enough for lag math).
#[mbse::mbse_exempt("time helper — not a model node")]
pub fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// A metric stream event with its publish timestamp (lag accounting).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
#[mbse_exempt("data type — not a model node")]
pub struct MetricEvent {
    pub kind: MetricKind,
    pub device: String,
    /// `std::time::Instant::now().as_millis()` at publish.
    pub ts_ms: u128,
}

/// Broadcast metric stream (REQ-015): publishers emit, any number of
/// subscribers react. Cloneable so the data plane can hand a handle to the
/// stream→fan-out bridge (REQ-030) while keeping one to publish.
#[derive(Clone)]
#[links_to("REQ-015", component = "ARCH-TELEMETRY")]
#[links_to("REQ-030", component = "ARCH-TELEMETRY")]
#[links_to("REQ-033", component = "ARCH-TELEMETRY")]
pub struct MetricStream {
    tx: tokio::sync::broadcast::Sender<MetricEvent>,
}

impl MetricStream {
    /// New stream buffered for `capacity` recent events per subscriber.
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = tokio::sync::broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// Send a pre-built event to all subscribers.
    pub fn send(&self, event: MetricEvent) -> Result<usize, tokio::sync::broadcast::error::SendError<MetricEvent>> {
        self.tx.send(event)
    }

    /// Publish an event to all subscribers (REQ-015), stamping it now.
    pub fn publish(&self, kind: MetricKind, device: impl Into<String>) -> Result<usize, tokio::sync::broadcast::error::SendError<MetricEvent>> {
        let event = MetricEvent {
            kind,
            device: device.into(),
            ts_ms: now_ms(),
        };
        self.send(event)
    }

    /// Whether any subscriber is attached.
    pub fn has_subscribers(&self) -> bool {
        self.tx.receiver_count() > 0
    }

    /// Subscribe for reactive integration.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<MetricEvent> {
        self.tx.subscribe()
    }
}

impl Default for MetricStream {
    fn default() -> Self {
        Self::new(256)
    }
}
