//! Hydra telemetry service (ARCH-TELEMETRY).
//!
//! Maps to MBSE architecture:
//! - REQ-013 — poll or push device telemetry
//! - REQ-015 — metric stream for reactive integration
//! - REQ-026 — per-device telemetry pull through the drivers
//! - REQ-027..029 — data-plane metric fan-out to delivery targets
//! - P-TELEM-INTERVAL, P-METRIC-STREAM-LAG (parameters)

mbse_graph::collect_test!();

pub mod collector;
pub mod fanout;
pub mod source;
pub mod stream;

pub use collector::{TelemetryCollector, TelemetryError, TelemetrySource};
pub use fanout::{
    CallbackTransport, DeliveryTarget, FanOutService, HttpClient, HttpError, HttpTransport,
    RecordingHttpClient, Transport, TransportError,
};
pub use source::{DeviceBinding, DriverTelemetrySource};
pub use stream::{MetricEvent, MetricKind, MetricStream, TelemetryPoint};

#[cfg(test)]
mod tests;
