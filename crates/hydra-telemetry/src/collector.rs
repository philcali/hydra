//! Telemetry collector (REQ-013): poll model and push model, feeding
//! the metric stream (REQ-015).

use crate::stream::{MetricEvent, MetricKind, MetricStream, TelemetryPoint};

use mbse::links_to;
use mbse::mbse_exempt;

/// Maximum telemetry collection interval, in seconds (model unit)
/// (P-TELEM-INTERVAL, bounded by REQ-013; model value 30).
#[links_to("REQ-013", parameter = "P-TELEM-INTERVAL", value = 30.0)]
pub const TELEM_INTERVAL_S: u64 = 30;

/// Telemetry source for the poll model (REQ-013).
#[links_to("REQ-013", component = "ARCH-TELEMETRY")]
#[async_trait::async_trait]
pub trait TelemetrySource: Send + Sync {
    /// Collect the current points from the source.
    async fn collect(&self) -> Vec<TelemetryPoint>;
}

/// Collector: poll model (periodic `collect_once`) and push model
/// (`push`), both feeding the metric stream (REQ-013 / REQ-015).
#[links_to("REQ-013", component = "ARCH-TELEMETRY")]
pub struct TelemetryCollector {
    source: Box<dyn TelemetrySource>,
    stream: MetricStream,
    interval_ms: u64,
}

/// Telemetry failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum TelemetryError {
    #[error("collection interval exceeds P-TELEM-INTERVAL ({0}ms > {1}s)")]
    IntervalExceeded(u64, u64),
    #[error("metric stream closed")]
    StreamClosed,
}

impl TelemetryCollector {
    /// New collector polling `source` every `interval_ms`.
    pub fn new(source: impl TelemetrySource + 'static, stream: MetricStream, interval_ms: u64) -> Self {
        Self {
            source: Box::new(source),
            stream,
            interval_ms,
        }
    }

    /// The configured collection interval.
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    /// Check the interval against P-TELEM-INTERVAL (model bound, seconds).
    pub fn validate_interval(&self) -> Result<(), TelemetryError> {
        if self.interval_ms > TELEM_INTERVAL_S * 1000 {
            Err(TelemetryError::IntervalExceeded(self.interval_ms, TELEM_INTERVAL_S))
        } else {
            Ok(())
        }
    }

    /// One poll cycle (REQ-013): collect points and publish each to the
    /// metric stream (REQ-015). Events are fire-and-forget: with no
    /// subscriber attached, points are still collected and returned.
    pub async fn collect_once(&self) -> Result<Vec<TelemetryPoint>, TelemetryError> {
        let points = self.source.collect().await;
        if self.stream.has_subscribers() {
            for point in &points {
                self.stream
                    .publish(MetricKind::Point(point.clone()), &point.device)
                    .map_err(|_| TelemetryError::StreamClosed)?;
            }
        }
        Ok(points)
    }

    /// Push model (REQ-013): ingest a point pushed by a device or driver
    /// and publish it to the metric stream.
    pub fn push(&self, point: TelemetryPoint) -> Result<MetricEvent, TelemetryError> {
        let event = MetricEvent {
            kind: MetricKind::Point(point.clone()),
            device: point.device.clone(),
            ts_ms: crate::stream::now_ms(),
        };
        if self.stream.has_subscribers() {
            self.stream.send(event.clone()).map_err(|_| TelemetryError::StreamClosed)?;
        }
        Ok(event)
    }

    /// Publish an arbitrary event (device health transitions, ...).
    pub fn publish_event(&self, kind: MetricKind, device: impl Into<String>) -> Result<usize, TelemetryError> {
        self.stream
            .publish(kind, device)
            .map_err(|_| TelemetryError::StreamClosed)
    }

    /// Run the poll loop until the runtime shuts down.
    pub async fn run(&self) {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(self.interval_ms));
        loop {
            interval.tick().await;
            if self.collect_once().await.is_err() {
                break;
            }
        }
    }
}
