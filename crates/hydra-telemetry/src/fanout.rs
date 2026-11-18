//! Metric fan-out (REQ-027..REQ-029) — `ARCH-FANOUT` (data plane).
//!
//! The data plane's delivery job: push metric events to **registered delivery
//! targets** (push targets / endpoints). This is a separate, independently
//! scalable unit — it holds no control-plane state, so it can run as its own
//! unit (or multiple units) alongside the stateless control plane.
//!
//! A `DeliveryTarget` is a push target: an id, a scope (which devices' events
//! it receives), and a delivery mechanism (a callback). The scope is what
//! keeps targets to the events they're entitled to (REQ-028).

use std::collections::HashSet;

use crate::stream::{MetricEvent, MetricStream};

use mbse::links_to;
use mbse::mbse_exempt;

/// The delivery mechanism of a target (REQ-031) — a pluggable transport.
///
/// This is the adapter boundary: `CallbackTransport` for in-process,
/// `HttpTransport` for a remote endpoint. The data plane only sees this trait,
/// so a target's transport is swappable without touching the fan-out.
#[links_to("REQ-031", component = "ARCH-FANOUT")]
pub trait Transport: Send + Sync {
    fn deliver(&self, event: &MetricEvent) -> Result<(), TransportError>;
}

/// A delivery failure (a specific transport couldn't push the event).
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum TransportError {
    #[error("transport: {0}")]
    Other(String),
}

/// An HTTP delivery failure (the endpoint was unreachable or rejected the push).
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum HttpError {
    #[error("endpoint unreachable: {0}")]
    Unreachable(String),
}

/// The HTTP mechanism (REQ-031) — the boundary the host can back however it
/// likes. `HttpTransport` only talks to this trait, so the actual client is
/// pluggable and testable with a recording stand-in (like the sim drivers).
#[links_to("REQ-031", component = "ARCH-FANOUT")]
pub trait HttpClient: Send + Sync {
    /// POST `body` to `url`. Returns the HTTP status code.
    fn post(&self, url: &str, body: &str) -> Result<u16, HttpError>;
}

/// In-process delivery: a callback (the original target behavior).
#[mbse_exempt("data type — not a model node")]
pub struct CallbackTransport {
    f: Box<dyn Fn(MetricEvent) + Send + Sync>,
}

impl CallbackTransport {
    pub fn new(f: impl Fn(MetricEvent) + Send + Sync + 'static) -> Self {
        Self {
            f: Box::new(f),
        }
    }
}

impl Transport for CallbackTransport {
    fn deliver(&self, event: &MetricEvent) -> Result<(), TransportError> {
        (self.f)(event.clone());
        Ok(())
    }
}

/// HTTP delivery to a remote endpoint (REQ-031): serializes the event to JSON
/// and POSTs it via the pluggable `HttpClient`.
#[links_to("REQ-031", component = "ARCH-FANOUT")]
pub struct HttpTransport {
    pub url: String,
    client: Box<dyn HttpClient>,
}

impl HttpTransport {
    pub fn new(url: impl Into<String>, client: impl HttpClient + 'static) -> Self {
        Self {
            url: url.into(),
            client: Box::new(client),
        }
    }
}

impl Transport for HttpTransport {
    fn deliver(&self, event: &MetricEvent) -> Result<(), TransportError> {
        let body = serde_json::to_string(event)
            .map_err(|e| TransportError::Other(format!("serialize: {e}")))?;
        let status = self
            .client
            .post(&self.url, &body)
            .map_err(|e| TransportError::Other(e.to_string()))?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(TransportError::Other(format!("endpoint returned {status}")))
        }
    }
}

/// A recording HTTP client (sim backend): records each request and returns a
/// fixed status — the test/stand-in for a real HTTP client (like `SimDevice`).
#[mbse_exempt("data type — not a model node")]
pub struct RecordingHttpClient {
    pub requests: std::sync::Mutex<Vec<(String, String)>>,
    pub status: u16,
}

impl RecordingHttpClient {
    pub fn new(status: u16) -> Self {
        Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status,
        }
    }
}

impl HttpClient for RecordingHttpClient {
    fn post(&self, url: &str, body: &str) -> Result<u16, HttpError> {
        self.requests
            .lock()
            .unwrap()
            .push((url.to_string(), body.to_string()));
        Ok(self.status)
    }
}

/// Share one recording client between the target and the test (a shared
/// handle to observe the pushed requests).
#[mbse_exempt("test stand-in — not a model node")]
type SharedHttpClient = std::sync::Arc<RecordingHttpClient>;

impl HttpClient for SharedHttpClient {
    fn post(&self, url: &str, body: &str) -> Result<u16, HttpError> {
        self.as_ref().post(url, body)
    }
}

/// A registered delivery target (push target / endpoint) the data plane
/// pushes metric events to (REQ-027), via a pluggable transport (REQ-031).
#[mbse_exempt("data type — not a model node")]
pub struct DeliveryTarget {
    pub id: String,
    /// Devices this target is entitled to receive. **Empty = all devices.**
    pub scope: HashSet<String>,
    /// The push mechanism (adapter) for this target.
    transport: Box<dyn Transport>,
}

impl DeliveryTarget {
    /// Register a push target delivered in-process via a callback.
    /// An empty `scope` receives all devices.
    pub fn new(
        id: impl Into<String>,
        scope: impl IntoIterator<Item = String>,
        deliver: impl Fn(MetricEvent) + Send + Sync + 'static,
    ) -> Self {
        Self {
            id: id.into(),
            scope: scope.into_iter().collect(),
            transport: Box::new(CallbackTransport::new(deliver)),
        }
    }

    /// Register a push target delivered to a remote HTTP endpoint (REQ-031).
    pub fn http(
        id: impl Into<String>,
        scope: impl IntoIterator<Item = String>,
        url: impl Into<String>,
        client: impl HttpClient + 'static,
    ) -> Self {
        Self {
            id: id.into(),
            scope: scope.into_iter().collect(),
            transport: Box::new(HttpTransport::new(url, client)),
        }
    }

    /// Whether this target is entitled to the event's device (REQ-028).
    pub fn entitled(&self, device: &str) -> bool {
        self.scope.is_empty() || self.scope.contains(device)
    }
}

/// The data plane's metric fan-out (REQ-027/028/029).
///
/// Holds registered delivery targets and pushes each event to every target
/// entitled to it. No control-plane dependency — a separate, scalable unit.
#[links_to("REQ-027", component = "ARCH-FANOUT")]
#[links_to("REQ-028", component = "ARCH-FANOUT")]
#[links_to("REQ-029", component = "ARCH-FANOUT")]
#[links_to("REQ-030", component = "ARCH-FANOUT")]
#[links_to("REQ-031", component = "ARCH-FANOUT")]
pub struct FanOutService {
    targets: Vec<DeliveryTarget>,
}

impl FanOutService {
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
        }
    }

    /// Register a delivery target (REQ-028).
    pub fn register(&mut self, target: DeliveryTarget) {
        self.targets.push(target);
    }

    /// Number of registered delivery targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Push an event to every target entitled to it (REQ-027).
    /// Returns the number of targets the event was successfully delivered to.
    pub fn deliver(&self, event: &MetricEvent) -> usize {
        let mut n = 0;
        for t in &self.targets {
            if t.entitled(&event.device) && t.transport.deliver(event).is_ok() {
                n += 1;
            }
        }
        n
    }

    /// The stream→fan-out bridge (REQ-030): subscribe to the metric stream
    /// and deliver every event to the entitled targets. Runs until the stream
    /// has no more senders. This closes the loop — events published to the
    /// stream reach the registered delivery targets.
    pub async fn pump(&self, stream: &MetricStream) {
        let mut rx = stream.subscribe();
        while let Ok(event) = rx.recv().await {
            self.deliver(&event);
        }
    }
}

impl Default for FanOutService {
    fn default() -> Self {
        Self::new()
    }
}
