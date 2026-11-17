//! Audit delivery (REQ-040, ARCH-AUDIT-DELIVERY): push audit records to
//! registered targets through pluggable transports — in-process (callback)
//! or a remote HTTP endpoint.
//!
//! The engine only sees the `AuditTransport` trait, so a target's
//! transport is swappable without touching the audit logic. Delivery is
//! best-effort: a record is persisted first, a failed push is logged, and
//! the action itself is not rolled back.

use crate::record::{AuditError, AuditRecord};

use mbse::links_to;
use mbse::mbse_exempt;

/// The delivery mechanism of an audit target (REQ-040) — the pluggable
/// adapter boundary.
#[links_to("REQ-040", component = "ARCH-AUDIT-DELIVERY")]
pub trait AuditTransport: Send + Sync {
    fn deliver(&self, record: &AuditRecord) -> Result<(), AuditError>;
}

/// In-process delivery: a callback (the simplest target).
#[links_to("REQ-040", component = "ARCH-AUDIT-DELIVERY")]
pub struct CallbackAuditTransport {
    f: Box<dyn Fn(AuditRecord) + Send + Sync>,
}

impl CallbackAuditTransport {
    pub fn new(f: impl Fn(AuditRecord) + Send + Sync + 'static) -> Self {
        Self {
            f: Box::new(f),
        }
    }
}

impl AuditTransport for CallbackAuditTransport {
    fn deliver(&self, record: &AuditRecord) -> Result<(), AuditError> {
        (self.f)(record.clone());
        Ok(())
    }
}

/// The HTTP boundary (REQ-040) — the host provides the client, so the
/// actual HTTP stack is pluggable and testable with a recording stand-in.
#[links_to("REQ-040", component = "ARCH-AUDIT-DELIVERY")]
pub trait AuditHttp: Send + Sync {
    /// POST `body` to `url`. Returns the HTTP status code.
    fn post(&self, url: &str, body: &str) -> Result<u16, AuditError>;
}

/// HTTP delivery to a remote endpoint (REQ-040): serializes the record to
/// JSON and POSTs it via the pluggable client.
#[links_to("REQ-040", component = "ARCH-AUDIT-DELIVERY")]
pub struct HttpAuditTransport {
    url: String,
    client: Box<dyn AuditHttp>,
}

impl HttpAuditTransport {
    pub fn new(url: impl Into<String>, client: impl AuditHttp + 'static) -> Self {
        Self {
            url: url.into(),
            client: Box::new(client),
        }
    }

    /// Build from an already-erased client (the `AuditConfig::engine` path).
    pub fn with_boxed_client(url: impl Into<String>, client: Box<dyn AuditHttp>) -> Self {
        Self {
            url: url.into(),
            client,
        }
    }

    /// The endpoint this target pushes to.
    pub fn url(&self) -> &str {
        &self.url
    }
}

impl AuditTransport for HttpAuditTransport {
    fn deliver(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let body = serde_json::to_string(record)
            .map_err(|e| AuditError::Io(format!("serialize: {e}")))?;
        let status = self.client.post(&self.url, &body)?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(AuditError::Io(format!("endpoint returned {status}")))
        }
    }
}

/// A recording HTTP client — the test/stand-in for a real HTTP client
/// (like the `SimDevice` in hydra-drivers).
#[derive(Default)]
#[mbse_exempt("test stand-in — not a model node")]
pub struct RecordingAuditHttp {
    pub requests: std::sync::Mutex<Vec<(String, String)>>,
    pub status: u16,
}

impl RecordingAuditHttp {
    pub fn new(status: u16) -> Self {
        Self {
            requests: std::sync::Mutex::new(Vec::new()),
            status,
        }
    }
}

impl AuditHttp for RecordingAuditHttp {
    fn post(&self, url: &str, body: &str) -> Result<u16, AuditError> {
        self.requests
            .lock()
            .map_err(|e| AuditError::Io(e.to_string()))?
            .push((url.to_string(), body.to_string()));
        Ok(self.status)
    }
}

impl AuditHttp for std::sync::Arc<RecordingAuditHttp> {
    fn post(&self, url: &str, body: &str) -> Result<u16, AuditError> {
        RecordingAuditHttp::post(self.as_ref(), url, body)
    }
}
