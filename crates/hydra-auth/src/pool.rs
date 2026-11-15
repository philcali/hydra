//! Identity pool and auth service (ARCH-AUTH core).
//!
//! REQ-001 — custom identity pool providers (OIDC first).
//! REQ-017 — certificate-based identity as an alternative mechanism.
//! P-AUTH-TIMEOUT — maximum authentication latency, enforced by `AuthService`.

use crate::acl::AclEngine;

use mbse::links_to;
use async_trait::async_trait;
use mbse::mbse_exempt;

/// Maximum authentication latency, in milliseconds.
///
/// Bounded by REQ-001 (→ P-AUTH-TIMEOUT); enforced by ARCH-AUTH and by
/// `AuthService::authenticate` via `tokio::time::timeout`.
#[links_to("REQ-001", parameter = "P-AUTH-TIMEOUT", value = 5000.0)]
pub const AUTH_TIMEOUT_MS: u64 = 5000;

/// An authenticated identity: principal, roles, and the method that
/// produced it (`"oidc"` or `"cert"`).
#[derive(Debug, Clone, PartialEq)]
#[mbse_exempt("data type — not a model node")]
pub struct Identity {
    pub principal: String,
    pub roles: Vec<String>,
    pub method: String,
}

/// An identity source. The pool (REQ-001) tries each registered provider
/// in order; the first to accept the token wins.
#[links_to("REQ-001", component = "ARCH-AUTH")]
#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Method name (`"oidc"`, `"cert"`, ...).
    fn method(&self) -> &'static str;
    /// Validate a presented token against this provider's mechanism.
    async fn verify(&self, token: &str, now_epoch: u64) -> Result<Identity, AuthError>;
}

/// Custom identity pool (REQ-001): OIDC and certificate providers are
/// registered and tried in order.
#[links_to("REQ-001", component = "ARCH-AUTH")]
#[links_to("REQ-017", component = "ARCH-AUTH")]
pub struct IdentityPool {
    providers: Vec<Box<dyn IdentityProvider>>,
}

impl IdentityPool {
    pub fn new() -> Self {
        Self { providers: Vec::new() }
    }

    /// Register a provider (OIDC, certificate, custom).
    pub fn register(mut self, provider: impl IdentityProvider + 'static) -> Self {
        self.providers.push(Box::new(provider));
        self
    }

    /// Try each provider in registration order.
    pub async fn authenticate(&self, token: &str, now_epoch: u64) -> Result<Identity, AuthError> {
        if self.providers.is_empty() {
            return Err(AuthError::NoProviders);
        }
        let mut last_err = None;
        for provider in &self.providers {
            match provider.verify(token, now_epoch).await {
                Ok(identity) => return Ok(identity),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or(AuthError::Rejected))
    }
}

/// Auth service: identity pool + ACL engine, with P-AUTH-TIMEOUT
/// enforcement on the authentication path.
#[links_to("REQ-001", component = "ARCH-AUTH")]
#[links_to("REQ-002", component = "ARCH-AUTH")]
#[links_to("REQ-003", component = "ARCH-AUTH")]
#[links_to("REQ-017", component = "ARCH-AUTH")]
pub struct AuthService {
    pool: IdentityPool,
    acl: AclEngine,
    timeout_ms: u64,
}

impl AuthService {
    pub fn new(pool: IdentityPool, acl: AclEngine) -> Self {
        Self {
            pool,
            acl,
            timeout_ms: AUTH_TIMEOUT_MS,
        }
    }

    /// Override the authentication timeout (default `AUTH_TIMEOUT_MS`).
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms;
        self
    }

    /// Authenticate a token, enforcing P-AUTH-TIMEOUT.
    pub async fn authenticate(&self, token: &str, now_epoch: u64) -> Result<Identity, AuthError> {
        match tokio::time::timeout(std::time::Duration::from_millis(self.timeout_ms), self.pool.authenticate(token, now_epoch)).await {
            Ok(result) => result,
            Err(_) => Err(AuthError::Timeout),
        }
    }

    /// Authorize an identity for `(action, resource)` via the ACL engine
    /// (REQ-002 / REQ-003).
    pub fn authorize(&self, identity: &Identity, action: &str, resource: &str) -> crate::acl::Decision {
        self.acl.evaluate(identity, action, resource)
    }
}

/// Authentication failure.
#[derive(Debug, thiserror::Error)]
#[mbse_exempt("error type — not a model node")]
pub enum AuthError {
    #[error("malformed token")]
    MalformedToken,
    #[error("missing claim: {0}")]
    MissingClaim(String),
    #[error("issuer mismatch")]
    IssuerMismatch,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("token expired")]
    Expired,
    #[error("certificate rejected: {0}")]
    CertRejected(String),
    #[error("authentication exceeded the P-AUTH-TIMEOUT budget")]
    Timeout,
    #[error("no providers registered")]
    NoProviders,
    #[error("no provider accepted the token")]
    Rejected,
    #[error("unknown local principal: {0}")]
    UnknownPrincipal(String),
    #[error("no credential set for local principal")]
    NoCredential,
    #[error("local credential mismatch")]
    CredentialMismatch,
}
