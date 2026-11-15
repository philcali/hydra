//! Hydra auth service (ARCH-AUTH).
//!
//! Maps to MBSE architecture:
//! - REQ-001 — custom identity pool providers via OIDC
//! - REQ-017 — certificate-based identity (mTLS / device certs)
//! - REQ-002 — granular ACL evaluation
//! - REQ-003 — operation scoping to roles and principals
//! - REQ-019..022 — local (stateful) IAM when no external IdP is configured
//! - REQ-023..025 — local PKI: issue, distribute, revoke device certificates
//! - P-AUTH-TIMEOUT, P-ACL-EVAL-LATENCY (parameters)

mbse_graph::collect_test!();

pub mod acl;
pub mod cert;
pub mod iam;
pub mod oidc;
pub mod pool;
pub mod pki;

pub use acl::{AclEngine, AclRule, Decision};
pub use cert::CertProvider;
pub use iam::{IamService, IamStore, LocalIdentity};
pub use oidc::OidcProvider;
pub use pool::{AuthError, AuthService, Identity, IdentityPool, IdentityProvider};
pub use pki::{CertAuthority, DeviceCert, PkiError, PkiService};

#[cfg(test)]
mod tests;
