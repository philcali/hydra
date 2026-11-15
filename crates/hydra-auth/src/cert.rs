//! Certificate-based identity (REQ-017).
//!
//! mTLS / device certificates as an alternative identity mechanism. The
//! TLS layer presents the certificate; the provider validates the
//! subject and validity window.

use crate::pool::{AuthError, Identity, IdentityProvider};

use async_trait::async_trait;
use mbse::links_to;

/// Certificate-based provider (REQ-017).
#[links_to("REQ-017", component = "ARCH-AUTH")]
pub struct CertProvider {
    /// Subjects must start with this prefix, e.g. `"device/"`.
    subject_prefix: String,
}

impl CertProvider {
    pub fn new(subject_prefix: impl Into<String>) -> Self {
        Self {
            subject_prefix: subject_prefix.into(),
        }
    }

    /// Validate a presented device certificate (JSON: `subject`, `not_after`).
    pub fn verify_cert(&self, cert: &str, now_epoch: u64) -> Result<Identity, AuthError> {
        let c: serde_json::Value =
            serde_json::from_str(cert).map_err(|_| AuthError::MalformedToken)?;

        let subject = c
            .get("subject")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::CertRejected("missing subject".into()))?;
        if !subject.starts_with(&self.subject_prefix) {
            return Err(AuthError::CertRejected(format!(
                "subject `{subject}` outside trusted namespace `{}`",
                self.subject_prefix
            )));
        }

        let not_after = c
            .get("not_after")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AuthError::CertRejected("missing not_after".into()))?;
        if now_epoch >= not_after {
            return Err(AuthError::Expired);
        }

        // `device/<name>` → principal `device/<name>`, role `device`.
        Ok(Identity {
            principal: subject.to_string(),
            roles: vec!["device".into()],
            method: "cert".into(),
        })
    }
}

#[async_trait]
impl IdentityProvider for CertProvider {
    fn method(&self) -> &'static str {
        "cert"
    }

    async fn verify(&self, token: &str, now_epoch: u64) -> Result<Identity, AuthError> {
        self.verify_cert(token, now_epoch)
    }
}
