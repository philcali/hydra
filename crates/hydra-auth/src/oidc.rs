//! OIDC identity provider (REQ-001).
//!
//! The gateway transport unwraps the JWT; the provider validates the
//! claims — `iss`, `aud`, `exp`, `sub` — and extracts `roles`.

use crate::pool::{AuthError, Identity, IdentityProvider};

use async_trait::async_trait;
use mbse::links_to;
use mbse::mbse_exempt;

/// Issuer / audience a token must be minted for.
#[derive(Debug, Clone)]
#[mbse_exempt("data type — not a model node")]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
}

/// OIDC provider (REQ-001: custom identity pool providers via OIDC).
#[links_to("REQ-001", component = "ARCH-AUTH")]
pub struct OidcProvider {
    config: OidcConfig,
}

impl OidcProvider {
    pub fn new(issuer: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            config: OidcConfig {
                issuer: issuer.into(),
                audience: audience.into(),
            },
        }
    }

    /// Validate OIDC claims and extract an identity.
    pub fn verify_claims(&self, claims: &str, now_epoch: u64) -> Result<Identity, AuthError> {
        let c: serde_json::Value =
            serde_json::from_str(claims).map_err(|_| AuthError::MalformedToken)?;

        let issuer = c
            .get("iss")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingClaim("iss".into()))?;
        if issuer != self.config.issuer {
            return Err(AuthError::IssuerMismatch);
        }

        let audience = c
            .get("aud")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingClaim("aud".into()))?;
        if audience != self.config.audience {
            return Err(AuthError::AudienceMismatch);
        }

        let exp = c
            .get("exp")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| AuthError::MissingClaim("exp".into()))?;
        if now_epoch >= exp {
            return Err(AuthError::Expired);
        }

        let principal = c
            .get("sub")
            .and_then(|v| v.as_str())
            .ok_or_else(|| AuthError::MissingClaim("sub".into()))?
            .to_string();

        let roles = c
            .get("roles")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|r| r.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Identity {
            principal,
            roles,
            method: "oidc".into(),
        })
    }
}

#[async_trait]
impl IdentityProvider for OidcProvider {
    fn method(&self) -> &'static str {
        "oidc"
    }

    async fn verify(&self, token: &str, now_epoch: u64) -> Result<Identity, AuthError> {
        self.verify_claims(token, now_epoch)
    }
}
