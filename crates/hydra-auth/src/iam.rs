//! Local identity & access management (REQ-019..REQ-022) — `ARCH-IAM`.
//!
//! The **stateful** half of the auth subsystem. Where `OidcProvider` and
//! `CertProvider` are stateless validators (state lives in an external IdP,
//! or in the presented token/cert), `IamService` owns identities,
//! credentials, and roles itself — and persists them. It is the path used
//! when no external IdP is configured.

use std::collections::BTreeMap;

use crate::pool::{AuthError, Identity};

use mbse::links_to;
use mbse::mbse_exempt;

/// A local identity: principal, its roles, and a credential hash.
///
/// Credentials are stored **only** as a SHA-256 hash — never in plaintext.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[links_to("REQ-019", component = "ARCH-IAM")]
pub struct LocalIdentity {
    pub principal: String,
    pub roles: Vec<String>,
    pub credential_hash: Option<String>,
}

/// Stateful store of local identities (REQ-019/021), credential records
/// (REQ-020), with persistence (REQ-022).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[links_to("REQ-022", component = "ARCH-IAM")]
pub struct IamStore {
    /// principal → identity record.
    pub identities: BTreeMap<String, LocalIdentity>,
}

impl IamStore {
    pub fn new() -> Self {
        Self {
            identities: BTreeMap::new(),
        }
    }

    /// Persist the store to `path` as JSON (REQ-022: survives a restart).
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }

    /// Load a previously persisted store from `path` (REQ-022).
    pub fn load(path: &std::path::Path) -> std::io::Result<Self> {
        let json = std::fs::read_to_string(path)?;
        serde_json::from_str(&json)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// SHA-256 hex digest of a credential. Helper only — the point is that the
/// raw credential is never stored.
#[mbse_exempt("hashing helper — not a model node")]
pub fn hash_credential(credential: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(credential.as_bytes());
    hex::encode(hasher.finalize())
}

/// Stateful local IAM service (REQ-019..REQ-022).
///
/// Owns identities (REQ-019), credentials (REQ-020), and roles (REQ-021),
/// and persists all of them (REQ-022).
#[links_to("REQ-019", component = "ARCH-IAM")]
#[links_to("REQ-020", component = "ARCH-IAM")]
#[links_to("REQ-021", component = "ARCH-IAM")]
#[links_to("REQ-022", component = "ARCH-IAM")]
pub struct IamService {
    store: IamStore,
}

impl IamService {
    pub fn new() -> Self {
        Self {
            store: IamStore::new(),
        }
    }

    /// Open a previously persisted store (REQ-022).
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        Ok(Self {
            store: IamStore::load(path)?,
        })
    }

    /// Persist current state to `path` (REQ-022).
    pub fn save(&self, path: &std::path::Path) -> std::io::Result<()> {
        self.store.save(path)
    }

    pub fn store(&self) -> &IamStore {
        &self.store
    }

    // ── REQ-019: identity management ───────────────────────────────

    /// Create (or replace) a local identity with a role set.
    pub fn create_identity(&mut self, principal: &str, roles: &[&str]) {
        self.store
            .identities
            .insert(
                principal.to_string(),
                LocalIdentity {
                    principal: principal.to_string(),
                    roles: roles.iter().map(|r| r.to_string()).collect(),
                    credential_hash: None,
                },
            );
    }

    /// Look up a local identity.
    pub fn get_identity(&self, principal: &str) -> Option<&LocalIdentity> {
        self.store.identities.get(principal)
    }

    /// Remove a local identity. Returns `true` if it existed.
    pub fn delete_identity(&mut self, principal: &str) -> bool {
        self.store.identities.remove(principal).is_some()
    }

    /// Number of managed identities.
    pub fn len(&self) -> usize {
        self.store.identities.len()
    }

    pub fn is_empty(&self) -> bool {
        self.store.identities.is_empty()
    }

    // ── REQ-021: role assignment (feeds the ACL engine) ─────────────

    /// Add a role to a local identity. Returns `true` if it was added.
    pub fn assign_role(&mut self, principal: &str, role: &str) -> bool {
        match self.store.identities.get_mut(principal) {
            Some(id) if !id.roles.iter().any(|r| r == role) => {
                id.roles.push(role.to_string());
                true
            }
            _ => false,
        }
    }

    /// Remove a role from a local identity. Returns `true` if it was removed.
    pub fn remove_role(&mut self, principal: &str, role: &str) -> bool {
        let Some(id) = self.store.identities.get_mut(principal) else {
            return false;
        };
        let before = id.roles.len();
        id.roles.retain(|r| r != role);
        id.roles.len() != before
    }

    // ── REQ-020: credential management ──────────────────────────────

    /// Set (or reset) the credential for a local identity.
    pub fn set_credential(&mut self, principal: &str, credential: &str) -> bool {
        match self.store.identities.get_mut(principal) {
            Some(id) => {
                id.credential_hash = Some(hash_credential(credential));
                true
            }
            None => false,
        }
    }

    /// Check a presented credential against a local identity.
    pub fn verify_credential(&self, principal: &str, credential: &str) -> bool {
        let Some(stored) = self
            .store
            .identities
            .get(principal)
            .and_then(|id| id.credential_hash.as_deref())
        else {
            return false;
        };
        stored == hash_credential(credential)
    }

    /// Authenticate a local identity by `(principal, credential)` → `Identity`.
    ///
    /// The returned identity carries its assigned roles (REQ-021) so it can be
    /// fed straight into the ACL engine (REQ-002/003).
    pub fn authenticate(
        &self,
        principal: &str,
        credential: &str,
    ) -> Result<Identity, AuthError> {
        let id = self
            .store
            .identities
            .get(principal)
            .ok_or(AuthError::UnknownPrincipal(principal.to_string()))?;
        let stored = id
            .credential_hash
            .as_deref()
            .ok_or(AuthError::NoCredential)?;
        if stored != hash_credential(credential) {
            return Err(AuthError::CredentialMismatch);
        }
        Ok(Identity {
            principal: id.principal.clone(),
            roles: id.roles.clone(),
            method: "local".into(),
        })
    }
}

impl Default for IamService {
    fn default() -> Self {
        Self::new()
    }
}
