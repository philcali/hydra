//! Local PKI — device certificate lifecycle (REQ-023..REQ-025) — `ARCH-PKI`.
//!
//! The **stateful** counterpart to the stateless `CertProvider` (which only
//! validates a *presented* certificate). `PkiService` owns the local
//! certificate authority: it **issues** device certificates (REQ-023),
//! **distributes** them to edge devices (REQ-024), and **revokes** them,
//! rejecting any revoked certificate (REQ-025).

use std::collections::{BTreeMap, BTreeSet};

use mbse::links_to;
use mbse::mbse_exempt;

/// A device certificate issued and signed by the local CA.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[mbse_exempt("data type — not a model node")]
pub struct DeviceCert {
    /// Unique serial assigned by the CA.
    pub serial: String,
    /// Subject the cert is issued to, e.g. `"device/switch-1"`.
    pub subject: String,
    /// Issuer (CA) name.
    pub issuer: String,
    pub not_before: u64,
    pub not_after: u64,
    /// CA signature over the cert contents (REQ-023: issued + signed).
    pub signature: String,
}

/// The local certificate authority (REQ-023).
///
/// `sign` produces a deterministic digest over the certificate contents;
/// `PkiService::verify` recomputes it to confirm authenticity.
#[derive(Debug, Clone)]
#[links_to("REQ-023", component = "ARCH-PKI")]
pub struct CertAuthority {
    pub name: String,
}

impl CertAuthority {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
        }
    }

    /// Sign a certificate: a digest over its contents under the CA name.
    pub fn sign(&self, cert: &DeviceCert) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.name.as_bytes());
        h.update(cert.serial.as_bytes());
        h.update(cert.subject.as_bytes());
        h.update(cert.issuer.as_bytes());
        h.update(cert.not_before.to_le_bytes());
        h.update(cert.not_after.to_le_bytes());
        hex::encode(h.finalize())
    }
}

impl Default for CertAuthority {
    fn default() -> Self {
        Self::new("hydra-local-ca")
    }
}

/// PKI operation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[mbse_exempt("error type — not a model node")]
pub enum PkiError {
    #[error("no certificate issued for device `{0}`")]
    NoCertForDevice(String),
    #[error("unknown certificate serial `{0}`")]
    UnknownSerial(String),
    #[error("certificate `{0}` has been revoked")]
    Revoked(String),
    #[error("certificate issued by untrusted CA `{0}`")]
    WrongIssuer(String),
    #[error("certificate signature invalid")]
    InvalidSignature,
    #[error("certificate not yet valid")]
    NotYetValid,
    #[error("certificate expired")]
    Expired,
}

/// Stateful local PKI service (REQ-023..REQ-025).
#[links_to("REQ-023", component = "ARCH-PKI")]
#[links_to("REQ-024", component = "ARCH-PKI")]
#[links_to("REQ-025", component = "ARCH-PKI")]
pub struct PkiService {
    ca: CertAuthority,
    next_serial: u64,
    /// serial → certificate.
    certs: BTreeMap<String, DeviceCert>,
    /// device id → latest serial issued for it.
    by_device: BTreeMap<String, String>,
    /// serials already distributed to their device (REQ-024).
    distributed: BTreeSet<String>,
    /// certificate revocation list: revoked serials (REQ-025).
    crl: BTreeSet<String>,
}

impl PkiService {
    pub fn new() -> Self {
        Self {
            ca: CertAuthority::default(),
            next_serial: 0,
            certs: BTreeMap::new(),
            by_device: BTreeMap::new(),
            distributed: BTreeSet::new(),
            crl: BTreeSet::new(),
        }
    }

    /// Use a specific CA name (default `"hydra-local-ca"`).
    pub fn with_ca(mut self, name: impl Into<String>) -> Self {
        self.ca = CertAuthority::new(name);
        self
    }

    pub fn authority(&self) -> &CertAuthority {
        &self.ca
    }

    /// Number of certificates issued.
    pub fn issued_count(&self) -> usize {
        self.certs.len()
    }

    // ── REQ-023: issue (sign) device certificates ───────────────────

    /// Issue (and CA-sign) a new certificate for a device (REQ-023).
    pub fn issue(
        &mut self,
        device_id: &str,
        subject: &str,
        not_before: u64,
        not_after: u64,
    ) -> DeviceCert {
        self.next_serial += 1;
        let serial = format!("{}-{}", self.ca.name, self.next_serial);
        let mut cert = DeviceCert {
            serial: serial.clone(),
            subject: subject.to_string(),
            issuer: self.ca.name.clone(),
            not_before,
            not_after,
            signature: String::new(),
        };
        cert.signature = self.ca.sign(&cert);
        self.certs.insert(serial.clone(), cert.clone());
        self.by_device.insert(device_id.to_string(), serial);
        cert
    }

    /// Look up a certificate by serial.
    pub fn get(&self, serial: &str) -> Option<&DeviceCert> {
        self.certs.get(serial)
    }

    /// The latest certificate issued for a device.
    pub fn for_device(&self, device_id: &str) -> Option<&DeviceCert> {
        self.by_device
            .get(device_id)
            .and_then(|serial| self.certs.get(serial))
    }

    // ── REQ-024: distribute certificates to edge devices ────────────

    /// Distribute the device's current certificate to the edge device
    /// (REQ-024). Returns the certificate material for the device to install
    /// and marks it distributed.
    pub fn distribute(&mut self, device_id: &str) -> Result<DeviceCert, PkiError> {
        let serial = self
            .by_device
            .get(device_id)
            .cloned()
            .ok_or_else(|| PkiError::NoCertForDevice(device_id.to_string()))?;
        let cert = self
            .certs
            .get(&serial)
            .cloned()
            .ok_or_else(|| PkiError::UnknownSerial(serial.clone()))?;
        self.distributed.insert(serial);
        Ok(cert)
    }

    /// Whether the device's current certificate has been distributed.
    pub fn is_distributed(&self, device_id: &str) -> bool {
        self.by_device
            .get(device_id)
            .map(|serial| self.distributed.contains(serial))
            .unwrap_or(false)
    }

    // ── REQ-025: revoke + reject revoked certificates ────────────────

    /// Revoke a certificate (add to the CRL). Returns `true` if it was known.
    pub fn revoke(&mut self, serial: &str) -> bool {
        if self.certs.contains_key(serial) {
            self.crl.insert(serial.to_string());
            true
        } else {
            false
        }
    }

    /// Whether a serial is on the revocation list.
    pub fn is_revoked(&self, serial: &str) -> bool {
        self.crl.contains(serial)
    }

    /// Full local-PKI validation (REQ-025): issuer, signature, validity
    /// window, and revocation. Rejects revoked certificates.
    pub fn verify(&self, cert: &DeviceCert, now: u64) -> Result<(), PkiError> {
        if self.crl.contains(&cert.serial) {
            return Err(PkiError::Revoked(cert.serial.clone()));
        }
        if cert.issuer != self.ca.name {
            return Err(PkiError::WrongIssuer(cert.issuer.clone()));
        }
        if self.ca.sign(&cert) != cert.signature {
            return Err(PkiError::InvalidSignature);
        }
        if now < cert.not_before {
            return Err(PkiError::NotYetValid);
        }
        if now >= cert.not_after {
            return Err(PkiError::Expired);
        }
        Ok(())
    }
}

impl Default for PkiService {
    fn default() -> Self {
        Self::new()
    }
}
