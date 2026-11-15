//! Tests for hydra-auth — verifies requirements via `#[links_to]`.

use crate::acl::{AclEngine, Decision};
use crate::cert::CertProvider;
use crate::iam::IamService;
use crate::oidc::OidcProvider;
use crate::pool::{AuthError, AuthService, Identity, IdentityPool, IdentityProvider};
use crate::pki::{PkiError, PkiService};

use mbse::links_to;

mbse_graph::collect_test!();

const ISSUER: &str = "https://id.hydra.internal";
const AUDIENCE: &str = "hydra-api";
const FUTURE: u64 = 4_102_444_800; // 2100-01-01
const NOW: u64 = 1_700_000_000;

fn claims(principal: &str, roles: &[&str], exp: u64) -> String {
    serde_json::json!({
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": principal,
        "exp": exp,
        "roles": roles,
    })
    .to_string()
}

fn pool() -> IdentityPool {
    IdentityPool::new().register(OidcProvider::new(ISSUER, AUDIENCE))
}

fn run<F: std::future::Future>(fut: F) -> F::Output {
    tokio::runtime::Runtime::new().unwrap().block_on(fut)
}

/// Verifies REQ-001: OIDC token with correct issuer/audience is accepted.
#[links_to("REQ-001")]
#[test]
fn test_oidc_token_accepted() {
    let id = run(pool().authenticate(&claims("alice", &["operator"], FUTURE), NOW)).unwrap();
    assert_eq!(id.principal, "alice");
    assert_eq!(id.roles, vec!["operator".to_string()]);
    assert_eq!(id.method, "oidc");
}

/// Verifies REQ-001: wrong audience is rejected.
#[links_to("REQ-001")]
#[test]
fn test_oidc_wrong_audience_rejected() {
    let token = serde_json::json!({
        "iss": ISSUER, "aud": "other-api", "sub": "alice",
        "exp": FUTURE, "roles": ["operator"],
    })
    .to_string();
    let err = run(pool().authenticate(&token, NOW)).unwrap_err();
    assert!(matches!(err, AuthError::AudienceMismatch));
}

/// Verifies REQ-001: expired token is rejected.
#[links_to("REQ-001")]
#[test]
fn test_oidc_expired_rejected() {
    let err = run(pool().authenticate(&claims("alice", &["operator"], NOW - 1), NOW)).unwrap_err();
    assert!(matches!(err, AuthError::Expired));
}

/// Verifies REQ-017: device certificate in the trusted namespace is accepted.
#[links_to("REQ-017")]
#[test]
fn test_device_cert_accepted() {
    let pool = IdentityPool::new().register(CertProvider::new("device/"));
    let cert = serde_json::json!({"subject": "device/switch-1", "not_after": FUTURE}).to_string();
    let id = run(pool.authenticate(&cert, NOW)).unwrap();
    assert_eq!(id.principal, "device/switch-1");
    assert_eq!(id.roles, vec!["device".to_string()]);
    assert_eq!(id.method, "cert");
}

/// Verifies REQ-017: certificate outside the trusted namespace is rejected.
#[links_to("REQ-017")]
#[test]
fn test_untrusted_cert_rejected() {
    let pool = IdentityPool::new().register(CertProvider::new("device/"));
    let cert = serde_json::json!({"subject": "rogue/bot", "not_after": FUTURE}).to_string();
    let err = run(pool.authenticate(&cert, NOW)).unwrap_err();
    assert!(matches!(err, AuthError::CertRejected(_)));
}

/// Verifies REQ-017: expired certificate is rejected.
#[links_to("REQ-017")]
#[test]
fn test_expired_cert_rejected() {
    let pool = IdentityPool::new().register(CertProvider::new("device/"));
    let cert = serde_json::json!({"subject": "device/switch-1", "not_after": NOW - 1}).to_string();
    let err = run(pool.authenticate(&cert, NOW)).unwrap_err();
    assert!(matches!(err, AuthError::Expired));
}

/// Verifies REQ-002: granular ACL allows a matching operation.
#[links_to("REQ-002")]
#[test]
fn test_acl_allows_matching_operation() {
    let acl = AclEngine::new().allow_role("operator", "catalog:list", "catalog/devices");
    let id = Identity {
        principal: "alice".into(),
        roles: vec!["operator".into()],
        method: "oidc".into(),
    };
    assert_eq!(acl.evaluate(&id, "catalog:list", "catalog/devices"), Decision::Allow);
}

/// Verifies REQ-002: default deny when no rule matches.
#[links_to("REQ-002")]
#[test]
fn test_acl_default_deny() {
    let acl = AclEngine::new().allow_role("operator", "catalog:list", "catalog/devices");
    let viewer = Identity {
        principal: "bob".into(),
        roles: vec!["viewer".into()],
        method: "oidc".into(),
    };
    assert_eq!(acl.evaluate(&viewer, "catalog:list", "catalog/devices"), Decision::Deny);
}

/// Verifies REQ-002: wildcard resource patterns are granular, not blanket.
#[links_to("REQ-002")]
#[test]
fn test_acl_wildcard_resource() {
    let acl = AclEngine::new().allow_role("operator", "device:reboot", "fleet/prod/*");
    let id = Identity {
        principal: "alice".into(),
        roles: vec!["operator".into()],
        method: "oidc".into(),
    };
    assert_eq!(acl.evaluate(&id, "device:reboot", "fleet/prod/rack-3"), Decision::Allow);
    assert_eq!(acl.evaluate(&id, "device:reboot", "fleet/staging/rack-1"), Decision::Deny);
}

/// Verifies REQ-003: an operation scoped to a role is denied for others.
#[links_to("REQ-003")]
#[test]
fn test_operation_scoped_to_role() {
    let acl = AclEngine::new().allow_role("admin", "device:factory-reset", "catalog/devices/*");
    let admin = Identity {
        principal: "root".into(),
        roles: vec!["admin".into()],
        method: "oidc".into(),
    };
    let operator = Identity {
        principal: "alice".into(),
        roles: vec!["operator".into()],
        method: "oidc".into(),
    };
    assert_eq!(
        acl.evaluate(&admin, "device:factory-reset", "catalog/devices/dev-1"),
        Decision::Allow
    );
    assert_eq!(
        acl.evaluate(&operator, "device:factory-reset", "catalog/devices/dev-1"),
        Decision::Deny
    );
}

/// Verifies REQ-003: an operation scoped to a principal ignores roles.
#[links_to("REQ-003")]
#[test]
fn test_operation_scoped_to_principal() {
    let acl = AclEngine::new().allow_principal("alice", "fleet:rotate", "fleet/prod/*");
    let alice = Identity {
        principal: "alice".into(),
        roles: vec!["viewer".into()],
        method: "oidc".into(),
    };
    let bob = Identity {
        principal: "bob".into(),
        roles: vec!["admin".into()],
        method: "oidc".into(),
    };
    assert_eq!(acl.evaluate(&alice, "fleet:rotate", "fleet/prod/rack-1"), Decision::Allow);
    assert_eq!(acl.evaluate(&bob, "fleet:rotate", "fleet/prod/rack-1"), Decision::Deny);
}

/// A deliberately slow identity source, for the timeout test.
struct SlowProvider;

#[async_trait::async_trait]
impl IdentityProvider for SlowProvider {
    fn method(&self) -> &'static str {
        "slow"
    }

    async fn verify(&self, _token: &str, _now_epoch: u64) -> Result<Identity, AuthError> {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        Ok(Identity {
            principal: "slow".into(),
            roles: vec![],
            method: "slow".into(),
        })
    }
}

/// Verifies REQ-001 (P-AUTH-TIMEOUT): authentication exceeding the budget
/// is rejected with a timeout.
#[links_to("REQ-001")]
#[tokio::test]
async fn test_auth_timeout_enforced() {
    let svc = AuthService::new(
        IdentityPool::new().register(SlowProvider),
        AclEngine::new(),
    )
    .with_timeout(10);
    let err = svc.authenticate("token", NOW).await.unwrap_err();
    assert!(matches!(err, AuthError::Timeout));
}

/// Verifies REQ-001 + REQ-002: the full authenticate → authorize path.
#[links_to("REQ-002")]
#[tokio::test]
async fn test_authenticate_then_authorize() {
    let svc = AuthService::new(pool(), AclEngine::new().allow_role("operator", "catalog:list", "catalog/devices"));
    let id = svc.authenticate(&claims("alice", &["operator"], FUTURE), NOW).await.unwrap();
    assert!(svc.authorize(&id, "catalog:list", "catalog/devices").allows());
    assert!(!svc.authorize(&id, "catalog:delete", "catalog/devices").allows());
}

// ── Local IAM (stateful, no external IdP) — REQ-019..REQ-022 ─────────

/// Verifies REQ-019: local identities can be created, read, and deleted.
#[links_to("REQ-019")]
#[test]
fn test_local_identity_crud() {
    let mut iam = IamService::new();
    iam.create_identity("alice", &["operator"]);
    iam.create_identity("bob", &["viewer"]);
    assert_eq!(iam.len(), 2);
    assert_eq!(iam.get_identity("alice").unwrap().roles, vec!["operator".to_string()]);
    assert!(iam.get_identity("ghost").is_none());
    assert!(iam.delete_identity("bob"));
    assert!(!iam.delete_identity("bob")); // already gone
    assert_eq!(iam.len(), 1);
    assert!(iam.get_identity("alice").is_some());
}

/// Verifies REQ-020: credentials can be set, verified, and rotated; the
/// stored form is a hash, not the plaintext.
#[links_to("REQ-020")]
#[test]
fn test_local_credential_set_verify_rotate() {
    let mut iam = IamService::new();
    iam.create_identity("alice", &["operator"]);
    assert!(!iam.verify_credential("alice", "hunter2")); // none set yet
    assert!(iam.set_credential("alice", "hunter2"));
    assert!(iam.verify_credential("alice", "hunter2"));
    assert!(!iam.verify_credential("alice", "wrong"));
    // plaintext is never stored — only the SHA-256 hash
    assert_ne!(iam.get_identity("alice").unwrap().credential_hash.as_deref(), Some("hunter2"));
    // rotate: old credential stops working, the new one works
    assert!(iam.set_credential("alice", "s3cret"));
    assert!(!iam.verify_credential("alice", "hunter2"));
    assert!(iam.verify_credential("alice", "s3cret"));
}

/// Verifies REQ-021: assigning/removing roles on a local identity changes
/// the ACL decision for that identity.
#[links_to("REQ-021")]
#[test]
fn test_local_role_assignment_reflected_in_acl() {
    let mut iam = IamService::new();
    iam.create_identity("alice", &["viewer"]);
    iam.set_credential("alice", "pw");
    let acl = AclEngine::new().allow_role("operator", "device:reboot", "devices/*");

    // viewer → the operator-only operation is denied
    let id = iam.authenticate("alice", "pw").unwrap();
    assert_eq!(acl.evaluate(&id, "device:reboot", "devices/d1"), Decision::Deny);

    // promote to operator → now allowed
    assert!(iam.assign_role("alice", "operator"));
    let id = iam.authenticate("alice", "pw").unwrap();
    assert!(id.roles.iter().any(|r| r == "operator"));
    assert_eq!(acl.evaluate(&id, "device:reboot", "devices/d1"), Decision::Allow);

    // demote → denied again
    assert!(iam.remove_role("alice", "operator"));
    let id = iam.authenticate("alice", "pw").unwrap();
    assert_eq!(acl.evaluate(&id, "device:reboot", "devices/d1"), Decision::Deny);
}

/// Verifies REQ-022: identities, credentials, and roles persist across a
/// restart (save → reopen).
#[links_to("REQ-022")]
#[test]
fn test_local_iam_state_survives_restart() {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("hydra-iam-{}-{ns}", std::process::id()));

    let mut iam = IamService::new();
    iam.create_identity("alice", &["operator"]);
    iam.set_credential("alice", "hunter2");
    iam.assign_role("alice", "admin");
    iam.save(&path).unwrap();

    // "restart": a brand-new service opened from disk.
    let restarted = IamService::open(&path).unwrap();
    assert_eq!(restarted.len(), 1);
    let id = restarted.get_identity("alice").unwrap();
    assert!(id.roles.iter().any(|r| r == "admin"));
    assert!(restarted.verify_credential("alice", "hunter2"));
    let auth = restarted.authenticate("alice", "hunter2").unwrap();
    assert_eq!(auth.method, "local");
    assert!(auth.roles.iter().any(|r| r == "admin"));

    let _ = std::fs::remove_file(&path);
}

// ── Local PKI (device certificates) — REQ-023..REQ-025 ───────────────

/// Verifies REQ-023: the local CA issues and signs a device certificate,
/// and the signature verifies.
#[links_to("REQ-023")]
#[test]
fn test_local_pki_issue_and_sign() {
    let mut pki = PkiService::new();
    let cert = pki.issue("dev-1", "device/switch-1", NOW, FUTURE);
    assert!(!cert.serial.is_empty());
    assert_eq!(cert.subject, "device/switch-1");
    assert_eq!(cert.issuer, pki.authority().name);
    assert!(!cert.signature.is_empty());
    assert_eq!(pki.issued_count(), 1);
    assert!(pki.for_device("dev-1").is_some());
    // a freshly issued, valid-window, unrevoked cert passes verification
    pki.verify(&cert, NOW).unwrap();
}

/// Verifies REQ-024: an issued certificate can be distributed to the
/// device; unknown devices are rejected.
#[links_to("REQ-024")]
#[test]
fn test_local_pki_distribute() {
    let mut pki = PkiService::new();
    pki.issue("dev-1", "device/switch-1", NOW, FUTURE);
    assert!(!pki.is_distributed("dev-1"));

    let delivered = pki.distribute("dev-1").unwrap();
    assert_eq!(delivered.subject, "device/switch-1");
    assert!(pki.is_distributed("dev-1"));

    // no certificate was issued for this device → distribution fails
    let err = pki.distribute("ghost").unwrap_err();
    assert!(matches!(err, PkiError::NoCertForDevice(_)));
}

/// Verifies REQ-025: revoking a certificate puts it on the CRL and the
/// validation path rejects it.
#[links_to("REQ-025")]
#[test]
fn test_local_pki_revoke_rejects() {
    let mut pki = PkiService::new();
    let cert = pki.issue("dev-1", "device/switch-1", NOW, FUTURE);
    assert!(pki.verify(&cert, NOW).is_ok());

    // revoke → on the CRL, and verification now rejects it
    assert!(pki.revoke(&cert.serial));
    assert!(pki.is_revoked(&cert.serial));
    let err = pki.verify(&cert, NOW).unwrap_err();
    assert!(matches!(err, PkiError::Revoked(_)));

    // re-issuing a fresh cert for the same device is unaffected
    let cert2 = pki.issue("dev-1", "device/switch-1", NOW, FUTURE);
    assert_ne!(cert2.serial, cert.serial);
    assert!(pki.verify(&cert2, NOW).is_ok());
}
