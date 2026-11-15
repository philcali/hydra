//! Granular ACL engine (REQ-002) with role / principal scoping (REQ-003).
//!
//! P-ACL-EVAL-LATENCY — maximum ACL evaluation latency per request.

use crate::pool::Identity;

use mbse::links_to;
use mbse::mbse_exempt;

/// ACL evaluation budget, in milliseconds (P-ACL-EVAL-LATENCY, bounded
/// by REQ-002). Evaluation is O(rules) over an in-memory rule set, which
/// stays within budget for fleet-scale rule counts.
#[links_to("REQ-002", parameter = "P-ACL-EVAL-LATENCY", value = 100.0)]
pub const ACL_EVAL_BUDGET_MS: u64 = 100;

/// ACL decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[mbse_exempt("data type — not a model node")]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    pub fn allows(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// A granular rule: an effect for `(role?, principal?, action, resource)`.
/// `None` fields are wildcards. Resource/action patterns may end in `*`
/// to match any suffix (e.g. `"fleet/prod/*"`).
#[derive(Debug, Clone)]
#[mbse_exempt("data type — not a model node")]
pub struct AclRule {
    pub role: Option<String>,
    pub principal: Option<String>,
    pub action: String,
    pub resource: String,
    pub effect: Decision,
}

/// Granular ACL engine (REQ-002). Rules scope specific operations to
/// roles and principals (REQ-003). First matching rule wins; default deny.
#[links_to("REQ-002", component = "ARCH-AUTH")]
#[links_to("REQ-003", component = "ARCH-AUTH")]
pub struct AclEngine {
    rules: Vec<AclRule>,
}

impl AclEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Scope an operation to a role (REQ-003).
    pub fn allow_role(mut self, role: &str, action: &str, resource: &str) -> Self {
        self.rules.push(AclRule {
            role: Some(role.into()),
            principal: None,
            action: action.into(),
            resource: resource.into(),
            effect: Decision::Allow,
        });
        self
    }

    /// Scope an operation to a specific principal (REQ-003).
    pub fn allow_principal(mut self, principal: &str, action: &str, resource: &str) -> Self {
        self.rules.push(AclRule {
            role: None,
            principal: Some(principal.into()),
            action: action.into(),
            resource: resource.into(),
            effect: Decision::Allow,
        });
        self
    }

    /// Add an explicit deny rule.
    pub fn deny(mut self, role: Option<&str>, principal: Option<&str>, action: &str, resource: &str) -> Self {
        self.rules.push(AclRule {
            role: role.map(String::from),
            principal: principal.map(String::from),
            action: action.into(),
            resource: resource.into(),
            effect: Decision::Deny,
        });
        self
    }

    /// Evaluate an operation for an identity. Default deny.
    pub fn evaluate(&self, identity: &Identity, action: &str, resource: &str) -> Decision {
        for rule in &self.rules {
            if rule.role.as_deref().map_or(true, |r| identity.roles.iter().any(|x| x == r))
                && rule.principal.as_deref().map_or(true, |p| p == identity.principal)
                && matches_pattern(&rule.action, action)
                && matches_pattern(&rule.resource, resource)
            {
                return rule.effect;
            }
        }
        Decision::Deny
    }
}

impl Default for AclEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// `*` at the end of a pattern matches any suffix.
fn matches_pattern(pattern: &str, value: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        pattern == value
    }
}
