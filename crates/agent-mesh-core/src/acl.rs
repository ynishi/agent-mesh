use serde::{Deserialize, Serialize};

use crate::identity::AgentId;

/// An ACL rule: "source agent may invoke these capabilities on target agent."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclRule {
    /// Who is making the request.
    pub source: AgentId,
    /// Who is being called.
    pub target: AgentId,
    /// Which capabilities are allowed. Empty = all denied.
    pub allowed_capabilities: Vec<String>,
}

/// ACL policy — a collection of rules.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclPolicy {
    /// Default behavior when no rule matches.
    #[serde(default)]
    pub default_deny: bool,
    /// Explicit rules.
    pub rules: Vec<AclRule>,
}

impl AclPolicy {
    pub fn new() -> Self {
        Self {
            default_deny: true,
            rules: Vec::new(),
        }
    }

    /// Check if `source` may invoke `capability` on `target`.
    pub fn is_allowed(&self, source: &AgentId, target: &AgentId, capability: &str) -> bool {
        for rule in &self.rules {
            if rule.source == *source && rule.target == *target {
                return rule.allowed_capabilities.iter().any(|c| c == capability);
            }
        }
        !self.default_deny
    }

    pub fn add_rule(&mut self, rule: AclRule) {
        self.rules.push(rule);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::AgentKeypair;

    #[test]
    fn default_deny_blocks() {
        let policy = AclPolicy::new();
        let a = AgentKeypair::generate().agent_id();
        let b = AgentKeypair::generate().agent_id();
        assert!(!policy.is_allowed(&a, &b, "scheduling"));
    }

    #[test]
    fn explicit_allow_works() {
        let mut policy = AclPolicy::new();
        let a = AgentKeypair::generate().agent_id();
        let b = AgentKeypair::generate().agent_id();
        policy.add_rule(AclRule {
            source: a.clone(),
            target: b.clone(),
            allowed_capabilities: vec!["scheduling".into(), "availability".into()],
        });
        assert!(policy.is_allowed(&a, &b, "scheduling"));
        assert!(policy.is_allowed(&a, &b, "availability"));
        assert!(!policy.is_allowed(&a, &b, "admin"));
    }
}
