//! Capability identifiers and specs.
//!
//! A capability is the unit an agent invokes: `"<connector>.<action>"`, e.g.
//! `braintree.transactions.search` or `github.pull_requests.create`. The connector
//! is everything before the *first* dot; the action is the remainder. This keeps a
//! flat, stable surface while letting connectors namespace their own actions.

use serde::{Deserialize, Serialize};

use crate::error::{PermauraError, Result};
use crate::model::RiskTier;

/// A validated capability identifier of the form `connector.action`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Parse and validate a capability id. Must contain at least one dot, with a
    /// non-empty connector segment and a non-empty action segment.
    pub fn parse(s: impl Into<String>) -> Result<Self> {
        let s = s.into();
        match s.split_once('.') {
            Some((connector, action)) if !connector.is_empty() && !action.is_empty() => {
                Ok(CapabilityId(s))
            }
            _ => Err(PermauraError::InvalidInput(format!(
                "capability id must be '<connector>.<action>': got '{s}'"
            ))),
        }
    }

    /// The full `connector.action` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The connector segment (everything before the first dot).
    pub fn connector(&self) -> &str {
        self.0.split_once('.').map(|(c, _)| c).unwrap_or(&self.0)
    }

    /// The action segment (everything after the first dot), e.g. `transactions.search`.
    pub fn action(&self) -> &str {
        self.0.split_once('.').map(|(_, a)| a).unwrap_or("")
    }
}

impl std::fmt::Display for CapabilityId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A capability's declared metadata: its id, a human description, its risk tier,
/// whether it always requires approval, and a JSON-Schema-ish input schema (kept as
/// a `serde_json::Value` so connectors can ship zod/JSON-Schema fragments unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySpec {
    /// The capability id.
    pub id: CapabilityId,
    /// Human-readable description, surfaced to the agent via `permaura.list_capabilities`.
    pub description: String,
    /// The risk tier driving default policy behavior.
    pub risk: RiskTier,
    /// If true, this capability always escalates to human approval regardless of grant.
    #[serde(default)]
    pub requires_approval: bool,
    /// Declarative input schema for the capability's parameters.
    #[serde(default)]
    pub input_schema: serde_json::Value,
}

impl CapabilitySpec {
    /// Build a spec, parsing and validating the id.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        risk: RiskTier,
    ) -> Result<Self> {
        Ok(CapabilitySpec {
            id: CapabilityId::parse(id)?,
            description: description.into(),
            risk,
            requires_approval: false,
            input_schema: serde_json::Value::Null,
        })
    }

    /// Builder: mark this capability as always-approval.
    pub fn requiring_approval(mut self) -> Self {
        self.requires_approval = true;
        self
    }

    /// Builder: attach an input schema.
    pub fn with_input_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema = schema;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_on_first_dot() {
        let id = CapabilityId::parse("braintree.transactions.search").unwrap();
        assert_eq!(id.connector(), "braintree");
        assert_eq!(id.action(), "transactions.search");
        assert_eq!(id.as_str(), "braintree.transactions.search");
    }

    #[test]
    fn github_capability() {
        let id = CapabilityId::parse("github.pull_requests.create").unwrap();
        assert_eq!(id.connector(), "github");
        assert_eq!(id.action(), "pull_requests.create");
    }

    #[test]
    fn rejects_missing_dot() {
        assert!(CapabilityId::parse("braintree").is_err());
    }

    #[test]
    fn rejects_empty_segments() {
        assert!(CapabilityId::parse(".search").is_err());
        assert!(CapabilityId::parse("braintree.").is_err());
    }

    #[test]
    fn spec_builder_and_serde() {
        let spec = CapabilitySpec::new(
            "braintree.transactions.refund",
            "Refund a Braintree transaction",
            RiskTier::Critical,
        )
        .unwrap()
        .requiring_approval()
        .with_input_schema(serde_json::json!({ "type": "object" }));
        assert!(spec.requires_approval);
        let json = serde_json::to_string(&spec).unwrap();
        let back: CapabilitySpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
        assert_eq!(back.risk, RiskTier::Critical);
    }
}
