use agent_mesh_core::identity::{AgentId, GroupId};
use async_trait::async_trait;

/// Verifies whether an agent is allowed to connect to the relay.
///
/// Returns `Ok(Some(GroupId))` when the agent is registered and active,
/// `Ok(None)` when the agent is not found in the Control Plane,
/// and `Err(...)` on communication or protocol errors.
#[async_trait]
pub trait GateVerifier: Send + Sync {
    async fn verify_agent(&self, agent_id: &AgentId) -> anyhow::Result<Option<GroupId>>;
}

/// Verifies agents by calling the Control Plane `/gate/verify` endpoint.
pub struct HttpGateVerifier {
    cp_url: String,
    cp_token: String,
    client: reqwest::Client,
}

impl HttpGateVerifier {
    pub fn new(cp_url: String, cp_token: String, client: reqwest::Client) -> Self {
        Self {
            cp_url,
            cp_token,
            client,
        }
    }
}

#[async_trait]
impl GateVerifier for HttpGateVerifier {
    async fn verify_agent(&self, agent_id: &AgentId) -> anyhow::Result<Option<GroupId>> {
        let url = format!("{}/gate/verify", self.cp_url.trim_end_matches('/'));
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.cp_token)
            .json(&serde_json::json!({ "agent_id": agent_id.as_str() }))
            .send()
            .await?;
        match resp.status() {
            s if s == reqwest::StatusCode::OK => {
                let body: serde_json::Value = resp.json().await?;
                let gid_str = body["group_id"]
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("missing group_id in CP response"))?;
                let uuid = uuid::Uuid::parse_str(gid_str)?;
                Ok(Some(GroupId(uuid)))
            }
            s if s == reqwest::StatusCode::NOT_FOUND => Ok(None),
            s => anyhow::bail!("unexpected status from CP gate/verify: {s}"),
        }
    }
}

/// Noop verifier: allows all agents.
/// Used when `cp_url` / `cp_token` are not configured (development / testing).
pub struct NoopGateVerifier;

#[async_trait]
impl GateVerifier for NoopGateVerifier {
    async fn verify_agent(&self, _agent_id: &AgentId) -> anyhow::Result<Option<GroupId>> {
        Ok(Some(GroupId(uuid::Uuid::nil())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::identity::AgentId;

    #[tokio::test]
    async fn noop_verifier_allows_all() {
        let verifier = NoopGateVerifier;
        let agent_id = AgentId::from_raw("test-agent".to_string());
        let result = verifier.verify_agent(&agent_id).await;
        assert!(result.is_ok());
        let group_id = result.unwrap();
        assert!(group_id.is_some());
        let gid = group_id.unwrap();
        assert_eq!(gid.0, uuid::Uuid::nil());
    }
}
