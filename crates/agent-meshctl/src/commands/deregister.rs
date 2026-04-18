use crate::cp_client::CpClient;
use anyhow::Result;

/// Deletes an agent card from the registry via `DELETE /agents/{id}`.
///
/// `card_id` is the AgentCard UUID (obtainable via `meshctl discover`), not
/// the agent_id. The caller must own the card — otherwise the CP returns 403.
/// This removes only the card; the underlying Ed25519 key is untouched
/// (unlike `revoke`, which blocks the key and disconnects every card sharing
/// it).
pub async fn deregister(cp: &CpClient, card_id: &str) -> Result<()> {
    let (status, resp) = cp.delete(&format!("/agents/{card_id}")).await?;
    if status.is_success() {
        eprintln!("Deleted agent card {card_id}");
        Ok(())
    } else {
        anyhow::bail!("Deregister failed ({}): {}", status, resp);
    }
}
