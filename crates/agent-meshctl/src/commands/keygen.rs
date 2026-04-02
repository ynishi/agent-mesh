use agent_mesh_core::identity::AgentKeypair;
use anyhow::Result;

/// Generates a new agent keypair and prints the Agent ID and secret key hex.
pub fn keygen() -> Result<()> {
    let kp = AgentKeypair::generate();
    let secret_hex = hex::encode(kp.secret_bytes());
    let agent_id = kp.agent_id();
    println!("Agent ID:    {agent_id}");
    println!("Secret Key:  {secret_hex}");
    println!();
    println!("Save the secret key securely. The Agent ID is derived from it.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keygen_succeeds() {
        keygen().unwrap();
    }
}
