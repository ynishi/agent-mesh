use crate::cp_client::CpClient;
use anyhow::Result;

/// Searches for agents in the registry via direct CP connection.
pub async fn discover(cp: &CpClient, capability: Option<&str>, search: Option<&str>) -> Result<()> {
    let mut params = Vec::new();
    if let Some(c) = capability {
        params.push(format!("capability={c}"));
    }
    if let Some(s) = search {
        params.push(format!("search={s}"));
    }
    let query_str = if params.is_empty() {
        String::new()
    } else {
        format!("?{}", params.join("&"))
    };

    let path = format!("/agents{query_str}");
    let (status, body) = cp.get(&path).await?;

    if !status.is_success() {
        anyhow::bail!("discover request failed ({}): {}", status, body);
    }

    let agents = body.as_array().map(|a| a.len()).unwrap_or(0);
    println!("Found {agents} agent(s):");
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}
