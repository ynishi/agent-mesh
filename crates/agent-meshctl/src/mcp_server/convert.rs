use std::sync::Arc;

use agent_mesh_core::agent_card::{AgentCard, Capability};
use agent_mesh_core::identity::AgentId;
use rmcp::model::{JsonObject, Tool};

/// Sanitizes a capability name to be safe for use in an MCP tool name.
///
/// Removes any character that is not in `[a-zA-Z0-9_-]` and lowercases the result.
/// If the sanitized name is empty, returns `"unknown"`.
pub fn sanitize_cap_name(name: &str) -> String {
    let sanitized: String = name
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if sanitized.is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}

/// Constructs an MCP tool name from an `AgentId` and capability name.
///
/// Format: `{agent_id_prefix8}__{sanitized_cap_name}`
///
/// The separator `__` never appears in base64url strings, so it is unambiguous.
pub fn make_tool_name(agent_id: &AgentId, cap_name: &str) -> String {
    let prefix = &agent_id.as_str()[..agent_id.as_str().len().min(8)];
    format!("{}__{}", prefix, sanitize_cap_name(cap_name))
}

/// Builds the `input_schema` `Arc<JsonObject>` for a capability.
///
/// If `Capability.input_schema` is a JSON object, it is used as-is.
/// Otherwise (None or non-object), falls back to `{"type":"object"}`.
fn build_input_schema(cap: &Capability) -> Arc<JsonObject> {
    let schema = cap
        .input_schema
        .as_ref()
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_else(|| {
            let mut m = serde_json::Map::new();
            m.insert(
                "type".to_string(),
                serde_json::Value::String("object".to_string()),
            );
            m
        });
    Arc::new(schema)
}

/// Converts a slice of `AgentCard`s into a flat list of MCP `Tool`s.
///
/// Each `Capability` in each `AgentCard` becomes one `Tool`.
/// The tool name is `{agent_id_prefix8}__{sanitized_cap_name}`.
/// The description is `"{cap_name} (via {agent_name})"`.
pub fn agent_cards_to_tools(cards: &[AgentCard]) -> Vec<Tool> {
    let mut tools = Vec::new();
    for card in cards {
        for cap in &card.capabilities {
            let name = make_tool_name(&card.agent_id, &cap.name);
            let description = match &cap.description {
                Some(d) => format!("{} (via {})", d, card.name),
                None => format!("{} (via {})", cap.name, card.name),
            };
            let input_schema = build_input_schema(cap);
            tools.push(Tool::new(name, description, input_schema));
        }
    }
    tools
}

/// Resolves an MCP tool name back to `(AgentId, capability_name)`.
///
/// Splits on the first `__` to get the 8-character agent_id prefix, then
/// searches `cards` for an agent whose id starts with that prefix and has
/// a capability whose sanitized name matches the suffix.
///
/// Returns `None` if no match is found.
pub fn resolve_tool_target(tool_name: &str, cards: &[AgentCard]) -> Option<(AgentId, String)> {
    let (prefix, cap_suffix) = tool_name.split_once("__")?;
    for card in cards {
        let id_str = card.agent_id.as_str();
        let id_prefix = &id_str[..id_str.len().min(8)];
        if id_prefix != prefix {
            continue;
        }
        for cap in &card.capabilities {
            if sanitize_cap_name(&cap.name) == cap_suffix {
                return Some((card.agent_id.clone(), cap.name.clone()));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_mesh_core::agent_card::{AgentCard, Capability};
    use agent_mesh_core::identity::{AgentCardId, AgentId, GroupId, UserId};
    use chrono::Utc;

    fn make_card(agent_id: &str, name: &str, caps: Vec<(&str, Option<&str>)>) -> AgentCard {
        AgentCard {
            id: AgentCardId::new_v4(),
            agent_id: AgentId::from_raw(agent_id.to_string()),
            owner_id: UserId::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            group_id: GroupId::parse_str("00000000-0000-0000-0000-000000000002").unwrap(),
            name: name.to_string(),
            description: None,
            capabilities: caps
                .into_iter()
                .map(|(cn, desc)| Capability {
                    name: cn.to_string(),
                    description: desc.map(str::to_string),
                    input_schema: None,
                    output_schema: None,
                })
                .collect(),
            registered_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: None,
            online: None,
        }
    }

    // ── sanitize_cap_name ─────────────────────────────────────────────────────

    #[test]
    fn sanitize_removes_spaces() {
        assert_eq!(sanitize_cap_name("hello world"), "helloworld");
    }

    #[test]
    fn sanitize_removes_special_chars() {
        assert_eq!(sanitize_cap_name("foo!@#bar"), "foobar");
    }

    #[test]
    fn sanitize_preserves_underscore_and_hyphen() {
        assert_eq!(sanitize_cap_name("foo_bar-baz"), "foo_bar-baz");
    }

    #[test]
    fn sanitize_empty_string_returns_unknown() {
        assert_eq!(sanitize_cap_name(""), "unknown");
    }

    #[test]
    fn sanitize_all_special_chars_returns_unknown() {
        assert_eq!(sanitize_cap_name("!@#$%"), "unknown");
    }

    #[test]
    fn sanitize_lowercases() {
        assert_eq!(sanitize_cap_name("HelloWorld"), "helloworld");
    }

    // ── make_tool_name ────────────────────────────────────────────────────────

    #[test]
    fn make_tool_name_format() {
        let agent_id = AgentId::from_raw("abcdefgh1234567890".to_string());
        assert_eq!(
            make_tool_name(&agent_id, "scheduling"),
            "abcdefgh__scheduling"
        );
    }

    #[test]
    fn make_tool_name_short_agent_id() {
        let agent_id = AgentId::from_raw("abc".to_string());
        assert_eq!(make_tool_name(&agent_id, "foo"), "abc__foo");
    }

    // ── agent_cards_to_tools ──────────────────────────────────────────────────

    #[test]
    fn convert_single_agent_single_cap() {
        let card = make_card(
            "abcdefgh12345678",
            "Bot",
            vec![("schedule", Some("Book slots"))],
        );
        let tools = agent_cards_to_tools(&[card]);
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name.as_ref(), "abcdefgh__schedule");
        assert!(tools[0]
            .description
            .as_ref()
            .unwrap()
            .contains("Book slots"));
        assert!(tools[0].description.as_ref().unwrap().contains("via Bot"));
    }

    #[test]
    fn convert_multiple_agents_multiple_caps() {
        let card1 = make_card(
            "agent001xxxxxxxxxx",
            "Agent1",
            vec![("cap_a", None), ("cap_b", None)],
        );
        let card2 = make_card("agent002xxxxxxxxxx", "Agent2", vec![("cap_c", None)]);
        let tools = agent_cards_to_tools(&[card1, card2]);
        assert_eq!(tools.len(), 3);
    }

    #[test]
    fn convert_empty_cards() {
        let tools = agent_cards_to_tools(&[]);
        assert!(tools.is_empty());
    }

    #[test]
    fn convert_cap_without_description_uses_cap_name() {
        let card = make_card("abcdefgh12345678", "MyBot", vec![("do_stuff", None)]);
        let tools = agent_cards_to_tools(&[card]);
        let desc = tools[0].description.as_ref().unwrap();
        assert!(desc.contains("do_stuff"), "desc: {desc}");
        assert!(desc.contains("via MyBot"), "desc: {desc}");
    }

    #[test]
    fn convert_with_input_schema() {
        let mut card = make_card("abcdefgh12345678", "Bot", vec![("act", None)]);
        card.capabilities[0].input_schema = Some(serde_json::json!({
            "type": "object",
            "properties": { "name": { "type": "string" } }
        }));
        let tools = agent_cards_to_tools(&[card]);
        let schema_val = serde_json::Value::Object(tools[0].input_schema.as_ref().clone());
        assert_eq!(schema_val["properties"]["name"]["type"], "string");
    }

    #[test]
    fn convert_none_input_schema_fallback() {
        let card = make_card("abcdefgh12345678", "Bot", vec![("act", None)]);
        let tools = agent_cards_to_tools(&[card]);
        let schema_val = serde_json::Value::Object(tools[0].input_schema.as_ref().clone());
        assert_eq!(schema_val["type"], "object");
    }

    // ── resolve_tool_target ───────────────────────────────────────────────────

    #[test]
    fn resolve_existing_tool() {
        let card = make_card("abcdefgh12345678", "Bot", vec![("scheduling", None)]);
        let result = resolve_tool_target("abcdefgh__scheduling", &[card]);
        assert!(result.is_some());
        let (aid, cap_name) = result.unwrap();
        assert_eq!(aid.as_str(), "abcdefgh12345678");
        assert_eq!(cap_name, "scheduling");
    }

    #[test]
    fn resolve_unknown_tool_returns_none() {
        let card = make_card("abcdefgh12345678", "Bot", vec![("scheduling", None)]);
        let result = resolve_tool_target("abcdefgh__unknown", &[card]);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_no_separator_returns_none() {
        let card = make_card("abcdefgh12345678", "Bot", vec![("scheduling", None)]);
        let result = resolve_tool_target("abcdefghscheduling", &[card]);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_wrong_prefix_returns_none() {
        let card = make_card("abcdefgh12345678", "Bot", vec![("scheduling", None)]);
        let result = resolve_tool_target("zzzzzzzz__scheduling", &[card]);
        assert!(result.is_none());
    }

    #[test]
    fn resolve_special_char_cap_name() {
        let card = make_card("abcdefgh12345678", "Bot", vec![("Hello World!", None)]);
        let tool_name = make_tool_name(&card.agent_id, "Hello World!");
        let result = resolve_tool_target(&tool_name, &[card]);
        assert!(result.is_some());
    }
}
