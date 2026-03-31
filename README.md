# agent-mesh

A transparent networking layer for agent-to-agent communication. Like Tailscale made VPN setup a single command — agent-mesh does the same for connecting AI agents.

## What it does

agent-mesh provides **reachability**, **authentication**, and **capability discovery** between agents — without prescribing any application-layer protocol (A2A, MCP, etc.).

```
[Alice] --> [mesh-sdk] --> WSS --> [Relay] --> WSS --> [meshd] --> HTTP --> [Bob]
                                        |
                                   [Registry]  (Agent Card search)
```

### Key design choices

- **Capability-based ACL** — not "IP:port" but "Agent A may invoke `scheduling` on Agent B"
- **Protocol-agnostic** — provides connectivity, not application semantics. A2A and MCP can both ride on top
- **Edge-compatible** — `mesh-sdk` runs without a daemon (CF Workers, Vercel Edge, Deno Deploy)
- **Ed25519 identity** — agents are identified by their public key, not by hostname or IP

## Architecture

```
agent-mesh/
  mesh-proto/    Protocol types (Agent Card, ACL, messages, Noise handshake)
  relay/         WebSocket relay server (routes by agent ID)
  meshd/         Local daemon — maintains relay connection, proxies to local agents
  mesh-sdk/      Client library — daemonless connectivity for edge/embedded
  registry/      Agent Card CRUD + capability search (SQLite-backed)
  meshctl/       CLI
  examples/      E2E demo (all components in-process)
```

## Features

### Networking
- WebSocket relay with routing by agent ID
- Offline message buffering (messages queued until agent reconnects)
- Heartbeat and dead agent detection
- Connection resumption with session tokens
- Streaming responses (chunked transfer over WebSocket)

### Security
- Ed25519 keypair identity
- Challenge-response authentication on relay connect
- Noise_XX end-to-end encryption (relay is blind to payload)
- Capability-based ACL with default-deny policy and hot reload
- Signed key revocation with relay enforcement

### Operations
- TOML-based relay configuration
- SQLite persistence for revocations and state
- Graceful shutdown with drain timeout
- Rate limiting per agent
- Request cancellation (CancelToken)
- Status and metrics endpoints (`/status`, `/metrics`)

### SDK
- `MeshClient` — daemonless client for sending encrypted requests
- `MeshAgent` — bidirectional agent with request handler, ACL, streaming
- Automatic Noise session negotiation and reuse
- Plaintext fallback for backward compatibility

## Quick start

```bash
# Build everything
cargo build --release

# 1. Generate a keypair
meshctl keygen
# => agent_id: <BASE64URL_PUBKEY>
# => secret_key: <HEX>

# 2. Start the relay
relay --listen 0.0.0.0:9800

# 3. Start the registry
registry --listen 0.0.0.0:9801

# 4. Register your agent
meshctl register \
  --name "my-agent" \
  --capabilities "scheduling,availability" \
  --secret-key <HEX>

# 5. Start meshd (connects your local agent to the mesh)
meshd \
  --relay ws://localhost:9800/ws \
  --local-agent http://localhost:8080 \
  --secret-key <HEX>

# 6. Discover agents
meshctl discover --capability scheduling

# 7. Send a request
meshctl request \
  --target <AGENT_ID> \
  --capability scheduling \
  --payload '{"date": "2026-04-01"}'
```

### E2E demo (all-in-one)

```bash
cargo run -p examples --bin e2e-demo
```

Starts relay, registry, mock agent, and meshd in a single process — runs 13 tests covering the full Alice -> Relay -> Bob flow with Noise E2E encryption, streaming, ACL, key revocation, rate limiting, and connection resumption.

## Security model

| Layer | Mechanism |
|---|---|
| Identity | Ed25519 keypair per agent |
| Authentication | Challenge-response on relay connect |
| Authorization | Capability-based ACL (default-deny, hot reload) |
| Transport encryption | TLS (relay-terminated) |
| E2E encryption | Noise_XX (agent-to-agent, relay is blind) |
| Key revocation | Signed revocation, relay enforcement, SQLite persistence |

## ACL example

```json
{
  "default_deny": true,
  "rules": [
    {
      "source": "<alice-agent-id>",
      "target": "<bob-agent-id>",
      "allowed_capabilities": ["scheduling", "availability"]
    }
  ]
}
```

## Crate overview

| Crate | Description |
|---|---|
| `mesh-proto` | Shared types — `AgentId`, `AgentCard`, `AclPolicy`, `MeshEnvelope`, Noise handshake |
| `relay` | WebSocket hub with routing, heartbeat, dead-agent detection, offline buffering, rate limiting, SQLite persistence, graceful shutdown |
| `meshd` | Local daemon — relay connection, ACL enforcement, HTTP proxy to local agent |
| `mesh-sdk` | `MeshClient` + `MeshAgent` — E2E encrypted requests, streaming, cancellation |
| `registry` | REST API for Agent Card CRUD, capability search, liveness enrichment |
| `meshctl` | CLI — `keygen`, `register`, `discover`, `request`, `status`, `revoke`, `acl` |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
