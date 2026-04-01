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
  crates/
    agent-mesh-core/      Protocol types (Agent Card, ACL, messages, Noise handshake)
    agent-mesh-relay/     WebSocket relay server (routes by agent ID)
    agent-meshd/          Local daemon — maintains relay connection, proxies to local agents
    agent-mesh-sdk/       Client library — daemonless connectivity for edge/embedded
    agent-mesh-registry/  Agent Card CRUD + capability search (SQLite-backed)
    agent-meshctl/        CLI
  examples/               Demo (all components in-process)
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
cargo build --release
```

### Demo (all-in-one)

```bash
cargo run --release -p examples --bin mesh-demo
```

Starts relay, registry, mock agent, and meshd in a single process — runs the full Alice → Relay → Bob flow with agent registration, capability discovery, and Noise E2E encrypted communication.

### Connect your own agent

Requires 4 terminals: relay, registry, meshd, and a control terminal.

```bash
# --- Terminal 1: Relay ---
agent-mesh-relay

# --- Terminal 2: Registry ---
agent-mesh-registry

# --- Control terminal ---

# Generate keypairs
agent-meshctl keygen
# Agent ID:    <BOB_ID>
# Secret Key:  <BOB_KEY>

agent-meshctl keygen
# Agent ID:    <ALICE_ID>
# Secret Key:  <ALICE_KEY>

# Register Bob
agent-meshctl register \
  --name "bob" \
  --capabilities "scheduling,availability" \
  --secret-key <BOB_KEY>

# --- Terminal 3: meshd (Bob's node) ---
agent-meshd \
  --relay ws://localhost:9800/ws \
  --local-agent http://localhost:8080 \
  --secret-key <BOB_KEY>

# --- Back to control terminal ---

# Discover agents and send a request as Alice
agent-meshctl discover --capability scheduling
agent-meshctl request \
  --target <BOB_ID> \
  --capability scheduling \
  --payload '{"action": "list"}' \
  --secret-key <ALICE_KEY>
```

Run `--help` on each binary for full options. `agent-meshd` also supports `--config meshd.json` for file-based configuration including ACL policies.

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
| `agent-mesh-core` | Shared types — `AgentId`, `AgentCard`, `AclPolicy`, `MeshEnvelope`, Noise handshake |
| `agent-mesh-relay` | WebSocket hub with routing, heartbeat, dead-agent detection, offline buffering, rate limiting, SQLite persistence, graceful shutdown |
| `agent-meshd` | Local daemon — relay connection, ACL enforcement, HTTP proxy to local agent |
| `agent-mesh-sdk` | `MeshClient` + `MeshAgent` — E2E encrypted requests, streaming, cancellation |
| `agent-mesh-registry` | REST API for Agent Card CRUD, capability search, liveness enrichment |
| `agent-meshctl` | CLI — `keygen`, `register`, `discover`, `request`, `status`, `revoke`, `acl` |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
