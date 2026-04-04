# agent-mesh

A private mesh network for AI agents. Capability discovery, E2E encryption, and protocol-agnostic connectivity — so agents find and talk to each other securely, without caring about where they run.

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

### Official hosted instance

The fastest way to get started. No server setup required.

```bash
# Install
cargo install --path crates/agent-meshctl
cargo install --path crates/agent-meshd

# Login via GitHub OAuth
agent-meshctl login

# Register an agent (keypair is auto-generated and saved to ~/.mesh/config.toml)
agent-meshctl register --name "my-agent" --capabilities "echo,chat"

# Discover agents in your group
agent-meshctl discover
```

### Send requests between agents

```bash
# Terminal 1: Start your agent's local HTTP server (any server that accepts POST and returns JSON)
python3 scripts/echo_server.py 9000 my-agent

# Terminal 2: Connect to the relay
agent-meshd \
  --relay wss://agent-mesh.fly.dev/relay/ws \
  --local-agent http://127.0.0.1:9000 \
  --secret-key <SECRET_KEY> \
  --cp-url https://agent-mesh.fly.dev

# Terminal 3: Send a request to another agent
agent-meshctl request \
  --target <TARGET_AGENT_ID> \
  --capability echo \
  --payload '{"message": "hello"}'
```

### Self-hosting

Run your own server instead of using the official instance. See [docs/self-hosting.md](docs/self-hosting.md) for Docker, fly.io, and VPS deployment options.

```bash
# Build and run
cargo build --release -p agent-mesh-server
./target/release/agent-mesh-server --listen 0.0.0.0:8080 --db-path mesh.db

# Point meshctl at your server
agent-meshctl login --cp-url https://your-server.example.com
```

### Demo (all-in-one)

```bash
cargo run --release -p examples --bin mesh-demo
```

Starts relay, registry, mock agent, and meshd in a single process — runs the full Alice → Relay → Bob flow with agent registration, capability discovery, and Noise E2E encrypted communication.

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
| `agent-mesh-server` | All-in-one server (registry + relay) for hosted or self-hosted deployment |
| `agent-meshctl` | CLI — `login`, `register`, `discover`, `request`, `status`, `revoke`, `rotate`, `acl`, `group`, `setup-key`, `up` |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
