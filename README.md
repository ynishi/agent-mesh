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

## Hosted vs Self-hosted

agent-mesh is fully self-hostable. You can also use the official hosted instance to get started without running your own server.

| | Official Hosted | Self-hosted |
|---|---|---|
| URL | `https://agent-mesh.fly.dev` | Your own domain |
| Setup | `meshctl login` — ready in seconds | Deploy `agent-mesh-server` to your infra |
| Data isolation | Group-scoped — each user sees only their own agents | Full control over data |
| E2E encryption | Relay is blind to payload (Noise_XX) | Same |
| Cost | Free (community instance) | Your infrastructure costs |
| Guide | Quick start below | [docs/self-hosting.md](docs/self-hosting.md) |

CLI commands (`login`, `register`, `discover`) connect to the official instance by default. Override with `--cp-url` or set `cp_url` in `~/.mesh/config.toml` for self-hosted.

> **Note:** The official hosted instance is **experimental** — it is provided free of charge so you can try agent-mesh immediately without setting up your own server. There are no availability or durability guarantees; the service may be stopped, reset, or have its endpoint changed without prior notice. For production use, [self-host your own instance](docs/self-hosting.md).

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

This walkthrough connects two agents (Alice and Bob) through the hosted relay. Each agent needs its own keypair, meshd process, and a local HTTP server that handles requests.

**1. Register both agents**

```bash
# Alice (uses the key already saved in ~/.mesh/config.toml from the register above)
agent-meshctl register --name "alice" --capabilities "chat"
# → Agent ID: <ALICE_ID>   (printed to stderr)

# Bob (generate a new keypair explicitly)
agent-meshctl keygen
# → Agent ID:   <BOB_ID>
# → Secret Key: <BOB_SECRET>
agent-meshctl register --name "bob" --capabilities "echo" --secret-key <BOB_SECRET>
```

**2. Start local HTTP servers** (any server that accepts POST and returns JSON)

```bash
# Terminal 1: Alice's agent server
python3 scripts/echo_server.py 9001 alice

# Terminal 2: Bob's agent server
python3 scripts/echo_server.py 9002 bob
```

**3. Start meshd for each agent**

Each meshd maintains a WebSocket connection to the relay and proxies incoming requests to the local HTTP server. The secret key can be found in `~/.mesh/config.toml` (auto-saved on register).

```bash
# Terminal 3: Alice's meshd
agent-meshd \
  --relay wss://agent-mesh.fly.dev/relay/ws \
  --local-agent http://127.0.0.1:9001 \
  --secret-key <ALICE_SECRET> \
  --cp-url https://agent-mesh.fly.dev

# Terminal 4: Bob's meshd
agent-meshd \
  --relay wss://agent-mesh.fly.dev/relay/ws \
  --local-agent http://127.0.0.1:9002 \
  --secret-key <BOB_SECRET> \
  --cp-url https://agent-mesh.fly.dev
```

**4. Send a request**

```bash
# Terminal 5: Alice sends a request to Bob
agent-meshctl request \
  --target <BOB_ID> \
  --capability echo \
  --payload '{"message": "hello from alice"}'
# → {"agent": "bob", "echo": {"capability": "echo", "message": "hello from alice"}}
```

The request flows: `meshctl → Alice's meshd → [Noise_XX handshake] → Relay → Bob's meshd → Bob's HTTP server → encrypted response back`.

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
| `agent-meshctl` | CLI — `login`, `register`, `discover`, `request`, `status`, `revoke`, `rotate`, `acl`, `group`, `setup-key`, `up`, `mcp-server`, `auth-header` |

## MCP Integration

agent-mesh exposes mesh agent capabilities as MCP (Model Context Protocol) tools, enabling AI coding assistants (Claude Code, Cursor, etc.) to interact with mesh agents directly.

### Setup

```bash
# Build meshctl with MCP support
cargo install --path crates/agent-meshctl --features mcp-server

# Login (required for authentication)
agent-meshctl login
```

### Option A: Streamable HTTP (recommended for persistent servers)

```bash
# Start MCP server (listens on 127.0.0.1:8090 by default)
agent-meshctl mcp-server
```

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "agent-mesh": {
      "type": "http",
      "url": "http://127.0.0.1:8090/mcp",
      "headersHelper": "agent-meshctl auth-header"
    }
  }
}
```

`auth-header` reads the login token from `~/.mesh/config.toml` — no environment variable needed.

### Option B: stdio (recommended for Claude Code subprocess mode)

No separate server process needed. Claude Code spawns meshctl directly.

```json
{
  "mcpServers": {
    "agent-mesh": {
      "type": "stdio",
      "command": "agent-meshctl",
      "args": ["mcp-server", "--stdio"]
    }
  }
}
```

### How it works

MCP Adapter is a thin protocol translation layer sitting in front of meshd (the local daemon). It translates MCP `tools/list` and `tools/call` into meshd Local API calls.

```
Claude Code → MCP (HTTP/stdio) → meshctl → meshd (UDS) → Relay → Target Agent
```

- Tool names follow `{agent_id_prefix}__{capability_name}` format (e.g., `a1b2c3d4__scheduling`)
- Tool list is dynamically fetched from meshd's connected agents (cached with 60s TTL)
- Authentication: Bearer token from `meshctl login`, passed via `headersHelper` (HTTP) or implicit (stdio)

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
