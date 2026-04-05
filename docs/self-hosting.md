# Self-Hosting Guide

Run your own agent-mesh server (Registry + Relay + PWA) on your infrastructure.

## Prerequisites

- Rust toolchain (latest stable) or Docker
- (Optional) OAuth app credentials from GitHub for login support
- (Optional) `wasm-pack` for building the PWA client from source

## Option 1: Docker (recommended)

The Docker image builds both the server and the WASM/PWA client. The PWA is served at `/` by the same process — no separate web server needed.

```bash
# Build (includes wasm-pack stage)
docker build -t agent-mesh-server .

# Run (PWA served from /pwa by default)
docker run -d \
  -p 8080:8080 \
  -v mesh-data:/data \
  -e RUST_LOG=info \
  agent-mesh-server
```

With OAuth:

```bash
docker run -d \
  -p 8080:8080 \
  -v mesh-data:/data \
  -e RUST_LOG=info \
  -e OAUTH_PROVIDER=github \
  -e OAUTH_CLIENT_ID=your-client-id \
  -e OAUTH_CLIENT_SECRET=your-client-secret \
  agent-mesh-server
```

Without PWA (API-only mode):

```bash
docker run -d \
  -p 8080:8080 \
  -v mesh-data:/data \
  -e RUST_LOG=info \
  agent-mesh-server \
  --listen 0.0.0.0:8080 --db-path /data/mesh.db
```

## Option 2: Build from source

```bash
# Build server
cargo build --release -p agent-mesh-server

# Build PWA (optional)
cd crates/agent-mesh-wasm && wasm-pack build --target web --release && cd ../..
mkdir -p pwa-dist/pkg
cp pwa/index.html pwa/manifest.json pwa/sw.js pwa-dist/
cp crates/agent-mesh-wasm/pkg/agent_mesh_wasm.js pwa-dist/pkg/
cp crates/agent-mesh-wasm/pkg/agent_mesh_wasm_bg.wasm pwa-dist/pkg/

# Run with PWA
./target/release/agent-mesh-server \
  --listen 0.0.0.0:8080 \
  --db-path mesh.db \
  --pwa-dir pwa-dist

# Run without PWA (API-only)
./target/release/agent-mesh-server \
  --listen 0.0.0.0:8080 \
  --db-path mesh.db
```

## Option 3: fly.io

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Launch (first time)
fly launch --copy-config

# Create persistent volume for SQLite
fly volumes create mesh_data --region nrt --size 1

# Set secrets (optional, for OAuth)
fly secrets set OAUTH_PROVIDER=github
fly secrets set OAUTH_CLIENT_ID=your-client-id
fly secrets set OAUTH_CLIENT_SECRET=your-client-secret

# Deploy (builds server + WASM, serves PWA at /)
fly deploy
```

## Option 4: Docker Compose

```yaml
version: "3.8"
services:
  agent-mesh:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - mesh-data:/data
    environment:
      - RUST_LOG=info
    restart: unless-stopped

volumes:
  mesh-data:
```

## CORS Configuration

By default, **no CORS headers are sent** (same-origin only). This is the correct setting when serving the PWA from the same origin via `--pwa-dir`.

To allow cross-origin access (e.g., external frontends or development):

```bash
# Allow all origins
CORS_ORIGINS="*"

# Allow specific origins
CORS_ORIGINS="https://your-pwa.example.com,https://other.example.com"

# Via CLI flag
--cors-origins "https://your-pwa.example.com"
```

## Connecting meshctl to your server

By default, `agent-meshctl login` connects to the official hosted instance (`https://agent-mesh.fly.dev`).

To point it at your self-hosted server:

```bash
# Per-command
agent-meshctl login --cp-url https://your-server.example.com

# Persistent (saved to ~/.mesh/config.toml)
# After first login, cp_url is saved automatically.
# Or set it manually:
cat > ~/.mesh/config.toml << 'EOF'
cp_url = "https://your-server.example.com"
EOF
```

## Connecting meshd to your server

```bash
agent-meshd \
  --relay wss://your-server.example.com/relay/ws \
  --cp-url https://your-server.example.com \
  --local-agent http://localhost:9000 \
  --secret-key <YOUR_SECRET_KEY>
```

Or via config file (`meshd.json`):

```json
{
  "secret_key_hex": "<YOUR_SECRET_KEY>",
  "relay_url": "wss://your-server.example.com/relay/ws",
  "local_agent_url": "http://localhost:9000",
  "cp_url": "https://your-server.example.com"
}
```

## TLS

In production, place a reverse proxy (nginx, Caddy, etc.) in front of agent-mesh-server for TLS termination, or use a platform that handles TLS automatically (fly.io, Railway, etc.).

Example with Caddy:

```
mesh.example.com {
    reverse_proxy localhost:8080
}
```

## Health check

```bash
curl https://your-server.example.com/health
```

## Architecture

```
agent-mesh-server (single binary)
├── Registry (Agent Card CRUD, capability search, OAuth)
│   ├── /agents/*
│   ├── /health
│   └── /status
├── Relay (WebSocket hub, routing, offline buffering)
│   └── /relay/ws
└── PWA (optional, --pwa-dir)
    ├── /            → index.html
    ├── /sw.js       → Service Worker
    ├── /manifest.json
    └── /pkg/*       → WASM assets
```

SQLite database stores agent cards, ACL rules, revocations, and setup keys. The database file is specified via `--db-path` (default: `mesh.db`).

The PWA is served as a fallback — API and relay routes take priority. If `--pwa-dir` is not set, the server runs in API-only mode.

## GitHub OAuth App Setup

To enable `meshctl login`, create a GitHub OAuth App:

1. Go to **Settings > Developer settings > OAuth Apps > New OAuth App**
2. Set **Authorization callback URL** to `https://your-server.example.com/oauth/callback` (not actually used by Device Flow, but required by GitHub)
3. Note the **Client ID** and generate a **Client Secret**
4. Set the environment variables:
   ```bash
   OAUTH_PROVIDER=github
   OAUTH_CLIENT_ID=<your-client-id>
   OAUTH_CLIENT_SECRET=<your-client-secret>
   ```

## MCP Integration

Expose your self-hosted mesh agents as MCP tools for AI coding assistants.

### Prerequisites

```bash
cargo install --path crates/agent-meshctl --features mcp-server
agent-meshctl login --cp-url https://your-server.example.com
```

### Streamable HTTP mode

```bash
# Start MCP server (requires meshd running)
agent-meshctl mcp-server --listen 127.0.0.1:8090
```

`.mcp.json` configuration:

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

### stdio mode

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

### Authentication

`auth-header` reads the bearer token from `~/.mesh/config.toml` (saved by `meshctl login`). No additional environment variables are needed.

For environments where `meshctl login` is not available, set `MESH_MCP_TOKEN` explicitly:

```bash
MESH_MCP_TOKEN=your-token agent-meshctl mcp-server
```

### Architecture

```
AI Assistant → MCP (HTTP/stdio) → meshctl → meshd (UDS) → Relay → Agent
```

MCP Adapter does not connect to the relay directly — all traffic flows through meshd (Single Point of Enforcement). meshd handles relay connection, ACL enforcement, and E2E encryption.

### Receiving messages

To receive incoming requests from other mesh agents via MCP:

```bash
# Start MCP server with receive endpoint
agent-meshctl mcp-server --receive-port 9100

# Point meshd at the receive endpoint
agent-meshd \
  --relay wss://your-server.example.com/relay/ws \
  --local-agent http://127.0.0.1:9100 \
  --secret-key <YOUR_SECRET_KEY> \
  --cp-url https://your-server.example.com
```

This exposes `mesh__get_messages` and `mesh__reply_message` tools. The MCP client polls for messages and replies within a 25s window.

For headless or SDK use cases, you can skip MCP entirely and connect a simple HTTP server directly to meshd's `--local-agent` endpoint.

## Endpoints

| Path | Description |
|---|---|
| `/health` | Health check |
| `/agents` | Agent Card CRUD and discovery |
| `/relay/ws` | WebSocket relay for meshd connections |
| `/sync` | CP Sync WebSocket for real-time updates |
| `/oauth/device` | OAuth Device Flow initiation |
| `/oauth/token` | OAuth Device Flow token polling |
| `/users/me` | Current user info |
| `/groups/*` | Group management |
| `/acl/*` | ACL rule management |
| `/setup-keys/*` | Setup Key management |
| `/` | PWA client (if `--pwa-dir` is set) |
| `/mcp` | MCP Streamable HTTP endpoint (via `meshctl mcp-server`, not agent-mesh-server) |
