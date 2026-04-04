# Self-Hosting Guide

Run your own agent-mesh server (Registry + Relay) on your infrastructure.

## Prerequisites

- Rust 1.85+ (for building from source) or Docker
- (Optional) OAuth app credentials from GitHub for login support

## Option 1: Docker

```bash
# Build
docker build -t agent-mesh-server .

# Run
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
  agent-mesh-server \
  --listen 0.0.0.0:8080 \
  --db-path /data/mesh.db \
  --oauth-provider github \
  --oauth-client-id your-client-id \
  --oauth-client-secret your-client-secret
```

## Option 2: Build from source

```bash
cargo build --release -p agent-mesh-server

# Run
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

# Deploy
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
└── Relay (WebSocket hub, routing, offline buffering)
    └── /relay/ws
```

SQLite database stores agent cards, ACL rules, revocations, and setup keys. The database file is specified via `--db-path` (default: `mesh.db`).
