# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-04-04

### Added

- **fly.io deployment** — `Dockerfile`, `fly.toml`, `.dockerignore` for one-command deployment
- **Official hosted instance** — Default CP URL (`https://agent-mesh.fly.dev`) for zero-config CLI usage
- **CpClient** — Direct HTTP client to Control Plane, enabling `login`/`register`/`discover` without meshd
- **Auto-keygen on register** — `meshctl register` auto-generates Ed25519 keypair and saves to `~/.mesh/config.toml` when no key is provided
- **Self-hosting documentation** — `docs/self-hosting.md` with Docker, fly.io, VPS, and Docker Compose instructions
- **E2E test script** — `scripts/echo_server.py` for local meshd testing

### Changed

- **meshctl login** — Connects directly to CP via HTTP instead of requiring meshd daemon
- **meshctl register/discover** — Use `CpClient` for direct CP access, no meshd required
- **OAuth config** — Server reads `OAUTH_PROVIDER`, `OAUTH_CLIENT_ID`, `OAUTH_CLIENT_SECRET` from environment variables via clap `env` attribute
- **meshd binary name** — Fixed `spawn_meshd()` to use correct binary name `agent-meshd`

### Fixed

- **Noise_XX handshake msg3 routing** — Messages with `in_reply_to` but no matching pending entry (e.g. handshake msg3 at the responder) now fall through to `handle_message()` instead of being silently dropped, fixing E2E encrypted communication

[0.2.1]: https://github.com/ynishi/agent-mesh/compare/v0.2.0...v0.2.1

## [0.2.0] - 2026-04-04

### Added

- **OAuth & Users** — Device Flow endpoints (`/device/code`, `/device/token`), `AppState` extension, `/users/me`
- **Groups** — Group CRUD routes with ownership-based authorization
- **Setup Keys** — Setup Key CRUD and `/register-with-key` endpoint for automated node enrollment
- **Node Lifecycle** — `NodeState` state machine, `MeshCredentials` TOML config, `--cp-url` CLI arg
- **meshd Local API** — UDS server with Control Plane proxy, login flow, revocations proxy endpoint
- **meshctl Integration** — `MeshdClient` and `ensure_meshd` for UDS communication; Group-scoped Discovery; Setup Key commands
- **Sync** — Core sync types, registry ACL/revocation/status/gate APIs, `SyncHub` WebSocket broadcast hub

### Changed

- **Local API errors** — Unified error responses to JSON format
- **Relay revocation** — Extracted revocation logic into `GateVerifier` trait
- **meshctl commands** — Split `commands.rs` into module directory, routed commands through meshd Local API

### Fixed

- README tagline rewritten to reflect agent-mesh's own identity

[0.2.0]: https://github.com/ynishi/agent-mesh/compare/v0.1.0...v0.2.0

## [0.1.0] - 2026-04-01

Initial public release.

### Added

- **agent-mesh-core** — shared types: `AgentId`, `AgentCard`, `AclPolicy`, `MeshEnvelope`, Noise_XX handshake
- **agent-mesh-relay** — WebSocket relay with routing by agent ID, offline message buffering, heartbeat, connection resumption, rate limiting, SQLite persistence, graceful shutdown
- **agent-mesh-sdk** — `MeshClient` and `MeshAgent` with E2E Noise encryption, streaming responses, request cancellation
- **agent-mesh-registry** — REST API for Agent Card CRUD, capability search, liveness enrichment
- **agent-meshd** — local daemon maintaining relay connection, ACL enforcement, HTTP proxy to local agent
- **agent-meshctl** — CLI: `keygen`, `register`, `discover`, `request`, `status`, `revoke`, `acl`
- Ed25519 identity with challenge-response authentication
- Capability-based ACL with default-deny policy and hot reload
- Signed key revocation with relay enforcement
- In-process demo (`mesh-demo`) exercising the full Alice → Relay → Bob flow

[0.1.0]: https://github.com/ynishi/agent-mesh/releases/tag/v0.1.0
