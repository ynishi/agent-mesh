# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
