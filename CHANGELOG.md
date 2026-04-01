# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
