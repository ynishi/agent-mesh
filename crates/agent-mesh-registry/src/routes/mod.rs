/// ACL rule management (`/acl`).
pub mod acl;
/// Agent Card registration, lookup, search, and key rotation (`/agents`).
pub mod agents;
/// Gate verification endpoint used by `agent-mesh-relay` (`/gate/verify`).
pub mod gate;
/// Group creation and membership management (`/groups`).
pub mod groups;
/// OAuth Device Flow login (`/oauth/device`, `/oauth/token`).
pub mod oauth;
/// Key revocation listing and creation (`/revocations`).
pub mod revocations;
/// Setup Key issuance, listing, and revocation (`/setup-keys`).
pub mod setup_keys;
/// Registry status/health summary (`/status`).
pub mod status;
/// Authenticated-user profile lookup (`/users/me`).
pub mod users;
