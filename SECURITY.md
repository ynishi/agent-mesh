# Security Policy

## Supported Versions

agent-mesh follows [Semantic Versioning](https://semver.org/) and is currently
pre-1.0. Security fixes are provided for the latest `0.3.x` release only.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

If you are running an unsupported version, please upgrade to the latest
`0.3.x` release before reporting an issue, as the vulnerability may already
be fixed.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub
issues, discussions, or pull requests.** Publicly disclosing details of a
vulnerability before a fix is available puts every user of agent-mesh at
risk.

Instead, report vulnerabilities privately via
[GitHub Security Advisories](https://github.com/ynishi/agent-mesh/security/advisories/new).
This creates a private discussion thread visible only to the maintainer and
lets us coordinate a fix and disclosure timeline with you before anything
becomes public.

When reporting, please include as much of the following as you can:

- A description of the vulnerability and its potential impact.
- Steps to reproduce, or a minimal proof-of-concept.
- The affected crate(s) and version(s).
- Any suggested mitigation, if you have one.

We aim to acknowledge new reports within 7 days on a best-effort basis. This
project is currently maintained by a small team without a dedicated
security response SLA, so response and fix timelines may vary with report
severity and complexity.

## Scope

agent-mesh is a secure agent-to-agent mesh network built on Noise Protocol
(Noise_XX) end-to-end encryption and Ed25519 agent identity. We are
especially interested in reports concerning:

- The Noise_XX handshake and session implementation (`agent-mesh-core::noise`),
  including key management, forward secrecy, and replay protection.
- Ed25519 identity, signing, and verification (`agent-mesh-core::identity`).
- ACL enforcement and authorization bypass (`agent-mesh-core::acl`,
  `agent-meshd`).
- The relay's message routing and rate limiting (`agent-mesh-relay`), and
  the registry's authentication, Setup Key, and token handling
  (`agent-mesh-registry`).

Reports on any other part of the codebase are welcome as well; the above is
a non-exhaustive list of areas we consider highest priority given the
project's threat model.
