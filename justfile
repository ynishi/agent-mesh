# Convenience wrappers around common workflows.
# List recipes: `just --list`.

# Run the full workspace test suite.
test:
    cargo test --workspace

# Lint: clippy (deny warnings) + rustfmt check.
check:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --all --check

# Dependency audit (advisories / bans / licenses / sources).
deny:
    cargo deny check

# Preflight assertions + publish plan. No side effects.
release-plan:
    scripts/publish.sh

# Publish all crates to crates.io in dependency order (irreversible).
# Run only after the release commit is tagged v{version}.
release-publish:
    scripts/publish.sh --execute
