#!/usr/bin/env bash
set -euo pipefail

# agent-mesh crates.io publish driver.
#
# Publishes all workspace crates in dependency order
# (core -> sdk/relay/registry -> ctl/meshd/wasm -> server), waiting
# for crates.io index propagation between crates.
#
# Safety: without --execute this script only runs the preflight
# assertions and prints the plan. Nothing is published.

CRATES=(
    agent-mesh-core
    agent-mesh-sdk
    agent-mesh-relay
    agent-mesh-registry
    agent-meshctl
    agent-meshd
    agent-mesh-wasm
    agent-mesh-server
)
SLEEP_SECS=30

usage() {
    cat <<'USAGE'
usage: scripts/publish.sh [--execute]

Without --execute: run preflight assertions and print the publish plan.
With    --execute: actually publish every crate to crates.io (irreversible).

Run from the repo root, after the release commit is tagged v{version}.
USAGE
}

MODE="plan"
if [ "${1:-}" = "--execute" ]; then
    MODE="execute"
elif [ -n "${1:-}" ]; then
    usage
    exit 1
fi

# --- preflight assertions (always run, fail fast) ---

[ -f Cargo.toml ] || { echo "ERROR: run from the repo root"; exit 1; }

VERSION=$(grep -m1 '^version = ' Cargo.toml | cut -d'"' -f2)
[ -n "${VERSION}" ] || { echo "ERROR: could not read workspace version from Cargo.toml"; exit 1; }

[ -z "$(git status --porcelain)" ] || { echo "ERROR: working tree is not clean"; exit 1; }

TAG="v${VERSION}"
git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null \
    || { echo "ERROR: tag ${TAG} does not exist (bump + tag first)"; exit 1; }

[ "$(git rev-parse HEAD)" = "$(git rev-parse "${TAG}^{}")" ] \
    || { echo "ERROR: HEAD is not the commit tagged ${TAG}"; exit 1; }

echo "OK: version ${VERSION}, working tree clean, HEAD == ${TAG}"
echo "publish order: ${CRATES[*]}"

if [ "${MODE}" = "plan" ]; then
    echo "plan mode: nothing published. Re-run with --execute to publish."
    exit 0
fi

# --- publish (irreversible) ---

LAST_INDEX=$(( ${#CRATES[@]} - 1 ))
for i in "${!CRATES[@]}"; do
    crate="${CRATES[$i]}"
    echo "== cargo publish -p ${crate} (${i}/${LAST_INDEX})"
    cargo publish -p "${crate}"
    if [ "${i}" -lt "${LAST_INDEX}" ]; then
        echo "-- waiting ${SLEEP_SECS}s for crates.io index propagation"
        sleep "${SLEEP_SECS}"
    fi
done

echo "DONE: published $(( LAST_INDEX + 1 )) crates at version ${VERSION}"
