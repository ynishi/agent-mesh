# ── Stage 1: WASM Builder ────────────────────────────────────────────────────
FROM rust:slim AS wasm-builder
RUN rustup target add wasm32-unknown-unknown && \
    cargo install wasm-pack
WORKDIR /app
COPY . .
RUN cd crates/agent-mesh-wasm && wasm-pack build --target web --release

# ── Stage 2: Server Builder ──────────────────────────────────────────────────
FROM rust:slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p agent-mesh-server

# ── Stage 3: Assemble PWA directory ──────────────────────────────────────────
FROM debian:bookworm-slim AS assembler
WORKDIR /pwa
COPY pwa/index.html pwa/manifest.json pwa/sw.js ./
COPY --from=wasm-builder /app/crates/agent-mesh-wasm/pkg/agent_mesh_wasm.js ./pkg/
COPY --from=wasm-builder /app/crates/agent-mesh-wasm/pkg/agent_mesh_wasm_bg.wasm ./pkg/

# ── Stage 4: Runtime (distroless) ────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /app/target/release/agent-mesh-server /usr/local/bin/agent-mesh-server
COPY --from=assembler /pwa /pwa

EXPOSE 8080

ENTRYPOINT ["agent-mesh-server"]
CMD ["--listen", "0.0.0.0:8080", "--db-path", "/data/mesh.db", "--pwa-dir", "/pwa"]
