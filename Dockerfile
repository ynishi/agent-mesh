# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM rust:slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p agent-mesh-server

# ── Stage 2: Runtime (distroless) ────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /app/target/release/agent-mesh-server /usr/local/bin/agent-mesh-server

EXPOSE 8080

ENTRYPOINT ["agent-mesh-server"]
CMD ["--listen", "0.0.0.0:8080", "--db-path", "/data/mesh.db"]
