# Hosted worker (Mode C) image: the same `permaura` binary with KMS custody (no static key; ADC on
# Cloud Run). A worker keeps its state in the default SQLite store, snapshotted to a per-tenant Cloud
# Storage bucket.
#
# Build context is the repository root:  docker build -f services/gateway/Dockerfile .

FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release -p permaura-gateway

FROM debian:bookworm-slim
# ca-certificates: verify permaura.com and Google API TLS. Nothing here links against OpenSSL: the
# HTTP stack is rustls throughout.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/permaura /usr/local/bin/permaura
# Cloud Run sets $PORT (default 8080); the gateway reads PERMAURA_ADDR, so map one to the other.
# `start` is explicit because the bare binary prints help and starts nothing.
ENTRYPOINT ["/bin/sh", "-c", "PERMAURA_ADDR=0.0.0.0:${PORT:-8080} exec /usr/local/bin/permaura start"]
