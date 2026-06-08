FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
# Cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && \
    SQLX_OFFLINE=true cargo build --release && rm -rf src

COPY src ./src
RUN touch src/main.rs && SQLX_OFFLINE=true cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates libssl3 curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/soc-auth .
COPY migrations ./migrations

ENV RUST_LOG=info
CMD ["./soc-auth"]