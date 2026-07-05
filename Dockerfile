FROM rust:1.88-alpine AS builder

WORKDIR /app
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM alpine:3.22

RUN adduser -S -D -H -u 10001 -s /sbin/nologin storage-harvester

COPY --from=builder /app/target/release/storage-harvester /usr/local/bin/storage-harvester

EXPOSE 9799

ENTRYPOINT ["/usr/local/bin/storage-harvester"]
CMD ["--config", "/etc/storage-harvester/config.yaml"]
