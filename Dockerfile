FROM rust:1.88-alpine AS builder

WORKDIR /app
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

# 3.24 for ffmpeg 8: it turns photos by their EXIF orientation and reads DNG raws (3.22 has 6.1).
FROM alpine:3.24

# ffmpeg makes the atlas's thumbnails of image and video files (`thumbnails: true` targets).
RUN apk add --no-cache ffmpeg

RUN adduser -S -D -H -u 10001 -s /sbin/nologin storage-harvester

COPY --from=builder /app/target/release/storage-harvester /usr/local/bin/storage-harvester

EXPOSE 9799

ENTRYPOINT ["/usr/local/bin/storage-harvester"]
CMD ["--config", "/etc/storage-harvester/config.yaml"]
