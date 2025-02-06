FROM rust:alpine AS builder
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    sqlite-dev \
    sqlite-libs \
    sqlite-static \
    git

RUN git config --global net.git-fetch-with-cli true

WORKDIR /usr/src/w3registrar
COPY . .
RUN rustup target add x86_64-unknown-linux-musl && \
    cargo build --target x86_64-unknown-linux-musl --release

FROM alpine
RUN apk add --no-cache \
    openssl \
    ca-certificates && \
    mkdir -p /etc/w3registrar && \
    addgroup -S w3r && \
    adduser -S w3r -G w3r && \
    chown -R w3r:w3r /etc/w3registrar

COPY --from=builder /usr/src/w3registrar/target/x86_64-unknown-linux-musl/release/w3registrar /usr/local/bin/
USER w3r
WORKDIR /etc/w3registrar
CMD ["w3registrar"]
