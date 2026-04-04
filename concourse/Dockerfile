FROM rust:1.84-slim-bullseye

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git \
    pkg-config \
    libssl-dev \
    libdbus-1-dev \
    libsecret-1-dev \
    python3 \
    gcc \
    g++ \
    make \
    curl \
  && rm -rf /var/lib/apt/lists/*

RUN rustup component add rustfmt clippy

ENV RUST_BACKTRACE=1 \
    CARGO_TERM_COLOR=always \
    CLICOLOR=1

WORKDIR /workspace
