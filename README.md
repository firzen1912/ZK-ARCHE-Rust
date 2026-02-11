# ZK-ARCHE (Rust Implementation)

Lightweight Schnorr Zero-Knowledge Mutual Authentication over
Ristretto255.

## Overview

This repository contains the Rust implementation of ZK-ARCHE, a
lightweight elliptic curve--based mutual authentication framework
designed for IoT and edge environments.

### Cryptographic Design

-   Group: Ristretto255 (prime-order abstraction over Curve25519)
-   Proof System: Schnorr Zero-Knowledge Proof (Fiat--Shamir
    transformed)
-   Transcript: Deterministic C-compatible transcript
-   Hash: SHA-512 (challenge derivation)
-   KDF: HKDF-SHA256
-   Transport: TCP over LAN

------------------------------------------------------------------------

## Requirements

Ubuntu / Raspberry Pi OS:

sudo apt update\
sudo apt install build-essential pkg-config git

Install Rust:

curl https://sh.rustup.rs -sSf \| sh\
source \~/.cargo/env\
rustup update

------------------------------------------------------------------------

## Build

cargo build --release

Binaries:

target/release/client\
target/release/server

------------------------------------------------------------------------

## Run Server

cargo run --release --bin server -- --bind 0.0.0.0:4000 --pairing

Options:

--bind `<IP:PORT>`{=html}\
--pairing\
--pairing-token `<TOKEN>`{=html}\
--pairing-seconds `<SECONDS>`{=html}

------------------------------------------------------------------------

## Provisioning (SETUP)

cargo run --release --bin client -- --server 127.0.0.1:4000 --setup

Creates:

device_id.bin\
device_x.bin

------------------------------------------------------------------------

## Authentication (AUTH)

cargo run --release --bin client -- --server 127.0.0.1:4000

------------------------------------------------------------------------

## Reset

rm -f device_id.bin device_x.bin registry.bin registry.bak

------------------------------------------------------------------------

## Research Prototype Notice

For research and academic evaluation only. Not production hardened.
