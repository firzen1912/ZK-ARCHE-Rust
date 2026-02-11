# ZK-ARCHE (Rust Implementation)

Lightweight Schnorr Zero-Knowledge Mutual Authentication over
Ristretto255.

------------------------------------------------------------------------

## Overview

Rust implementation of ZK-ARCHE, a lightweight elliptic-curve-based
mutual authentication protocol for IoT and edge systems.

### Cryptographic Design

-   Group: Ristretto255 (prime-order abstraction over Curve25519)
-   Proof System: Schnorr ZKP (Fiat--Shamir)
-   Transcript: Deterministic C-compatible transcript
-   Hash: SHA-512 (challenge derivation)
-   KDF: HKDF-SHA256
-   Transport: TCP over LAN

------------------------------------------------------------------------

## 1. Install Dependencies (Ubuntu / Raspberry Pi OS)

``` bash
sudo apt update
sudo apt install build-essential pkg-config git curl
```

Install Rust:

``` bash
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
rustup update
```

------------------------------------------------------------------------

## 2. Build

``` bash
cargo build --release
```

Binaries will be in:

    target/release/client
    target/release/server

------------------------------------------------------------------------

## 3. Run Server

``` bash
cargo run --release --bin server -- --bind 0.0.0.0:4000 --pairing
```

Optional arguments:

``` bash
--bind <IP:PORT>
--pairing
--pairing-token <TOKEN>
--pairing-seconds <SECONDS>
```

------------------------------------------------------------------------

## 4. Provision Device (SETUP)

``` bash
cargo run --release --bin client -- --server 127.0.0.1:4000 --setup
```

Creates:

    device_id.bin
    device_x.bin

------------------------------------------------------------------------

## 5. Authenticate (AUTH)

``` bash
cargo run --release --bin client -- --server 127.0.0.1:4000
```

------------------------------------------------------------------------

## 6. Reset Environment

``` bash
rm -f device_id.bin device_x.bin registry.bin registry.bak
```

------------------------------------------------------------------------

## Research Notice

Research prototype. Not production hardened.
