# ZK-ARCHE (Rust Implementation)

Lightweight **Zero-Knowledge Proof Mutual Authentication** using Schnorr proofs over **Ristretto255**.

This Rust implementation is the **reference implementation** of the ZK-ARCHE protocol and interoperates with the C version used for embedded and IoT environments.

The system supports:

* **Zero-Touch Provisioning (ZTP)** with Trust-On-First-Use (TOFU) server key discovery
* **Schnorr Zero-Knowledge Authentication**
* **Encrypted zero-privacy transport** (device identity hidden inside X25519 tunnel)
* **Mutual authentication** with key confirmation MACs

---

# Architecture

| Component              | Role                       |
| ---------------------- | -------------------------- |
| Raspberry Pi 3 / 4 / 5 | Provers (IoT devices)      |
| Ubuntu Server          | Verifier                   |
| Bootstrap Registry     | Provisioning database      |
| Device Root Secret     | Persistent device identity |

---

# Cryptographic Design

| Primitive            | Algorithm                        |
| -------------------- | -------------------------------- |
| Group                | Ristretto255                     |
| Proof System         | Schnorr ZKP                      |
| Fiat-Shamir Hash     | SHA-512                          |
| Key Derivation       | HKDF-SHA256                      |
| Encryption           | ChaCha20-Poly1305                |
| Anonymous Tunnel     | X25519 ECDHE + Blake2b512        |
| Key Confirmation     | HMAC-SHA256 (server + client MAC)|
| Transcript           | Length-prefixed domain-separated |
| Constant-time ops    | `subtle` crate                   |
| Secret zeroisation   | `zeroize` crate                  |
| Transport            | TCP                              |

Libraries used:

* `curve25519-dalek = "4"`
* `x25519-dalek = { version = "2.0", features = ["static_secrets"] }`
* `sha2`, `hkdf`, `hmac`, `blake2`
* `chacha20poly1305`
* `rand`, `hex`, `subtle`, `zeroize`

---

# Security Model

The protocol separates **two identities** and uses a two-phase handshake.

---

## 1. Bootstrap Identity (Provisioning)

Used **only during device onboarding (SETUP)**.

The device proves knowledge of a pre-shared `bootstrap_secret` via an HMAC-SHA256 MAC. The MAC transcript binds:

```
bootstrap_id  ||  device_id  ||  device_pub
||  server_pub  ||  client_nonce  ||  server_nonce
```

Because `server_pub` is included in the transcript, **a MITM cannot substitute the server's public key** without breaking the MAC check on the server side.

Server verifies against:

```
bootstrap_registry.bin
```

This enables **Zero-Touch Provisioning** with no manual key copying required.

---

## 2. Operational Identity (Authentication)

Derived deterministically from the device root secret:

```
device_root.bin  →  device_id
              →  device_private_scalar x
              →  device_public_key = G * x
```

Authentication uses a **Schnorr Zero-Knowledge Proof** over an **anonymous X25519 encrypted tunnel** so the device identity is hidden from passive observers.

Mutual authentication is confirmed with **key confirmation MACs** (`server finished` + `client finished`) over the full session transcript.

---

## 3. Server Key Discovery (TOFU)

On first contact, the client has no prior knowledge of the server's public key. The key is received over the wire during SETUP and cryptographically bound into the bootstrap MAC transcript. The server only sends a `0x01` enrollment acknowledgment **after** verifying the MAC against its own real public key.

The client pins `server_pub.bin` to disk **only after receiving this ack** — so a MITM-substituted key is never pinned.

On all subsequent connections (re-enrollment and AUTH) the pinned key is enforced with a constant-time comparison.

Manual out-of-band pinning via `--pin-server-pub` is still supported for deployments that require it.

---

# File Layout

## Client (IoT Device)

```
/var/lib/iot-auth/
    device_root.bin
    bootstrap_id.bin
    bootstrap_secret.bin
    server_pub.bin          ← auto-pinned via TOFU during first setup
```

| File                   | Purpose                                          |
| ---------------------- | ------------------------------------------------ |
| `device_root.bin`      | Device root secret (32 bytes)                    |
| `bootstrap_id.bin`     | Bootstrap identifier (32 bytes)                  |
| `bootstrap_secret.bin` | Bootstrap credential (32 bytes)                  |
| `server_pub.bin`       | Pinned verifier public key — written after TOFU ack |

## Server (Verifier)

```
registry.bin
bootstrap_registry.bin
server_sk.bin
```

| File                     | Purpose                            |
| ------------------------ | ---------------------------------- |
| `registry.bin`           | Enrolled device identities         |
| `bootstrap_registry.bin` | Bootstrap credentials              |
| `server_sk.bin`          | Verifier static private key        |

---

# Install Dependencies

**Ubuntu / Raspberry Pi OS:**

```bash
sudo apt update
sudo apt install build-essential pkg-config git curl xxd openssl
```

**Install Rust:**

```bash
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
rustup update
```

---

# Compile (Release Build)

```bash
cargo build --release
```

Binaries:

```
./target/release/server
./target/release/client
```

Build individually:

```bash
cargo build --release --bin server
cargo build --release --bin client
```

---

# Automation Script

All operations can be run through the included `zk-arche.sh` script.

```
Usage:
  ./zk-arche.sh build
  ./zk-arche.sh add-bootstrap [<id_hex> <secret_hex>]
  ./zk-arche.sh show-bootstrap
  ./zk-arche.sh start-server <bind_addr> [--pairing] [--pairing-token <t>] [--pairing-seconds <n>]
  ./zk-arche.sh server-local <bind_addr>
  ./zk-arche.sh provision-bootstrap <id_hex> <secret_hex>
  ./zk-arche.sh setup-device <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh auth-device <server_ip:port>
  ./zk-arche.sh show-pinned-key
  ./zk-arche.sh pin-server <server_pub_hex>
  ./zk-arche.sh status
  ./zk-arche.sh client-local <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh full-device-onboard <server_ip:port> <id_hex> <secret_hex> [<server_pub_hex>]
  ./zk-arche.sh reset-client | reset-server | reset-all
```

---

# Deployment

## Two-Machine Setup (Recommended)

No manual key exchange is required. The server public key is auto-pinned via TOFU.

**Server machine:**

```bash
./zk-arche.sh build
./zk-arche.sh add-bootstrap
./zk-arche.sh show-bootstrap          # note BOOTSTRAP_ID and BOOTSTRAP_SECRET
./zk-arche.sh start-server 0.0.0.0:4000 --pairing
```

**Client machine** (paste the values from `show-bootstrap`):

```bash
./zk-arche.sh build
./zk-arche.sh provision-bootstrap <BOOTSTRAP_ID> <BOOTSTRAP_SECRET>
./zk-arche.sh setup-device <server_ip>:4000     # server key auto-pinned via TOFU
./zk-arche.sh auth-device <server_ip>:4000
```

---

## Single-Machine Local Test

**Terminal 1:**

```bash
./zk-arche.sh build
./zk-arche.sh add-bootstrap
./zk-arche.sh server-local 127.0.0.1:4000
```

**Terminal 2:**

```bash
./zk-arche.sh client-local 127.0.0.1:4000
./zk-arche.sh auth-device 127.0.0.1:4000
```

`client-local` reads bootstrap values from `last_bootstrap.env` automatically.

---

## Optional: Pairing Token

To restrict which clients can enroll during a pairing window:

**Server:**
```bash
./zk-arche.sh start-server 0.0.0.0:4000 --pairing --pairing-token mysecrettoken --pairing-seconds 120
```

**Client:**
```bash
./zk-arche.sh setup-device <server_ip>:4000 --pairing-token mysecrettoken
```

---

## Optional: Manual Out-of-Band Key Pinning

If you prefer to pin the server public key manually before setup (skips TOFU):

```bash
# On the server, the public key is printed at startup:
#   Server public key (pin this on client): <hex>

./zk-arche.sh pin-server <server_pub_hex>
./zk-arche.sh setup-device <server_ip>:4000
```

---

## Raw Binary Usage (without script)

**Server — register bootstrap credential:**
```bash
./target/release/server --add-bootstrap <bootstrap_id_hex> <bootstrap_secret_hex>
```

**Server — start with pairing window:**
```bash
./target/release/server --bind 0.0.0.0:4000 --pairing
```

**Client — provision bootstrap + enroll:**
```bash
./target/release/client --provision-bootstrap <bootstrap_id_hex> <bootstrap_secret_hex>
./target/release/client --server <server_ip>:4000 --setup
```

**Client — authenticate:**
```bash
./target/release/client --server <server_ip>:4000
```

---

# Example Deployment

```
Verifier:  Ubuntu Server    192.168.1.10
Provers:   Raspberry Pi 3   192.168.1.101
           Raspberry Pi 4   192.168.1.102
           Raspberry Pi 5   192.168.1.103
```

Each device is provisioned once with a unique bootstrap credential. After enrollment, it authenticates repeatedly using its Schnorr ZKP identity — the bootstrap credential is never used again.

---

# Inspecting State

```bash
./zk-arche.sh status           # shows all file presence, bootstrap values, pinned key
./zk-arche.sh show-bootstrap   # print last generated bootstrap credential
./zk-arche.sh show-pinned-key  # print the server pub fingerprint pinned on this client
```

---

# Reset Environment

```bash
./zk-arche.sh reset-all        # wipes both client and server state

# Or individually:
./zk-arche.sh reset-client     # removes /var/lib/iot-auth
./zk-arche.sh reset-server     # removes registry, bootstrap db, server key files
```

Manual equivalents:

```bash
# Client
sudo rm -rf /var/lib/iot-auth

# Server
rm -f registry.bin registry.bak \
      bootstrap_registry.bin bootstrap_registry.bak \
      server_sk.bin server_pub.bin server_pub.hex \
      last_bootstrap.env
```

---

# Research Notice

This project is a **research prototype** for:

* IoT authentication protocols
* Zero-knowledge identification systems
* Cross-language cryptographic interoperability
* Evaluation on constrained devices (Raspberry Pi, embedded Linux)

Not intended for production deployment without additional hardening.