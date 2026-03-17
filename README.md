# ZK-ARCHE (Rust Implementation)

Lightweight **Zero-Knowledge Proof Mutual Authentication** using Schnorr proofs over **Ristretto255**.

This Rust implementation is the reference implementation of the ZK-ARCHE protocol and interoperates with the C version used for embedded and IoT environments. The current onboarding path uses **mutual certificate-based Zero-Touch Provisioning (ZTP)** and keeps the existing authenticated transport and Schnorr-based operational authentication.

The system supports:

* **Mutual certificate-based ZTP** for first enrollment
* **Schnorr Zero-Knowledge Authentication** for operational access
* **Encrypted identity-protecting transport** using X25519
* **Mutual authentication** with key confirmation MACs

---

# Architecture

| Component              | Role                                      |
| ---------------------- | ----------------------------------------- |
| Raspberry Pi 3 / 4 / 5 | Provers (IoT devices)                     |
| Ubuntu Server          | Verifier                                  |
| X.509 CA               | Trust anchor for onboarding               |
| Device Root Secret     | Persistent operational device identity    |
| Device / Server Certs  | Enrollment authorization and peer binding |

---

# Cryptographic Design

| Primitive            | Algorithm                               |
| -------------------- | --------------------------------------- |
| Group                | Ristretto255                            |
| Proof System         | Schnorr ZKP                             |
| Fiat-Shamir Hash     | SHA-512                                 |
| Key Derivation       | HKDF-SHA256                             |
| Encryption           | ChaCha20-Poly1305                       |
| Anonymous Tunnel     | X25519 ECDHE + Blake2b512               |
| Key Confirmation     | HMAC-SHA256 (server + client MAC)       |
| Transcript           | Length-prefixed domain-separated        |
| Certificates         | X.509 (OpenSSL-generated demo PKI)      |
| Constant-time ops    | `subtle` crate                          |
| Secret zeroisation   | `zeroize` crate                         |
| Transport            | TCP                                     |

Libraries used:

* `curve25519-dalek = "4"`
* `x25519-dalek = { version = "2.0", features = ["static_secrets"] }`
* `sha2`, `hkdf`, `hmac`, `blake2`
* `chacha20poly1305`
* `rand`, `hex`, `subtle`, `zeroize`
* `openssl = { version = "0.10", features = ["vendored"] }`

---

# Security Model

The protocol separates **onboarding trust** from **operational authentication**.

---

## 1. Mutual Certificate-Based Onboarding (SETUP)

Used only during device enrollment.

During `SETUP`:

* the **device presents a device certificate** and proves possession of the matching private key
* the **server presents a server certificate** and proves possession of the matching private key
* both sides validate the same CA chain
* both sides sign the same setup transcript
* the server sends the `0x01` enrollment acknowledgment only after all setup checks succeed

This removes the old bootstrap-secret dependency and avoids Trust-On-First-Use for first contact.

### Setup transcript binding

The mutual-certificate setup flow binds at least:

```text
"ztp-mutual-cert-v1"
|| device_id
|| device_static_pub
|| client_nonce
|| server_nonce
|| H(device_cert_der)
|| H(server_cert_der)
```

That transcript is signed by both peers during onboarding.

---

## 2. Operational Identity (Authentication)

Operational identity is still derived deterministically from the device root secret:

```text
device_root.bin  →  device_id
              →  device_private_scalar x
              →  device_public_key = G * x
```

Operational authentication continues to use a **Schnorr Zero-Knowledge Proof** over an **anonymous X25519 encrypted tunnel**, so the device identity remains hidden from passive observers.

Mutual authentication is confirmed with **key confirmation MACs** (`server finished` + `client finished`) over the full session transcript.

---

## 3. Compatibility Pinning for AUTH_V2

The onboarding path no longer requires TOFU. However, the current code still keeps a pinned `server_pub.bin` for compatibility with the existing `AUTH_V2` flow.

That means:

* **SETUP** uses mutual certificate validation
* **AUTH_V2** may still rely on the pinned server compatibility key
* manual out-of-band pinning via `--pin-server-pub` is still available

This is a migration boundary, not the root of trust for first enrollment.

---

# File Layout

## Client (IoT Device)

```text
/var/lib/iot-auth/
    device_root.bin
    device_cert.pem
    device_key.pem
    ca_cert.pem
    server_pub.bin          ← compatibility pin for current AUTH_V2 path
```

| File              | Purpose |
| ----------------- | ------- |
| `device_root.bin` | Device root secret used to derive operational identity |
| `device_cert.pem` | Device X.509 certificate used during SETUP |
| `device_key.pem`  | Device private key used to sign the setup transcript |
| `ca_cert.pem`     | Trusted CA certificate used to validate the server cert |
| `server_pub.bin`  | Optional compatibility pin for the current `AUTH_V2` path |

## Server (Verifier)

```text
registry.bin
server_sk.bin
server_cert.pem
server_cert_key.pem
ca_cert.pem
certs/
```

| File                  | Purpose |
| --------------------- | ------- |
| `registry.bin`        | Enrolled device identities |
| `server_sk.bin`       | Server static private key used by the current operational auth path |
| `server_cert.pem`     | Server X.509 certificate presented during SETUP |
| `server_cert_key.pem` | Server private key used to sign the setup transcript |
| `ca_cert.pem`         | CA certificate that signs trusted device and server certs |
| `certs/`              | Working directory for generated demo PKI artifacts |

---

# Install Dependencies

**Ubuntu / Raspberry Pi OS:**

```bash
sudo apt update
sudo apt install build-essential pkg-config git curl xxd openssl python3
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

```text
./target/release/server
./target/release/client
```

Build individually:

```bash
cargo build --release --bin server
cargo build --release --bin client
```

If you are using the updated mutual-certificate onboarding code, add this dependency to `Cargo.toml` before building:

```toml
openssl = { version = "0.10", features = ["vendored"] }
```

---

# Automation Script

All operations can be run through the updated `zk-arche.sh` workflow.

```text
Usage:
  ./zk-arche.sh build
  ./zk-arche.sh make-certs [device_id_hex]
  ./zk-arche.sh check-server-certs
  ./zk-arche.sh check-client-certs
  ./zk-arche.sh install-client-certs
  ./zk-arche.sh start-server <bind_addr> [--pairing] [--pairing-token <t>] [--pairing-seconds <n>]
  ./zk-arche.sh server-local <bind_addr>
  ./zk-arche.sh setup-device <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh auth-device <server_ip:port>
  ./zk-arche.sh show-pinned-key
  ./zk-arche.sh pin-server <server_pub_hex>
  ./zk-arche.sh status
  ./zk-arche.sh client-local <server_ip:port> [--pairing-token <t>]
  ./zk-arche.sh full-device-onboard <server_ip:port> [--pairing-token <t>] [--server-pub <server_pub_hex>]
  ./zk-arche.sh reset-client | reset-server | reset-all
```

---

# Deployment

## Two-Machine Setup (Recommended)

The onboarding path now uses **mutual certificate validation** instead of bootstrap secrets.

**Server machine:**

```bash
./zk-arche.sh build
./zk-arche.sh make-certs
./zk-arche.sh start-server 0.0.0.0:4000 --pairing
```

**Client machine:**

```bash
./zk-arche.sh build
./zk-arche.sh install-client-certs
./zk-arche.sh setup-device <server_ip>:4000
./zk-arche.sh auth-device <server_ip>:4000
```

If the server requires a pairing token:

```bash
./zk-arche.sh setup-device <server_ip>:4000 --pairing-token mysecrettoken
```

---

## Single-Machine Local Test

**Terminal 1:**

```bash
./zk-arche.sh build
./zk-arche.sh make-certs
./zk-arche.sh server-local 127.0.0.1:4000
```

**Terminal 2:**

```bash
./zk-arche.sh client-local 127.0.0.1:4000
./zk-arche.sh auth-device 127.0.0.1:4000
```

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

## Optional: Manual Compatibility Pinning

The onboarding path does not require TOFU, but you may still pin the current operational server key for compatibility with `AUTH_V2`:

```bash
./zk-arche.sh pin-server <server_pub_hex>
./zk-arche.sh setup-device <server_ip>:4000
```

---

# Raw Binary Usage (without script)

**Server — start with pairing window:**

```bash
./target/release/server --bind 0.0.0.0:4000 --pairing
```

**Client — enroll with mutual certificates:**

```bash
./target/release/client --server <server_ip>:4000 --setup
```

**Client — enroll with pairing token:**

```bash
./target/release/client --server <server_ip>:4000 --setup --pairing-token mysecrettoken
```

**Client — authenticate:**

```bash
./target/release/client --server <server_ip>:4000
```

**Client — optional compatibility pin:**

```bash
./target/release/client --pin-server-pub <server_pub_hex>
```

---

# Example Deployment

```text
Verifier:  Ubuntu Server    192.168.1.10
Provers:   Raspberry Pi 3   192.168.1.101
           Raspberry Pi 4   192.168.1.102
           Raspberry Pi 5   192.168.1.103
```

Each device is issued a device certificate and enrolled once using mutual certificate validation. After enrollment, it authenticates repeatedly using its Schnorr ZKP operational identity.

---

# Inspecting State

```bash
./zk-arche.sh status
./zk-arche.sh check-server-certs
./zk-arche.sh check-client-certs
./zk-arche.sh show-pinned-key
```

---

# Reset Environment

```bash
./zk-arche.sh reset-all

# Or individually:
./zk-arche.sh reset-client
./zk-arche.sh reset-server
```

Manual equivalents:

```bash
# Client
sudo rm -rf /var/lib/iot-auth

# Server
rm -f registry.bin registry.bak \
      server_sk.bin server_pub.bin server_pub.hex \
      server_cert.pem server_cert_key.pem ca_cert.pem
rm -rf certs
```

---

# Certificate Generation Caveat

The current `make-certs` helper is suitable for a demo workflow, but it presently uses placeholder `OU` values when issuing the certificates.

That means:

* the **device cert CN** is aligned to the client `device_id`
* the **OU fields are placeholders** unless you reissue with the exact compressed Ristretto public keys

If your final Rust verifier/client enforce exact certificate binding to `device_static_pub` or `server_static_pub`, you must regenerate the certs so those fields match the real protocol public keys exactly.

---

# Research Notice

This project is a research prototype for:

* IoT authentication protocols
* Zero-knowledge identification systems
* Cross-language cryptographic interoperability
* Evaluation on constrained devices (Raspberry Pi, embedded Linux)

It is not intended for production deployment without additional hardening, PKI policy enforcement, certificate revocation handling, and a full end-to-end security review.
