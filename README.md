
---

# ZK-ARCHE (Rust Implementation)

Lightweight **Zero-Knowledge Proof Mutual Authentication** using Schnorr proofs over **Ristretto255**.

This Rust implementation is the reference implementation of the ZK-ARCHE protocol and interoperates with the C version used for embedded and IoT environments. The current onboarding path uses **mutual certificate-based Zero-Touch Provisioning (ZTP)** and keeps the existing authenticated transport and Schnorr-based operational authentication.

The system supports:

* **Zero-Touch Provisioning (ZTP)**
* **Schnorr Zero-Knowledge Authentication**
* **Secure encrypted communication channel**

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

| Primitive        | Algorithm         |
| ---------------- | ----------------- |
| Group            | Ristretto255      |
| Proof System     | Schnorr ZKP       |
| Fiat-Shamir Hash | SHA-512           |
| Key Derivation   | HKDF-SHA256       |
| Encryption       | ChaCha20-Poly1305 |
| Transport        | TCP               |

Libraries used:

* `curve25519-dalek`
* `sha2`
* `hkdf`
* `chacha20poly1305`
* `rand`

---

# Security Model

The protocol separates **two identities**.

---

## 1️⃣ Bootstrap Identity (Provisioning)

Used **only during device onboarding**.

Device proves knowledge of:

```
bootstrap_secret
```

Server verifies against:

```
bootstrap_registry.bin
```

This enables **Zero-Touch Provisioning**.

---

## 2️⃣ Operational Identity (Authentication)

Derived from the device root secret:

```
device_root.bin
```

Client derives:

```
device_id
device_private_scalar x
device_public_key = G * x
```

Authentication uses a **Schnorr Zero-Knowledge Proof**.

---

# File Layout

## Client (IoT Device)

```text
/var/lib/iot-auth/

device_root.bin
bootstrap_id.bin
bootstrap_secret.bin
server_pub.bin
```

| File                 | Purpose                    |
| -------------------- | -------------------------- |
| device_root.bin      | device root secret         |
| bootstrap_id.bin     | bootstrap identifier       |
| bootstrap_secret.bin | bootstrap credential       |
| server_pub.bin       | pinned verifier public key |

---

## Server (Verifier)

```text
registry.bin
server_sk.bin
server_cert.pem
server_cert_key.pem
ca_cert.pem
certs/
```

| File                   | Purpose                    |
| ---------------------- | -------------------------- |
| registry.bin           | enrolled device identities |
| bootstrap_registry.bin | bootstrap credentials      |
| server_sk.bin          | verifier private key       |

---

# Install Dependencies

Ubuntu / Raspberry Pi OS

```bash
sudo apt update
sudo apt install build-essential pkg-config git curl
```

Install Rust:

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
./target/release/client
./target/release/server
```

You can also build individually:

```bash
cargo build --release --bin server
cargo build --release --bin client
```

If you are using the updated mutual-certificate onboarding code, add this dependency to `Cargo.toml` before building:

```toml
openssl = { version = "0.10", features = ["vendored"] }
```

---

# Server Setup

## 1️⃣ Add Bootstrap Credentials

Each device requires a unique bootstrap credential.

Generate credentials:

```bash
BOOTSTRAP_ID=$(openssl rand -hex 16)
BOOTSTRAP_SECRET=$(openssl rand -hex 32)
```

Add them to the bootstrap registry:

```bash
./target/release/server --add-bootstrap $BOOTSTRAP_ID $BOOTSTRAP_SECRET
```

---

## 2️⃣ Start the Verifier

Enable provisioning window:

```bash
./target/release/server --bind 0.0.0.0:4000 --pairing
```

Without `--pairing`, device setup is rejected.

---

# Device Provisioning (ZTP)

Before provisioning, install bootstrap credentials on the device.

```bash
./target/release/client --provision-bootstrap <bootstrap_id_hex> <bootstrap_secret_hex>
```

Pin the server public key:

```bash
./target/release/client --pin-server-pub <server_pub_hex>
```

Run provisioning:

```bash
./target/release/client --server <server_ip>:4000 --setup
```

**Client — enroll with pairing token:**

```bash
./target/release/client --server <server_ip>:4000 --setup --pairing-token mysecrettoken
```

The device will now be enrolled in `registry.bin`.

---

# Authentication

After provisioning, devices authenticate normally.

```bash
./target/release/client --server <server_ip>:4000
```

Authentication uses:

```
Schnorr Zero-Knowledge Proof
```

over an encrypted transport channel.

---

# Example Deployment

Verifier:

```
Ubuntu Server
192.168.1.10
```

Provers:

```
Raspberry Pi 3 → 192.168.1.101
Raspberry Pi 4 → 192.168.1.102
Raspberry Pi 5 → 192.168.1.103
```

Provision each device once, then authenticate repeatedly.

---

# Reset Environment

Client reset:

```bash
sudo rm -rf /var/lib/iot-auth
```

Server reset:

```bash
rm -f registry.bin bootstrap_registry.bin server_sk.bin
```

---

# Research Notice

This project is a research prototype for:

* IoT authentication protocols
* Zero-knowledge identification systems
* cross-language cryptographic interoperability
* evaluation on constrained devices

Not intended for production deployment without additional hardening.
