# ZK-ARCHE (Rust Implementation)

ZK-ARCHE is a Rust implementation of lightweight **zero-knowledge mutual authentication** for constrained and IoT-style environments. It uses **Schnorr proofs over Ristretto255** for device authentication, hides the device identity during the operational authentication flow, and supports **mutual-certificate onboarding** aligned with the C implementation.

## What this implementation provides

- **Mutual-certificate onboarding (SETUP)** using client and server certificates plus transcript signatures.
- **Pinned server key enforcement** during both setup and authentication to resist MITM substitution.
- **Hidden device identity during AUTH** using an X25519 ECDHE tunnel with ChaCha20-Poly1305 protected payloads.
- **Mutual authentication with key confirmation** using `server finished` and `client finished` style HMAC tags over the session transcript.
- **Replay protection** on the server with persistent nonce tracking.
- **A helper automation script** for building, certificate generation, local testing, setup, authentication, status checks, and state reset.

---

## Architecture

| Component | Role |
| --- | --- |
| Raspberry Pi / IoT device | Prover / client |
| Ubuntu / Linux server | Verifier / server |
| Device root secret | Stable per-device operational identity seed |
| Device certificate | Client onboarding credential |
| Server certificate | Server onboarding credential |
| CA certificate | Trust anchor for onboarding |
| Registry | Stores enrolled device identities |

---

## Cryptographic design

| Primitive | Algorithm |
| --- | --- |
| Group | Ristretto255 |
| Proof system | Schnorr ZKP |
| Fiat-Shamir hash | SHA-512 |
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| Anonymous tunnel | X25519 ECDHE |
| Transcript hash / device ID derivation support | Blake2b |
| Key confirmation | HMAC-SHA256 |
| Constant-time comparison | `subtle` |
| Secret cleanup | `zeroize` |
| Transport | TCP |

Primary Rust crates used in the code include `curve25519-dalek`, `x25519-dalek`, `sha2`, `hkdf`, `hmac`, `blake2`, `chacha20poly1305`, `rand`, `hex`, `subtle`, `zeroize`, and `openssl`.

---

## Protocol model

### 1. Operational device identity

The client stores a persistent `device_root.bin`. From that root secret, the implementation deterministically derives:

- `device_id`
- the device private scalar `x`
- the corresponding device public key `G * x`

This operational identity is what the Schnorr authentication flow proves knowledge of during AUTH.

### 2. Setup / onboarding

The current Rust implementation no longer uses the older bootstrap-secret onboarding flow. The setup path now follows a **certificate-based mutual onboarding handshake** aligned with the C version. The server loads its certificate, certificate private key, CA certificate, and static server secret; the client uses its device certificate, device private key, CA certificate, and pinned server public key state.

### 3. Authentication

During AUTH, the client proves possession of its operational secret with a Schnorr proof. The device identity is protected inside an X25519-based encrypted tunnel, and the server proves possession of its own static secret. Both sides then verify key-confirmation tags derived from the shared session context.

### 4. Server key pinning

The client stores the server’s pinned public key in:

```text
/var/lib/iot-auth/client/server_pub.bin
```

The helper script can show or set this value with `show-pinned-key` and `pin-server`. The Rust client also supports raw `--pin-server-pub <hex>`.

---

## State layout

### Client state

```text
/var/lib/iot-auth/client/
├── device_root.bin
├── device_cert.pem
├── device_key.pem
├── ca_cert.pem
└── server_pub.bin
```

| File | Purpose |
| --- | --- |
| `device_root.bin` | Persistent device root secret |
| `device_cert.pem` | Client certificate used during setup |
| `device_key.pem` | Client certificate private key |
| `ca_cert.pem` | Trusted CA certificate |
| `server_pub.bin` | Pinned server Ristretto public key |

### Server state

```text
/var/lib/iot-auth/server/
├── registry.bin
├── registry.bak
├── server_sk.bin
├── server_cert.pem
├── server_cert_key.pem
├── ca_cert.pem
├── ca_key.pem              # optional after export-ca-key
└── server_pub.hex
```

| File | Purpose |
| --- | --- |
| `registry.bin` | Enrolled device registry |
| `registry.bak` | Registry backup |
| `server_sk.bin` | Server static secret for protocol authentication |
| `server_cert.pem` | Server certificate used during setup |
| `server_cert_key.pem` | Server certificate private key |
| `ca_cert.pem` | CA certificate |
| `ca_key.pem` | CA private key used to issue certs; intended to be moved offline |
| `server_pub.hex` | Hex copy of the server public key |

### Generated files

The automation script also uses:

```text
/var/lib/iot-auth/generated/
├── device_cert.pem
├── device_key.pem
├── device.csr
├── server.csr
└── ca_cert.srl
```

These are temporary or generated artifacts used while creating and installing certificates. The script securely removes the generated device private key after installation into the client state directory.

---

## System dependencies

On Ubuntu or Raspberry Pi OS, install the build and runtime prerequisites first:

```bash
sudo apt update
sudo apt install -y build-essential gcc pkg-config git curl xxd openssl libssl-dev libsodium-dev
```

Why these are needed:

- `libssl-dev` is needed for the Rust `openssl` crate used by both client and server.
- `libsodium-dev` and `gcc` are needed because `zk-arche.sh` builds a small helper C program that derives the client identity from `device_root.bin`.

Install Rust:

```bash
curl https://sh.rustup.rs -sSf | sh
source ~/.cargo/env
rustup update
```

---

## Build

Build both binaries:

```bash
cargo build --release
```

Resulting binaries:

```text
./target/release/server
./target/release/client
```

Or build individually:

```bash
cargo build --release --bin server
cargo build --release --bin client
```

---

## Automation script

The repository includes `zk-arche.sh`, which is the recommended way to manage state, generate demo certificates, run local tests, and execute setup/authentication flows. Its current command surface is:

```text
./zk-arche.sh build
./zk-arche.sh make-certs
./zk-arche.sh install-client-certs
./zk-arche.sh check-server-certs
./zk-arche.sh check-client-certs
./zk-arche.sh export-ca-key
./zk-arche.sh start-server <bind_addr> [opts]
./zk-arche.sh server-local <bind_addr>
./zk-arche.sh setup-device <server_ip:port> [--pairing-token <token>]
./zk-arche.sh auth-device <server_ip:port>
./zk-arche.sh show-pinned-key
./zk-arche.sh pin-server <server_pub_hex>
./zk-arche.sh status
./zk-arche.sh client-local <server_ip:port> [--pairing-token <token>]
./zk-arche.sh full-device-onboard <server_ip:port> [--pairing-token <token>]
./zk-arche.sh reset-client
./zk-arche.sh reset-server
./zk-arche.sh reset-all
```

Notable behavior:

- `make-certs` generates a CA, server certificate, and device certificate, then installs client cert material.
- `export-ca-key` prints the CA private key and removes it from the server so it can be stored offline.
- `status` reports current server state, client state, generated files, and derived identities.

---

## Recommended local test flow

This is the simplest end-to-end smoke test on one machine.

### Terminal 1

```bash
./zk-arche.sh build
./zk-arche.sh reset-all
./zk-arche.sh make-certs
sudo ./zk-arche.sh server-local 127.0.0.1:4000
```

### Terminal 2

```bash
sudo ./zk-arche.sh client-local 127.0.0.1:4000
sudo ./zk-arche.sh auth-device 127.0.0.1:4000
```

---

## Two-machine flow

### Server host

```bash
./zk-arche.sh build
./zk-arche.sh reset-all
./zk-arche.sh make-certs
sudo ./zk-arche.sh start-server 0.0.0.0:4000 --pairing
```

### Client host

Copy or install the matching client materials so the client host has:

- `/var/lib/iot-auth/client/device_root.bin`
- `/var/lib/iot-auth/client/device_cert.pem`
- `/var/lib/iot-auth/client/device_key.pem`
- `/var/lib/iot-auth/client/ca_cert.pem`

Then run:

```bash
sudo ./zk-arche.sh setup-device <server_ip>:4000
sudo ./zk-arche.sh auth-device <server_ip>:4000
```

The setup step performs mutual-certificate onboarding and stores the operational pinned server key if present.

---

## Pairing window and optional token

The server can require an enrollment window and optionally a token.

Start the server with pairing enabled:

```bash
sudo ./zk-arche.sh start-server 0.0.0.0:4000 --pairing
```

Start the server with a token and expiration window:

```bash
sudo ./zk-arche.sh start-server 0.0.0.0:4000 --pairing --pairing-token mysecrettoken --pairing-seconds 120
```

Run setup from the client with the same token:

```bash
sudo ./zk-arche.sh setup-device <server_ip>:4000 --pairing-token mysecrettoken
```

The server binary supports `--pairing`, `--pairing-token`, and `--pairing-seconds`, and the client supports `--pairing-token` for setup.

---

## Manual server-key pinning

If you want to pin the server public key out-of-band before setup:

1. Print the server public key:

```bash
cd /var/lib/iot-auth/server
sudo /path/to/target/release/server --print-pubkey
```

or use the helper script after the server key exists:

```bash
./zk-arche.sh pin-server <server_pub_hex>
```

2. Verify the pinned key on the client:

```bash
./zk-arche.sh show-pinned-key
```

The raw client binary also supports:

```bash
./target/release/client --pin-server-pub <server_pub_hex>
```

---

## Raw binary usage

### Server

```bash
./target/release/server --bind 0.0.0.0:4000
./target/release/server --bind 0.0.0.0:4000 --pairing
./target/release/server --bind 0.0.0.0:4000 --pairing --pairing-token TOKEN --pairing-seconds 120
./target/release/server --print-pubkey
```

### Client

```bash
./target/release/client --server 127.0.0.1:4000 --setup
./target/release/client --server 127.0.0.1:4000 --setup --pairing-token TOKEN
./target/release/client --server 127.0.0.1:4000
./target/release/client --pin-server-pub <server_pub_hex>
./target/release/client --print-device-identity
```

---

## Security notes

- The setup path is certificate-based; do not rely on the older bootstrap-secret README flow for this version.
- `ca_key.pem` is intentionally convenient for demos, but it should not remain on the server in production. Run `./zk-arche.sh export-ca-key` and store the key offline.
- The generated device private key is cleaned from `/var/lib/iot-auth/generated` after installation to avoid leaving a second copy behind.
- The server rejects identity points and bounds encrypted payload sizes.

---

## Quick troubleshooting

Check current state:

```bash
./zk-arche.sh status
```

Check certificate material only:

```bash
./zk-arche.sh check-server-certs
./zk-arche.sh check-client-certs
```

Reset and rebuild demo state:

```bash
./zk-arche.sh reset-all
./zk-arche.sh build
./zk-arche.sh make-certs
```

---

# Research Notice

This project is a **research prototype** for:

* IoT authentication protocols
* Zero-knowledge identification systems
* Cross-language cryptographic interoperability
* Evaluation on constrained devices (Raspberry Pi, embedded Linux)

Not intended for production deployment without additional hardening.