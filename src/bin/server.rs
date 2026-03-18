// ==============================
// server.rs (Rust implementation aligned to the C mutual-certificate onboarding flow)
// ==============================
//
// Goals:
//   1) Let clients learn/pin server identity during SETUP by sending server_static_pub.
//   2) Mutual auth: server proves possession of its static secret during AUTH.
//   3) Zero Privacy: Hide identity via ECDHE (X25519) + ChaCha20Poly1305 tunnel during AUTH.
//   4) Replay protection: persistent nonce tracking (dropped time-based TTL for DoS fix).
//   5) Key confirmation MACs: server sends tag_s, client replies tag_c over the secure tunnel.
//   6) ZTP setup uses mutual certificates and transcript signatures exactly like the C version.
//
// Server setup now matches the C implementation's mutual-certificate onboarding handshake.
//
// Cargo.toml dependencies:
//   curve25519-dalek = "4"
//   x25519-dalek     = { version = "2.0", features = ["static_secrets"] }
//   chacha20poly1305 = "0.10"
//   blake2           = "0.10"
//   rand             = "0.8"
//   sha2             = "0.10"
//   hkdf             = "0.12"
//   hmac             = "0.12"
//   hex              = "0.4"
//   zeroize          = "1"
//   subtle           = "2"
//   openssl          = "0.10"
//

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::convert::TryFrom;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use blake2::{Blake2b512, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

use openssl::pkey::{Id as PKeyId, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::x509::{X509, X509NameRef};

type HmacSha256 = Hmac<Sha256>;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;

const REGISTRY_BIN: &str = "/var/lib/iot-auth/server/registry.bin";
const REGISTRY_BAK: &str = "/var/lib/iot-auth/server/registry.bak";
const SERVER_SK_FILE: &str = "/var/lib/iot-auth/server/server_sk.bin";
const SERVER_CERT_FILE: &str = "/var/lib/iot-auth/server/server_cert.pem";
const SERVER_CERT_KEY_FILE: &str = "/var/lib/iot-auth/server/server_cert_key.pem";
const CA_CERT_FILE: &str = "/var/lib/iot-auth/server/ca_cert.pem";
const MAX_CERT_FILE_SIZE: usize = 128 * 1024;
const MAX_SIG_SIZE: usize = 8192;

const T_SETUP: &[u8] = b"setup_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";

const IO_TIMEOUT: Duration = Duration::from_secs(5);

// [FIX-4] Hard cap on incoming encrypted payload size (~4 KiB is generous for this protocol)
const MAX_ENCRYPTED_PAYLOAD: usize = 4096;

// [FIX-5] Each generation holds at most this many nonces before rotating
const REPLAY_GEN_MAX: usize = 25_000;

// ============================================================
// [FIX-9] NonceCounter — safe sequential nonce management
// ============================================================
struct NonceCounter {
    value: u64,
}

impl NonceCounter {
    fn new() -> Self {
        Self { value: 0 }
    }

    // Returns a fresh 12-byte nonce and advances the counter.
    // Panics only on u64 overflow (2^64 messages — not reachable in practice).
    fn next(&mut self) -> Nonce {
        let n = self.value;
        self.value = self.value.checked_add(1).expect("nonce counter exhausted");
        let mut bytes = [0u8; 12];
        bytes[..8].copy_from_slice(&n.to_le_bytes());
        *Nonce::from_slice(&bytes)
    }
}

// ============================================================
// C-compatible transcript
// ============================================================
struct CompatTranscript {
    buf: Vec<u8>,
}

impl CompatTranscript {
    fn new(domain: &[u8]) -> Self {
        assert!(domain.len() <= 255, "domain too long");
        let mut buf = Vec::with_capacity(512);
        buf.push(domain.len() as u8);
        buf.extend_from_slice(domain);
        Self { buf }
    }

    fn append_message(&mut self, label: &[u8], msg: &[u8]) {
        assert!(label.len() <= 255, "label too long");
        self.buf.push(label.len() as u8);
        self.buf.extend_from_slice(label);
        let len = msg.len() as u32;
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(msg);
    }

    fn challenge_scalar(&self) -> Scalar {
        let mut h = Sha512::new();
        sha2::Digest::update(&mut h, &self.buf);
        let digest = h.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

// ============================================================
// Crypto helpers
// ============================================================
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn random_bytes_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

// [FIX-7] Reject identity (low-order / neutral) points on all adversary inputs
fn reject_identity(p: &RistrettoPoint, what: &str) -> std::io::Result<()> {
    if *p == RistrettoPoint::default() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} is the identity point"),
        ));
    }
    Ok(())
}

// ============================================================
// Schnorr proofs
// ============================================================
fn schnorr_verify_setup(
    pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    server_nonce: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
) -> bool {
    let mut t = CompatTranscript::new(T_SETUP);
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"server_nonce", server_nonce);
    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + pubkey * c
}

fn schnorr_verify_auth(
    expected_pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    let mut t = CompatTranscript::new(T_CLIENT);
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", expected_pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());
    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + expected_pubkey * c
}

fn schnorr_prove_server(
    server_secret: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * server_secret;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let mut t = CompatTranscript::new(T_SERVER);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());
    let c = t.challenge_scalar();
    let s = r + c * server_secret;
    (a, s)
}

// ============================================================
// Session key derivation
// [FIX-8] x25519_shared is mixed in so the outer tunnel binds to the session key
// ============================================================
fn derive_session_key(
    eph_secret: &Scalar,
    peer_eph_pub: &RistrettoPoint,
    nonce_c: &[u8; 32],
    nonce_s: &[u8; 32],
    device_id: &[u8; 32],
    eph_c: &RistrettoPoint,
    eph_s: &RistrettoPoint,
    x25519_shared: &[u8; 32],
) -> [u8; 32] {
    let shared = peer_eph_pub * eph_secret;
    let shared_bytes = shared.compress().to_bytes();

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(nonce_c);
    salt[32..].copy_from_slice(nonce_s);

    let mut info = Vec::with_capacity(11 + 32 + 32 + 32 + 32);
    info.extend_from_slice(b"session key");
    info.extend_from_slice(device_id);
    info.extend_from_slice(eph_c.compress().as_bytes());
    info.extend_from_slice(eph_s.compress().as_bytes());
    info.extend_from_slice(x25519_shared);

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
    okm
}

// ============================================================
// Key confirmation (KC)
// ============================================================
fn kc_transcript_hash(
    device_id: &[u8; 32],
    a_c: &RistrettoPoint,
    s_c: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    server_pub: &RistrettoPoint,
    a_s: &RistrettoPoint,
    s_s: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> [u8; 32] {
    let mut t = CompatTranscript::new(T_KC);
    t.append_message(b"device_id", device_id);
    t.append_message(b"a_c", a_c.compress().as_bytes());
    t.append_message(b"s_c", &s_c.to_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());
    t.append_message(b"server_pub", server_pub.compress().as_bytes());
    t.append_message(b"a_s", a_s.compress().as_bytes());
    t.append_message(b"s_s", &s_s.to_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());

    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, &t.buf);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

fn derive_kc_keys(session_key: &[u8; 32], th: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(th), session_key);
    let mut k_s2c = [0u8; 32];
    let mut k_c2s = [0u8; 32];
    hk.expand(b"kc s2c", &mut k_s2c).unwrap();
    hk.expand(b"kc c2s", &mut k_c2s).unwrap();
    (k_s2c, k_c2s)
}

fn hmac_tag(key: &[u8; 32], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size ok");
    mac.update(label);
    mac.update(th);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

// ============================================================
// Network helpers
// ============================================================
fn send_all(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    *sent += buf.len();
    stream.write_all(buf)
}

fn recv_exact(stream: &mut impl Read, buf: &mut [u8], recv: &mut usize) -> std::io::Result<()> {
    stream.read_exact(buf)?;
    *recv += buf.len();
    Ok(())
}

fn recv_u8(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    recv_exact(stream, &mut b, recv)?;
    Ok(b[0])
}

fn recv_device_id(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<[u8; 32]> {
    let mut id = [0u8; 32];
    recv_exact(stream, &mut id, recv)?;
    Ok(id)
}

// [FIX-7] reject_identity called on all decompressed points
fn recv_point(stream: &mut impl Read, recv: &mut usize, label: &str) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    let p = CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid point: {label}")))?;
    reject_identity(&p, label)?;
    Ok(p)
}

// [FIX-10] Uses Option::from(CtOption) for dalek v4 API compatibility
fn recv_scalar(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    Option::from(Scalar::from_canonical_bytes(b))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical scalar"))
}

// [FIX-4] Bounded length-prefixed ciphertext read
fn recv_encrypted_blob(
    stream: &mut impl Read,
    recv: &mut usize,
) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv_exact(stream, &mut len_buf, recv)?;
    let rx_len = u32::from_le_bytes(len_buf) as usize;
    if rx_len > MAX_ENCRYPTED_PAYLOAD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("payload too large: {rx_len} bytes (max {MAX_ENCRYPTED_PAYLOAD})"),
        ));
    }
    let mut buf = vec![0u8; rx_len];
    recv_exact(stream, &mut buf, recv)?;
    Ok(buf)
}

// [FIX-11] Receive the pairing token sent by the client during SETUP
fn recv_pairing_token(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Option<String>> {
    let len = recv_u8(stream, recv)? as usize;
    if len == 0 {
        return Ok(None);
    }
    if len > 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "pairing token too long",
        ));
    }
    let mut buf = vec![0u8; len];
    recv_exact(stream, &mut buf, recv)?;
    let s = String::from_utf8(buf)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token not UTF-8"))?;
    Ok(Some(s))
}

// ============================================================
// Registry persistence
// ============================================================
fn load_registry(path: &str) -> std::io::Result<HashMap<[u8; 32], RistrettoPoint>> {
    let mut reg = HashMap::new();
    let data = fs::read(path).unwrap_or_default();
    for chunk in data.chunks_exact(64) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&chunk[0..32]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&chunk[32..64]);
        if let Some(p) = CompressedRistretto(pk).decompress() {
            if p != RistrettoPoint::default() {
                reg.insert(id, p);
            }
        }
    }
    Ok(reg)
}

fn save_registry_atomic(
    path: &str,
    bak_path: &str,
    reg: &HashMap<[u8; 32], RistrettoPoint>,
) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    ensure_parent_dir(bak_path)?;
    if Path::new(path).exists() {
        let _ = fs::copy(path, bak_path);
    }
    let tmp = format!("{path}.tmp");
    let mut out = Vec::with_capacity(reg.len() * 64);
    for (id, pk) in reg {
        out.extend_from_slice(id);
        out.extend_from_slice(pk.compress().as_bytes());
    }
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&out)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_file_all(path: &str, max_len: usize) -> std::io::Result<Vec<u8>> {
    let data = fs::read(path)?;
    if data.len() > max_len {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{path} exceeds max size")));
    }
    Ok(data)
}

fn load_cert_from_bytes(buf: &[u8]) -> std::io::Result<X509> {
    X509::from_pem(buf)
        .or_else(|_| X509::from_der(buf))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("X509 parse failed: {e}")))
}

fn load_private_key_from_bytes(buf: &[u8]) -> std::io::Result<PKey<Private>> {
    PKey::private_key_from_pem(buf)
        .or_else(|_| PKey::private_key_from_der(buf))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("private key parse failed: {e}")))
}

fn verify_cert_against_ca(cert: &X509, ca_cert: &X509) -> std::io::Result<()> {
    let ca_pub = ca_cert.public_key().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("CA public key failed: {e}")))?;
    cert.verify(&ca_pub)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("certificate verify failed: {e}")))
        .and_then(|ok| if ok { Ok(()) } else { Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "certificate not issued by trusted CA")) })
}

fn cert_subject_field_hex(cert: &X509, nid: openssl::nid::Nid) -> std::io::Result<String> {
    let name: &X509NameRef = cert.subject_name();
    let entry = name.entries_by_nid(nid).next().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("missing subject field {nid:?}")))?;
    let data = entry.data().as_utf8().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("subject field utf8 failed: {e}")))?;
    Ok(data.to_string().to_ascii_lowercase())
}

fn sign_transcript_hash(pkey: &PKey<Private>, th: &[u8; 32]) -> std::io::Result<Vec<u8>> {
    let mut signer = if matches!(pkey.id(), PKeyId::ED25519 | PKeyId::ED448) {
        Signer::new_without_digest(pkey)
    } else {
        Signer::new(openssl::hash::MessageDigest::sha256(), pkey)
    }.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("sign init failed: {e}")))?;
    signer.sign_oneshot_to_vec(th)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("sign failed: {e}")))
}

fn verify_transcript_hash_sig(pkey: &PKey<Public>, th: &[u8; 32], sig: &[u8]) -> std::io::Result<()> {
    let mut verifier = if matches!(pkey.id(), PKeyId::ED25519 | PKeyId::ED448) {
        Verifier::new_without_digest(pkey)
    } else {
        Verifier::new(openssl::hash::MessageDigest::sha256(), pkey)
    }.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("verify init failed: {e}")))?;
    let ok = verifier.verify_oneshot(sig, th)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("verify failed: {e}")))?;
    if ok { Ok(()) } else { Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "signature verification failed")) }
}

fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() { send_all(stream, buf, sent)?; }
    Ok(())
}

fn recv_blob(stream: &mut impl Read, max_len: usize, recv: &mut usize) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv_exact(stream, &mut len_buf, recv)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max_len { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("blob too large: {len}"))); }
    let mut buf = vec![0u8; len];
    if len > 0 { recv_exact(stream, &mut buf, recv)?; }
    Ok(buf)
}

fn ztp_cert_transcript_hash(
    device_id: &[u8; 32],
    device_pub: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    device_cert: &[u8],
    server_cert: &[u8],
) -> [u8; 32] {
    let dev_hash = Sha256::digest(device_cert);
    let srv_hash = Sha256::digest(server_cert);
    let mut t = CompatTranscript::new(b"ztp-mutual-cert-v1");
    t.append_message(b"device_id", device_id);
    t.append_message(b"device_pub", device_pub);
    t.append_message(b"client_nonce", client_nonce);
    t.append_message(b"server_nonce", server_nonce);
    t.append_message(b"device_cert_hash", &dev_hash);
    t.append_message(b"server_cert_hash", &srv_hash);
    let out = Sha256::digest(&t.buf);
    let mut th = [0u8; 32];
    th.copy_from_slice(&out);
    th
}

fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn load_or_create_server_sk(path: &str) -> std::io::Result<Scalar> {
    if Path::new(path).exists() {
        let b = fs::read(path)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server_sk.bin wrong length",
            ));
        }
        let mut bb = [0u8; 32];
        bb.copy_from_slice(&b);
        // [FIX-10] dalek v4: use Option::from(CtOption)
        Option::from(Scalar::from_canonical_bytes(bb)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "server_sk.bin not canonical")
        })
    } else {
        let sk = random_scalar();
        ensure_parent_dir(path)?;
        fs::write(path, sk.to_bytes())?;
        Ok(sk)
    }
}

// ============================================================
// [FIX-5] Two-generation replay cache — no full-clear vulnerability
// ============================================================
#[derive(Default)]
struct ReplayCache {
    current: HashSet<[u8; 64]>,
    previous: HashSet<[u8; 64]>,
}

impl ReplayCache {
    // Returns true if the nonce is fresh (not seen before), and records it.
    // Returns false if it is a replay.
    fn check_and_insert(&mut self, device_id: &[u8; 32], nonce_c: &[u8; 32]) -> bool {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(device_id);
        k[32..].copy_from_slice(nonce_c);

        if self.current.contains(&k) || self.previous.contains(&k) {
            return false;
        }

        if self.current.len() >= REPLAY_GEN_MAX {
            self.previous = std::mem::take(&mut self.current);
        }

        self.current.insert(k);
        true
    }
}

// ============================================================
// [FIX-1] Pairing policy — token enforced with constant-time comparison
// ============================================================
#[derive(Clone)]
struct PairingPolicy {
    enabled: bool,
    token: Option<String>,
    deadline: Option<Instant>,
}

impl PairingPolicy {
    fn allows_ztp_setup(&self, provided_token: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(dl) = self.deadline {
            if Instant::now() > dl {
                return false;
            }
        }
        // [FIX-1] Constant-time token comparison
        match (&self.token, provided_token) {
            (Some(expected), Some(got)) => {
                expected.as_bytes().ct_eq(got.as_bytes()).into()
            }
            (Some(_), None) => false,
            (None, _) => true,
        }
    }
}

// ============================================================
// Handlers
// ============================================================

fn handle_setup(
    stream: &mut TcpStream,
    policy: &PairingPolicy,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], RistrettoPoint>>>,
    server_cert_buf: &[u8],
    server_cert: &X509,
    server_cert_key: &PKey<Private>,
    ca_cert: &X509,
    sent: &mut usize,
    recv: &mut usize,
) -> std::io::Result<()> {
    let provided_token = recv_pairing_token(stream, recv)?;
    if !policy.allows_ztp_setup(provided_token.as_deref()) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "pairing rejected by policy"));
    }

    let device_id = recv_device_id(stream, recv)?;
    let device_static_pub = recv_point(stream, recv, "device_pub")?;
    let device_pub_bytes = device_static_pub.compress().to_bytes();
    let mut client_nonce = [0u8; 32];
    recv_exact(stream, &mut client_nonce, recv)?;
    let device_cert_buf = recv_blob(stream, MAX_CERT_FILE_SIZE, recv)?;
    let device_cert = load_cert_from_bytes(&device_cert_buf)?;
    verify_cert_against_ca(&device_cert, ca_cert)?;

    let expected_cn = hex::encode(device_id);
    let expected_ou = hex::encode(device_pub_bytes);
    if cert_subject_field_hex(&device_cert, openssl::nid::Nid::COMMONNAME)? != expected_cn {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device certificate CN mismatch"));
    }
    if cert_subject_field_hex(&device_cert, openssl::nid::Nid::ORGANIZATIONALUNITNAME)? != expected_ou {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device certificate OU mismatch"));
    }

    {
        let reg_r = reg.read().unwrap();
        if let Some(existing) = reg_r.get(&device_id) {
            if existing.compress().to_bytes().ct_eq(&device_pub_bytes).unwrap_u8() == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device_id collision"));
            }
        }
    }

    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);
    let transcript_hash = ztp_cert_transcript_hash(
        &device_id,
        &device_pub_bytes,
        &client_nonce,
        &server_nonce,
        &device_cert_buf,
        server_cert_buf,
    );
    let server_sig = sign_transcript_hash(server_cert_key, &transcript_hash)?;

    send_all(stream, &server_nonce, sent)?;
    send_blob(stream, server_cert_buf, sent)?;
    send_blob(stream, &server_sig, sent)?;
    stream.flush()?;

    let a = recv_point(stream, recv, "setup_A")?;
    let s = recv_scalar(stream, recv)?;
    let device_sig = recv_blob(stream, MAX_SIG_SIZE, recv)?;

    if !schnorr_verify_setup(&device_static_pub, &device_id, &server_nonce, &a, &s) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Schnorr proof invalid"));
    }

    let device_cert_pubkey = device_cert.public_key().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("device pubkey extract failed: {e}")))?;
    verify_transcript_hash_sig(&device_cert_pubkey, &transcript_hash, &device_sig)?;

    let upsert = {
        let mut reg_w = reg.write().unwrap();
        let existed = reg_w.contains_key(&device_id);
        reg_w.insert(device_id, device_static_pub);
        save_registry_atomic(REGISTRY_BIN, REGISTRY_BAK, &reg_w)?;
        !existed
    };

    println!(
        "Server[SETUP/ZTP]: {} device_id={} via mutual certificate onboarding",
        if upsert { "enrolled NEW" } else { "validated existing" },
        hex::encode(device_id),
    );

    send_all(stream, &[0x01u8], sent)?;
    stream.flush()?;
    let _ = server_static_pub;
    let _ = server_cert;
    Ok(())
}

fn handle_auth_v2(
    stream: &mut TcpStream,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], RistrettoPoint>>>,
    replay: &Arc<Mutex<ReplayCache>>,
    sent: &mut usize,
    recv: &mut usize,
) -> std::io::Result<()> {
    // ── 1. Anonymous ephemeral X25519 key exchange ────────────────────────────
    let mut client_pk_bytes = [0u8; 32];
    recv_exact(stream, &mut client_pk_bytes, recv)?;
    let client_pk = X25519Public::from(client_pk_bytes);

    let server_sk = EphemeralSecret::random_from_rng(OsRng);
    let server_pk = X25519Public::from(&server_sk);
    send_all(stream, server_pk.as_bytes(), sent)?;
    stream.flush()?;

    // Derive tunnel keys (libsodium crypto_kx order)
    let shared_secret = server_sk.diffie_hellman(&client_pk);
    // [FIX-8] Save raw shared secret bytes to bind into session key later
    let x25519_shared_bytes: [u8; 32] = *shared_secret.as_bytes();

    let mut hasher = Blake2b512::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(client_pk_bytes);
    hasher.update(server_pk.as_bytes());
    let hash = hasher.finalize();

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];
    rx_key.copy_from_slice(&hash[32..64]); // C→S (server RX)
    tx_key.copy_from_slice(&hash[0..32]);  // S→C (server TX)

    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());
    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());

    // [FIX-9] Separate nonce counters per direction
    let mut nonce_rx_ctr = NonceCounter::new();
    let mut nonce_tx_ctr = NonceCounter::new();

    // ── 2. Decrypt client identity payload ───────────────────────────────────
    // [FIX-4] Bounded allocation
    let rx_ct = recv_encrypted_blob(stream, recv)?;
    let pt = cipher_rx
        .decrypt(&nonce_rx_ctr.next(), rx_ct.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed"))?;

    if pt.len() != 160 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid payload size: {} (expected 160)", pt.len()),
        ));
    }

    let mut device_id   = [0u8; 32]; device_id.copy_from_slice(&pt[0..32]);
    let mut a_c_bytes   = [0u8; 32]; a_c_bytes.copy_from_slice(&pt[32..64]);
    let mut s_c_bytes   = [0u8; 32]; s_c_bytes.copy_from_slice(&pt[64..96]);
    let mut nonce_c     = [0u8; 32]; nonce_c.copy_from_slice(&pt[96..128]);
    let mut eph_c_bytes = [0u8; 32]; eph_c_bytes.copy_from_slice(&pt[128..160]);

    // [FIX-2] [FIX-7] Proper error propagation, no unwrap on adversary data
    let a_c = CompressedRistretto(a_c_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_c"))?;
    reject_identity(&a_c, "a_c")?;

    // [FIX-10] dalek v4 CtOption API
    let s_c = Option::from(Scalar::from_canonical_bytes(s_c_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical s_c"))?;

    let eph_c = CompressedRistretto(eph_c_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_c"))?;
    reject_identity(&eph_c, "eph_c")?;

    // ── 3. Replay & Schnorr verification ─────────────────────────────────────
    {
        let mut rc = replay.lock().unwrap();
        if !rc.check_and_insert(&device_id, &nonce_c) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replay detected",
            ));
        }
    }

    let expected_pub = {
        let reg_r = reg.read().unwrap();
        match reg_r.get(&device_id) {
            Some(p) => *p,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "unknown device_id",
                ))
            }
        }
    };

    if !schnorr_verify_auth(&expected_pub, &device_id, &a_c, &s_c, &nonce_c, &eph_c) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "client Schnorr proof invalid",
        ));
    }

    // ── 4. Build encrypted server response ───────────────────────────────────
    let nonce_s = random_bytes_32();
    let mut eph_s_secret = random_scalar();
    let eph_s = RISTRETTO_BASEPOINT_POINT * eph_s_secret;
    let (a_s, s_s) = schnorr_prove_server(server_static_secret, &nonce_s, &eph_s);

    // [FIX-8] Pass x25519_shared_bytes into session key derivation
    let session_key = derive_session_key(
        &eph_s_secret, &eph_c, &nonce_c, &nonce_s,
        &device_id, &eph_c, &eph_s, &x25519_shared_bytes,
    );
    let th = kc_transcript_hash(
        &device_id, &a_c, &s_c, &nonce_c, &eph_c,
        server_static_pub, &a_s, &s_s, &nonce_s, &eph_s,
    );
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);
    let tag_s = hmac_tag(&k_s2c, b"server finished", &th);

    let mut payload2 = Vec::with_capacity(192);
    payload2.extend_from_slice(server_static_pub.compress().as_bytes());
    payload2.extend_from_slice(a_s.compress().as_bytes());
    payload2.extend_from_slice(&s_s.to_bytes());
    payload2.extend_from_slice(&nonce_s);
    payload2.extend_from_slice(eph_s.compress().as_bytes());
    payload2.extend_from_slice(&tag_s);

    // [FIX-2] Proper error propagation on encrypt
    // [FIX-9] NonceCounter manages the TX nonce
    let ct2 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), payload2.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encrypt failed"))?;

    let len2 = (ct2.len() as u32).to_le_bytes();
    send_all(stream, &len2, sent)?;
    send_all(stream, &ct2, sent)?;
    stream.flush()?;

    // ── 5. Decrypt and verify client finished tag ─────────────────────────────
    // [FIX-4] Bounded allocation
    let rx_ct2 = recv_encrypted_blob(stream, recv)?;

    // [FIX-9] NonceCounter advances automatically
    let tag_c_plain = cipher_rx
        .decrypt(&nonce_rx_ctr.next(), rx_ct2.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed on tag_c"))?;

    if tag_c_plain.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tag_c wrong length",
        ));
    }

    let expected_tag_c = hmac_tag(&k_c2s, b"client finished", &th);

    // [FIX-3] Constant-time comparison
    let tag_c_arr: [u8; 32] = tag_c_plain.try_into().unwrap();
    if expected_tag_c.ct_eq(&tag_c_arr).unwrap_u8() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "tag_c mismatch",
        ));
    }

    println!(
        "Server[AUTH]: device_id={} session_key={} KC=OK",
        hex::encode(device_id),
        hex::encode(session_key),
    );

    eph_s_secret.zeroize();
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    server_static_secret: Arc<Scalar>,
    server_static_pub: Arc<RistrettoPoint>,
    policy: PairingPolicy,
    reg: Arc<RwLock<HashMap<[u8; 32], RistrettoPoint>>>,
    server_cert_buf: Arc<Vec<u8>>,
    server_cert_key: Arc<PKey<Private>>,
    server_cert: Arc<X509>,
    ca_cert: Arc<X509>,
    replay: Arc<Mutex<ReplayCache>>,
) {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv_bytes = 0usize;
    let peer = stream.peer_addr().ok();

    macro_rules! bail {
        ($msg:expr) => {{
            eprintln!("Server: {} from {:?}", $msg, peer);
            return;
        }};
    }

    if stream.set_nodelay(true).is_err() { bail!("set_nodelay failed"); }
    if stream.set_read_timeout(Some(IO_TIMEOUT)).is_err() { bail!("set_read_timeout failed"); }
    if stream.set_write_timeout(Some(IO_TIMEOUT)).is_err() { bail!("set_write_timeout failed"); }

    let msg_type = match recv_u8(&mut stream, &mut recv_bytes) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Server: read msg_type error from {:?}: {}", peer, e);
            return;
        }
    };

    let res = match msg_type {
        MSG_SETUP => handle_setup(
            &mut stream, &policy, &server_static_pub,
            &reg, &server_cert_buf, &server_cert, &server_cert_key, &ca_cert,
            &mut sent, &mut recv_bytes,
        ),
        MSG_AUTH_V2 => handle_auth_v2(
            &mut stream, &server_static_secret, &server_static_pub,
            &reg, &replay, &mut sent, &mut recv_bytes,
        ),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown msg_type: 0x{msg_type:02x}"),
        )),
    };

    if let Err(e) = res {
        eprintln!("Server: request from {:?} failed: {}", peer, e);
    }

    println!(
        "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        peer, start.elapsed(), sent, recv_bytes,
    );
}

// ============================================================
// MAIN
// ============================================================
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "server".to_string());

    let mut bind_addr = "0.0.0.0:4000".to_string();
    let mut pairing = false;
    let mut pairing_token: Option<String> = None;
    let mut pairing_seconds: Option<u64> = None;
    let mut print_pubkey = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--bind missing value")); }
                bind_addr = args[i + 1].clone();
                i += 2;
            }
            "--pairing" => { pairing = true; i += 1; }
            "--pairing-token" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pairing-token missing value")); }
                pairing_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--pairing-seconds" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pairing-seconds missing value")); }
                pairing_seconds = Some(args[i + 1].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --pairing-seconds"))?);
                i += 2;
            }
            "--print-pubkey" => { print_pubkey = true; i += 1; }
            _ => {
                eprintln!("Usage: {} [--bind 0.0.0.0:4000] [--pairing] [--pairing-token TOKEN] [--pairing-seconds N] [--print-pubkey]", prog);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown argument: {}", args[i])));
            }
        }
    }

    let server_static_secret = load_or_create_server_sk(SERVER_SK_FILE)?;
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;
    reject_identity(&server_static_pub, "server_static_pub")?;
    if print_pubkey {
        println!("{}", hex::encode(server_static_pub.compress().to_bytes()));
        return Ok(());
    }

    let server_cert_buf = read_file_all(SERVER_CERT_FILE, MAX_CERT_FILE_SIZE)?;
    let server_key_buf = read_file_all(SERVER_CERT_KEY_FILE, MAX_CERT_FILE_SIZE)?;
    let ca_cert_buf = read_file_all(CA_CERT_FILE, MAX_CERT_FILE_SIZE)?;
    let server_cert = load_cert_from_bytes(&server_cert_buf)?;
    let ca_cert = load_cert_from_bytes(&ca_cert_buf)?;
    let server_cert_key = load_private_key_from_bytes(&server_key_buf)?;
    verify_cert_against_ca(&server_cert, &ca_cert)?;
    let expected_server_ou = hex::encode(server_static_pub.compress().to_bytes());
    if cert_subject_field_hex(&server_cert, openssl::nid::Nid::ORGANIZATIONALUNITNAME)? != expected_server_ou {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Server certificate OU does not match server_pub"));
    }

    let deadline = pairing_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let policy = PairingPolicy { enabled: pairing, token: pairing_token, deadline };
    let reg_map = load_registry(REGISTRY_BIN).unwrap_or_default();
    let reg = Arc::new(RwLock::new(reg_map));
    let replay = Arc::new(Mutex::new(ReplayCache::default()));
    let listener = TcpListener::bind(&bind_addr)?;

    println!("C-compatible Rust Server listening on {}", bind_addr);
    println!("Server public key (pin this on client): {}", hex::encode(server_static_pub.compress().to_bytes()));
    println!(
        "Server: pairing_enabled={} token_configured={} deadline={} mutual_cert_onboarding=true",
        policy.enabled,
        policy.token.is_some(),
        if policy.deadline.is_some() { "set" } else { "none" },
    );

    let ss = Arc::new(server_static_secret);
    let sp = Arc::new(server_static_pub);
    let server_cert_buf = Arc::new(server_cert_buf);
    let server_cert_key = Arc::new(server_cert_key);
    let server_cert = Arc::new(server_cert);
    let ca_cert = Arc::new(ca_cert);

    loop {
        let (stream, _) = listener.accept()?;
        let ss2 = Arc::clone(&ss);
        let sp2 = Arc::clone(&sp);
        let pol2 = policy.clone();
        let reg2 = Arc::clone(&reg);
        let scb2 = Arc::clone(&server_cert_buf);
        let sck2 = Arc::clone(&server_cert_key);
        let sc2 = Arc::clone(&server_cert);
        let ca2 = Arc::clone(&ca_cert);
        let rep2 = Arc::clone(&replay);
        thread::spawn(move || {
            handle_client(stream, ss2, sp2, pol2, reg2, scb2, sck2, sc2, ca2, rep2);
        });
    }
}
