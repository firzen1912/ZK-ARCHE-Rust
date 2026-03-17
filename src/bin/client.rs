// ==============================
// client.rs (V3: AUTH_V2 unchanged, SETUP upgraded to mutual certificate-based onboarding)
// ==============================
//
// Goals:
//   1) Keep AUTH_V2 unchanged for operational auth/session protection.
//   2) Replace bootstrap-secret onboarding with mutual certificate validation during SETUP.
//   3) Eliminate first-contact TOFU for SETUP by verifying a trusted CA-signed server cert.
//   4) Bind device_id + device_static_pub into the device certificate used during SETUP.
//   5) Preserve the final 0x01 enrollment ack after full server-side verification.
//
// Certificate binding convention used here:
//   - Device cert subject CN = lowercase hex(device_id)
//   - Device cert subject OU = lowercase hex(device_static_pub_compressed)
//   - Server cert subject OU = lowercase hex(server_static_pub_compressed)
//
// Cargo.toml additions for this version:
//   openssl          = { version = "0.10", features = ["vendored"] }
//

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
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
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;

const DEVICE_ROOT_FILE: &str = "/var/lib/iot-auth/device_root.bin";
const SERVER_PUB_FILE: &str = "/var/lib/iot-auth/server_pub.bin";
const DEVICE_CERT_FILE: &str = "/var/lib/iot-auth/device_cert.pem";
const DEVICE_KEY_FILE: &str = "/var/lib/iot-auth/device_key.pem";
const CA_CERT_FILE: &str = "/var/lib/iot-auth/ca_cert.pem";
const MAX_CERT_BLOB: usize = 16 * 1024;
const MAX_SIG_BLOB: usize = 4 * 1024;

const T_SETUP: &[u8] = b"setup_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";

const IO_TIMEOUT: Duration = Duration::from_secs(5);

// [FIX-4] Hard cap on incoming encrypted payload size
const MAX_ENCRYPTED_PAYLOAD: usize = 4096;

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

// [FIX-7] Reject identity (neutral) points on all adversary inputs
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
fn schnorr_prove_setup(
    x: &Scalar,
    device_id: &[u8; 32],
    server_nonce: &[u8; 32],
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let mut t = CompatTranscript::new(T_SETUP);
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"server_nonce", server_nonce);
    let c = t.challenge_scalar();
    let s = r + c * x;
    (a, s)
}

fn schnorr_prove_auth(
    x: &Scalar,
    device_id: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let mut t = CompatTranscript::new(T_CLIENT);
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());
    let c = t.challenge_scalar();
    let s = r + c * x;
    (a, s)
}

fn schnorr_verify_server(
    server_static_pub: &RistrettoPoint,
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> bool {
    let mut t = CompatTranscript::new(T_SERVER);
    t.append_message(b"pubkey", server_static_pub.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());
    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
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

// [FIX-4] Bounded length-prefixed ciphertext read
fn recv_u32_le(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<u32> {
    let mut b = [0u8; 4];
    recv_exact(stream, &mut b, recv)?;
    Ok(u32::from_le_bytes(b))
}

fn send_u32_le(stream: &mut impl Write, v: u32, sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &v.to_le_bytes(), sent)
}

fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_u32_le(stream, buf.len() as u32, sent)?;
    send_all(stream, buf, sent)
}

fn recv_blob(
    stream: &mut impl Read,
    recv: &mut usize,
    max_len: usize,
    what: &str,
) -> std::io::Result<Vec<u8>> {
    let len = recv_u32_le(stream, recv)? as usize;
    if len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} too large: {len} bytes (max {max_len})"),
        ));
    }
    let mut buf = vec![0u8; len];
    recv_exact(stream, &mut buf, recv)?;
    Ok(buf)
}

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

// ============================================================
// Local credential storage
// ============================================================
fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn load_or_create_device_root() -> std::io::Result<[u8; 32]> {
    if Path::new(DEVICE_ROOT_FILE).exists() {
        let b = fs::read(DEVICE_ROOT_FILE)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "device_root wrong length",
            ));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&b);
        Ok(root)
    } else {
        ensure_parent_dir(DEVICE_ROOT_FILE)?;
        let root = random_bytes_32();
        fs::write(DEVICE_ROOT_FILE, root)?;
        Ok(root)
    }
}

fn derive_device_id(root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"device-id");
    sha2::Digest::update(&mut h, root);
    let out = h.finalize();
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&out);
    device_id
}

fn derive_device_scalar(root: &[u8; 32]) -> Scalar {
    let mut h = Sha512::new();
    sha2::Digest::update(&mut h, b"device-auth-v1");
    sha2::Digest::update(&mut h, root);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn load_device_creds_from_root() -> std::io::Result<([u8; 32], Scalar)> {
    let mut root = load_or_create_device_root()?;
    let device_id = derive_device_id(&root);
    let x = derive_device_scalar(&root);
    root.zeroize();
    Ok((device_id, x))
}

fn creds_exist() -> bool {
    Path::new(DEVICE_ROOT_FILE).exists()
}

fn load_exact_file<const N: usize>(path: &str, what: &str) -> std::io::Result<[u8; N]> {
    let b = fs::read(path)?;
    if b.len() != N {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} wrong length"),
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&b);
    Ok(out)
}

fn load_file(path: &str) -> std::io::Result<Vec<u8>> {
    fs::read(path)
}

fn load_x509_from_file(path: &str) -> std::io::Result<X509> {
    let data = load_file(path)?;
    X509::from_pem(&data)
        .or_else(|_| X509::from_der(&data))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("failed to load X509 from {path}: {e}")))
}

fn load_private_key_from_file(path: &str) -> std::io::Result<PKey<Private>> {
    let data = load_file(path)?;
    PKey::private_key_from_pem(&data)
        .or_else(|_| PKey::private_key_from_der(&data))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("failed to load private key from {path}: {e}")))
}

fn x509_to_der(cert: &X509) -> std::io::Result<Vec<u8>> {
    cert.to_der().map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("cert DER encode failed: {e}")))
}

fn subject_hex_entry(cert: &X509, nid: Nid, what: &str) -> std::io::Result<String> {
    let subject = cert.subject_name();
    let entry = subject.entries_by_nid(nid).next().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, format!("certificate missing {what}"))
    })?;
    let txt = entry
        .data()
        .as_utf8()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad {what} utf8: {e}")))?;
    Ok(txt.to_string().to_lowercase())
}

fn cert_bound_ristretto_pub(cert: &X509, what: &str) -> std::io::Result<RistrettoPoint> {
    let hex_str = subject_hex_entry(cert, Nid::ORGANIZATIONALUNITNAME, what)?;
    let decoded = hex::decode(&hex_str)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid {what} hex")))?;
    if decoded.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} must be 32 bytes compressed ristretto"),
        ));
    }
    let mut bb = [0u8; 32];
    bb.copy_from_slice(&decoded);
    let p = CompressedRistretto(bb)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid {what} point")))?;
    reject_identity(&p, what)?;
    Ok(p)
}

fn verify_cert_signed_by_ca(cert: &X509, ca_cert: &X509) -> std::io::Result<()> {
    let mut builder = X509StoreBuilder::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("X509StoreBuilder::new failed: {e}")))?;
    builder.add_cert(ca_cert.clone())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("add CA cert failed: {e}")))?;
    let store = builder.build();
    let chain = Stack::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("X509 chain alloc failed: {e}")))?;
    let mut ctx = X509StoreContext::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("X509StoreContext::new failed: {e}")))?;
    let verified = ctx
        .init(&store, cert, &chain, |c| c.verify_cert())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("certificate chain verify failed: {e}")))?;
    if !verified {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "certificate chain verification returned false",
        ));
    }
    Ok(())
}

fn sign_transcript(key: &PKey<Private>, transcript_hash: &[u8; 32]) -> std::io::Result<Vec<u8>> {
    let mut signer = Signer::new(MessageDigest::sha256(), key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Signer::new failed: {e}")))?;
    signer
        .update(transcript_hash)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Signer::update failed: {e}")))?;
    signer
        .sign_to_vec()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Signer::sign_to_vec failed: {e}")))
}

fn verify_transcript_signature(
    cert: &X509,
    transcript_hash: &[u8; 32],
    sig: &[u8],
) -> std::io::Result<()> {
    let pubkey: PKey<Public> = cert
        .public_key()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("extract cert public key failed: {e}")))?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pubkey)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Verifier::new failed: {e}")))?;
    verifier
        .update(transcript_hash)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Verifier::update failed: {e}")))?;
    let ok = verifier
        .verify(sig)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("signature verification failed: {e}")))?;
    if !ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "transcript signature mismatch",
        ));
    }
    Ok(())
}

fn ztp_cert_transcript_hash(
    device_id: &[u8; 32],
    device_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    device_cert_der: &[u8],
    server_cert_der: &[u8],
) -> [u8; 32] {
    let mut t = CompatTranscript::new(b"ztp-mutual-cert-v1");
    t.append_message(b"device_id", device_id);
    t.append_message(b"device_pub", device_static_pub.compress().as_bytes());
    t.append_message(b"client_nonce", client_nonce);
    t.append_message(b"server_nonce", server_nonce);
    let dev_hash = Sha256::digest(device_cert_der);
    let srv_hash = Sha256::digest(server_cert_der);
    t.append_message(b"device_cert_hash", &dev_hash);
    t.append_message(b"server_cert_hash", &srv_hash);
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, &t.buf);
    let out = h.finalize();
    let mut th = [0u8; 32];
    th.copy_from_slice(&out);
    th
}

// ============================================================
// Server pubkey pinning (TOFU & out-of-band)
// ============================================================
fn load_server_pub() -> std::io::Result<Option<RistrettoPoint>> {
    if !Path::new(SERVER_PUB_FILE).exists() {
        return Ok(None);
    }
    let b = fs::read(SERVER_PUB_FILE)?;
    if b.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server_pub.bin wrong length",
        ));
    }
    let mut bb = [0u8; 32];
    bb.copy_from_slice(&b);
    let p = CompressedRistretto(bb)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "server_pub invalid")
        })?;
    reject_identity(&p, "pinned server_pub")?;
    Ok(Some(p))
}

fn save_server_pub(pubkey: &RistrettoPoint) -> std::io::Result<()> {
    ensure_parent_dir(SERVER_PUB_FILE)?;
    fs::write(SERVER_PUB_FILE, pubkey.compress().as_bytes())?;
    Ok(())
}

// ============================================================
// SETUP (mutual certificate-based onboarding)
// ============================================================
fn do_setup(
    server_addr: &str,
    device_id: [u8; 32],
    mut x: Scalar,
    pairing_token: Option<&str>,
) -> std::io::Result<()> {
    let mut sent = 0usize;
    let mut recv = 0usize;

    let pinned_server_pub = load_server_pub()?;
    let device_cert = load_x509_from_file(DEVICE_CERT_FILE)?;
    let device_key = load_private_key_from_file(DEVICE_KEY_FILE)?;
    let ca_cert = load_x509_from_file(CA_CERT_FILE)?;
    let device_cert_der = x509_to_der(&device_cert)?;

    let device_static_pub = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&device_static_pub, "client device_static_pub")?;

    let expected_device_id_hex = hex::encode(device_id);
    let cert_device_id_hex = subject_hex_entry(&device_cert, Nid::COMMONNAME, "device cert CN")?;
    if cert_device_id_hex != expected_device_id_hex {
        x.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("device cert CN mismatch: expected {expected_device_id_hex}, got {cert_device_id_hex}"),
        ));
    }

    let cert_device_pub = cert_bound_ristretto_pub(&device_cert, "device cert OU")?;
    if cert_device_pub
        .compress()
        .to_bytes()
        .ct_eq(&device_static_pub.compress().to_bytes())
        .unwrap_u8()
        == 0
    {
        x.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "device cert OU does not match local device_static_pub",
        ));
    }

    verify_cert_signed_by_ca(&device_cert, &ca_cert)?;

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    println!("Client[SETUP/MTLS]: Connected to {}", server_addr);

    send_all(&mut stream, &[MSG_SETUP], &mut sent)?;

    match pairing_token {
        Some(token) => {
            let tb = token.as_bytes();
            if tb.len() > 128 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "pairing token too long (max 128 bytes)",
                ));
            }
            send_all(&mut stream, &[tb.len() as u8], &mut sent)?;
            send_all(&mut stream, tb, &mut sent)?;
        }
        None => send_all(&mut stream, &[0u8], &mut sent)?,
    }

    let client_nonce = random_bytes_32();
    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, device_static_pub.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &client_nonce, &mut sent)?;
    send_blob(&mut stream, &device_cert_der, &mut sent)?;
    stream.flush()?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;
    let server_cert_der = recv_blob(&mut stream, &mut recv, MAX_CERT_BLOB, "server cert")?;
    let server_sig = recv_blob(&mut stream, &mut recv, MAX_SIG_BLOB, "server signature")?;

    let server_cert = X509::from_der(&server_cert_der)
        .or_else(|_| X509::from_pem(&server_cert_der))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid server cert encoding: {e}")))?;
    verify_cert_signed_by_ca(&server_cert, &ca_cert)?;

    let server_static_pub = cert_bound_ristretto_pub(&server_cert, "server cert OU")?;
    match &pinned_server_pub {
        Some(pinned) => {
            if pinned
                .compress()
                .to_bytes()
                .ct_eq(&server_static_pub.compress().to_bytes())
                .unwrap_u8()
                == 0
            {
                x.zeroize();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "server cert bound key mismatches pinned server pub",
                ));
            }
            println!("Client[SETUP/MTLS]: Server certificate matches pinned server pub.");
        }
        None => {
            println!(
                "Client[SETUP/MTLS]: Validated CA-signed server cert, will pin server pub {} for AUTH_V2 compatibility.",
                hex::encode(server_static_pub.compress().to_bytes())
            );
        }
    }

    let th = ztp_cert_transcript_hash(
        &device_id,
        &device_static_pub,
        &client_nonce,
        &server_nonce,
        &device_cert_der,
        &server_cert_der,
    );
    verify_transcript_signature(&server_cert, &th, &server_sig)?;

    let (a, s) = schnorr_prove_setup(&x, &device_id, &server_nonce);
    let device_sig = sign_transcript(&device_key, &th)?;
    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    send_blob(&mut stream, &device_sig, &mut sent)?;
    stream.flush()?;

    let mut ack = [0u8; 1];
    recv_exact(&mut stream, &mut ack, &mut recv)?;
    if ack[0] != 0x01 {
        x.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server rejected certificate-based setup",
        ));
    }

    if pinned_server_pub.is_none() {
        save_server_pub(&server_static_pub)?;
        println!(
            "Client[SETUP/MTLS]: Saved validated server pub for AUTH_V2: {}",
            hex::encode(server_static_pub.compress().to_bytes())
        );
    }

    println!(
        "Client[SETUP/MTLS]: Sent={} bytes, Received={} bytes. Enrolled.",
        sent, recv,
    );
    x.zeroize();
    Ok(())
}

fn do_auth_v2(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    let pinned_server_pub = load_server_pub()?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "No pinned server_pub.bin — run --setup first to enroll and pin the server key.",
        )
    })?;

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    println!("Client[AUTH]: Connected to {}", server_addr);

    // ── 1. Anonymous ephemeral X25519 key exchange ────────────────────────────
    let client_sk = EphemeralSecret::random_from_rng(OsRng);
    let client_pk = X25519Public::from(&client_sk);

    send_all(&mut stream, &[MSG_AUTH_V2], &mut sent)?;
    send_all(&mut stream, client_pk.as_bytes(), &mut sent)?;
    stream.flush()?;

    let mut server_pk_bytes = [0u8; 32];
    recv_exact(&mut stream, &mut server_pk_bytes, &mut recv)?;
    let server_pk = X25519Public::from(server_pk_bytes);

    // Derive tunnel keys (libsodium crypto_kx order)
    let shared_secret = client_sk.diffie_hellman(&server_pk);
    // [FIX-8] Retain raw shared secret bytes to bind into session key
    let x25519_shared_bytes: [u8; 32] = *shared_secret.as_bytes();

    let mut hasher = Blake2b512::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(client_pk.as_bytes());
    hasher.update(server_pk_bytes);
    let hash = hasher.finalize();

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];
    rx_key.copy_from_slice(&hash[0..32]);  // S→C (client RX)
    tx_key.copy_from_slice(&hash[32..64]); // C→S (client TX)

    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());
    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());

    // [FIX-9] Separate nonce counters per direction
    let mut nonce_tx_ctr = NonceCounter::new();
    let mut nonce_rx_ctr = NonceCounter::new();

    // ── 2. Encrypt and send identity + Schnorr proof ──────────────────────────
    let mut nonce_c = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_c);

    let mut eph_secret = random_scalar();
    let eph_pub = RISTRETTO_BASEPOINT_POINT * eph_secret;
    let (a_c, s_c) = schnorr_prove_auth(&x, &device_id, &nonce_c, &eph_pub);

    let mut payload1 = Vec::with_capacity(160);
    payload1.extend_from_slice(&device_id);
    payload1.extend_from_slice(a_c.compress().as_bytes());
    payload1.extend_from_slice(&s_c.to_bytes());
    payload1.extend_from_slice(&nonce_c);
    payload1.extend_from_slice(eph_pub.compress().as_bytes());

    // [FIX-2] Proper error propagation; [FIX-9] NonceCounter manages nonce
    let ct1 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), payload1.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    let len1 = (ct1.len() as u32).to_le_bytes();
    send_all(&mut stream, &len1, &mut sent)?;
    send_all(&mut stream, &ct1, &mut sent)?;
    stream.flush()?;

    // ── 3. Read and decrypt server response ───────────────────────────────────
    // [FIX-4] Bounded allocation
    let rx_ct = recv_encrypted_blob(&mut stream, &mut recv)?;

    // [FIX-9] NonceCounter advances automatically
    let pt2 = cipher_rx
        .decrypt(&nonce_rx_ctr.next(), rx_ct.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed"))?;

    if pt2.len() != 192 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid server payload length: {} (expected 192)", pt2.len()),
        ));
    }

    let mut s_pub_bytes  = [0u8; 32]; s_pub_bytes.copy_from_slice(&pt2[0..32]);
    let mut a_s_bytes    = [0u8; 32]; a_s_bytes.copy_from_slice(&pt2[32..64]);
    let mut s_s_bytes    = [0u8; 32]; s_s_bytes.copy_from_slice(&pt2[64..96]);
    let mut nonce_s      = [0u8; 32]; nonce_s.copy_from_slice(&pt2[96..128]);
    let mut eph_s_bytes  = [0u8; 32]; eph_s_bytes.copy_from_slice(&pt2[128..160]);
    let mut tag_s        = [0u8; 32]; tag_s.copy_from_slice(&pt2[160..192]);

    // [FIX-2] No unwrap on adversary data; [FIX-7] reject identity on all points
    let server_static_pub = CompressedRistretto(s_pub_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server_static_pub")
        })?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let a_s = CompressedRistretto(a_s_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_s")
        })?;
    reject_identity(&a_s, "a_s")?;

    // [FIX-10] dalek v4: Option::from(CtOption)
    let s_s = Option::from(Scalar::from_canonical_bytes(s_s_bytes))
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical s_s")
        })?;

    let eph_s = CompressedRistretto(eph_s_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_s")
        })?;
    reject_identity(&eph_s, "eph_s")?;

    // [FIX-3] Constant-time pinned key comparison
    if pinned_server_pub
        .compress()
        .to_bytes()
        .ct_eq(&server_static_pub.compress().to_bytes())
        .unwrap_u8()
        == 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Server pubkey mismatch — possible MITM",
        ));
    }

    if !schnorr_verify_server(&server_static_pub, &a_s, &s_s, &nonce_s, &eph_s) {
        eprintln!("Client[AUTH]: Server Schnorr proof FAILED");
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server Schnorr proof invalid",
        ));
    }
    println!("Client[AUTH]: Server Schnorr proof OK");

    // [FIX-8] Pass x25519_shared_bytes into session key derivation
    let session_key = derive_session_key(
        &eph_secret, &eph_s, &nonce_c, &nonce_s,
        &device_id, &eph_pub, &eph_s, &x25519_shared_bytes,
    );
    let th = kc_transcript_hash(
        &device_id, &a_c, &s_c, &nonce_c, &eph_pub,
        &server_static_pub, &a_s, &s_s, &nonce_s, &eph_s,
    );
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);

    let expected_tag_s = hmac_tag(&k_s2c, b"server finished", &th);

    // [FIX-3] Constant-time tag comparison
    if expected_tag_s.ct_eq(&tag_s).unwrap_u8() == 0 {
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server finished tag mismatch",
        ));
    }
    println!("Client[AUTH]: Key confirmation (server finished) OK");

    // ── 4. Send encrypted client confirmation ────────────────────────────────
    let tag_c = hmac_tag(&k_c2s, b"client finished", &th);

    // [FIX-2] Proper error propagation; [FIX-9] NonceCounter manages nonce
    let ct3 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), tag_c.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    let len3 = (ct3.len() as u32).to_le_bytes();
    send_all(&mut stream, &len3, &mut sent)?;
    send_all(&mut stream, &ct3, &mut sent)?;
    stream.flush()?;

    println!("Client[AUTH]: Sent encrypted client finished tag");

    x.zeroize();
    eph_secret.zeroize();

    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(), sent, recv,
    );
    Ok(())
}

// ============================================================
// MAIN
// ============================================================
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mut server_addr = "127.0.0.1:4000".to_string();
    let mut do_setup_flag = false;
    let mut pairing_token: Option<String> = None;
    let mut did_pin_server_pub = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--server missing value",
                    ));
                }
                server_addr = args[i + 1].clone();
                i += 2;
            }
            "--setup" => {
                do_setup_flag = true;
                i += 1;
            }
            "--pairing-token" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--pairing-token missing value",
                    ));
                }
                pairing_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--pin-server-pub" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--pin-server-pub missing value",
                    ));
                }
                let hex_str = args[i + 1].clone();
                let decoded = hex::decode(&hex_str).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid hex")
                })?;
                if decoded.len() != 32 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "pinned key must be 32 bytes",
                    ));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&decoded);
                let p = CompressedRistretto(key_bytes).decompress().ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "invalid ristretto point",
                    )
                })?;
                reject_identity(&p, "pinned server pub")?;
                save_server_pub(&p)?;
                println!("Client: Successfully pinned server pubkey out-of-band.");
                did_pin_server_pub = true;
                i += 2;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown argument: {}", args[i]),
                ))
            }
        }
    }

    if did_pin_server_pub && !do_setup_flag {
        return Ok(());
    }

    if !creds_exist() && !do_setup_flag {
        eprintln!(
            "Client: device root missing ({}). Refusing AUTH. Run with --setup to enroll.",
            DEVICE_ROOT_FILE,
        );
        return Ok(());
    }

    if do_setup_flag {
        if creds_exist() {
            println!("Client[SETUP/ZTP]: Using existing device root for setup.");
        } else {
            println!("Client[SETUP/ZTP]: No device root found; generating NEW device root.");
        }
        let (device_id, x) = load_device_creds_from_root()?;
        do_setup(&server_addr, device_id, x, pairing_token.as_deref())?;
        return Ok(());
    }

    let (device_id, x) = load_device_creds_from_root()?;
    do_auth_v2(&server_addr, device_id, x)
}