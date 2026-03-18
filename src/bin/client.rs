// ==============================
// client.rs (Rust implementation aligned to the C mutual-certificate onboarding flow)
// ==============================
//
// Goals:
//   1) Use the same /var/lib/iot-auth/{client,server} state layout as the C version.
//   2) Enforce pinned server_static_pub during SETUP and AUTH (reject MITM).
//   3) Zero Privacy: Hide identity (device_id) during AUTH using X25519 ECDHE tunnel.
//   4) Add key confirmation MACs: "server finished" and "client finished".
//   5) Use the same mutual-certificate transcript/signature setup path as the C implementation.
//
// Server setup now follows the same certificate-based onboarding flow as the C version.
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

use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use blake2::digest::{Update, VariableOutput};
use blake2::{Blake2b512, Blake2bVar, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use openssl::pkey::{Id as PKeyId, PKey, Private, Public};
use openssl::sign::{Signer, Verifier};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509, X509NameRef};
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;

const DEVICE_ROOT_FILE: &str = "/var/lib/iot-auth/client/device_root.bin";
const SERVER_PUB_FILE: &str = "/var/lib/iot-auth/client/server_pub.bin";
const DEVICE_CERT_FILE: &str = "/var/lib/iot-auth/client/device_cert.pem";
const DEVICE_KEY_FILE: &str = "/var/lib/iot-auth/client/device_key.pem";
const CA_CERT_FILE: &str = "/var/lib/iot-auth/client/ca_cert.pem";
const MAX_CERT_FILE_SIZE: usize = 128 * 1024;
const MAX_SIG_SIZE: usize = 8192;

const T_SETUP: &[u8] = b"setup_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ENCRYPTED_PAYLOAD: usize = 4096;

// ============================================================
// NonceCounter — safe sequential nonce management
// ============================================================
struct NonceCounter {
    value: u64,
}

impl NonceCounter {
    fn new() -> Self {
        Self { value: 0 }
    }

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
    Mac::update(&mut mac, label);
    Mac::update(&mut mac, th);
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

fn recv_encrypted_blob(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Vec<u8>> {
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

fn write_private_file_atomic(path: &str, data: &[u8]) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    let tmp = format!("{path}.tmp");
    #[cfg(unix)]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn verify_private_file_permissions(path: &str) -> std::io::Result<()> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{path} must not be group/world accessible (mode {:o})", mode),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_file_permissions(_path: &str) -> std::io::Result<()> {
    Ok(())
}

fn load_or_create_device_root() -> std::io::Result<[u8; 32]> {
    if Path::new(DEVICE_ROOT_FILE).exists() {
        verify_private_file_permissions(DEVICE_ROOT_FILE)?;
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
        let root = random_bytes_32();
        write_private_file_atomic(DEVICE_ROOT_FILE, &root)?;
        Ok(root)
    }
}

fn derive_device_id(root: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("invalid Blake2b output length");
    Update::update(&mut h, b"device-id");
    Update::update(&mut h, root);

    let mut device_id = [0u8; 32];
    h.finalize_variable(&mut device_id)
        .expect("failed to finalize Blake2b-256");
    device_id
}

fn derive_device_scalar(root: &[u8; 32]) -> Scalar {
    let mut h = Blake2b512::new();
    Digest::update(&mut h, b"device-auth-v1");
    Digest::update(&mut h, root);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest[..64]);
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

fn read_file_all(path: &str, max_len: usize) -> std::io::Result<Vec<u8>> {
    let data = fs::read(path)?;
    if data.len() > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{path} exceeds max size"),
        ));
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
    let now = openssl::asn1::Asn1Time::days_from_now(0)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("time init failed: {e}")))?;
    if cert.not_before().compare(&now)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("not_before compare failed: {e}")))?
        .is_gt()
    {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "certificate is not yet valid"));
    }
    if cert.not_after().compare(&now)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("not_after compare failed: {e}")))?
        .is_lt()
    {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "certificate has expired"));
    }

    let mut store_builder = X509StoreBuilder::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("store builder failed: {e}")))?;
    store_builder
        .add_cert(ca_cert.to_owned())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("add CA cert failed: {e}")))?;
    let store = store_builder.build();
    let chain = Stack::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("chain init failed: {e}")))?;
    let mut ctx = X509StoreContext::new()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("store context failed: {e}")))?;
    let ok = ctx
        .init(&store, cert, &chain, |c| c.verify_cert())
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("certificate path validation failed: {e}")))?;
    if !ok {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "certificate not issued by trusted CA"));
    }
    Ok(())
}

fn cert_subject_field_hex(cert: &X509, nid: openssl::nid::Nid) -> std::io::Result<String> {
    let name: &X509NameRef = cert.subject_name();
    let entry = name.entries_by_nid(nid).next().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("missing subject field {nid:?}"),
        )
    })?;
    let data = entry
        .data()
        .as_utf8()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("subject field utf8 failed: {e}")))?;
    Ok(data.to_string().to_ascii_lowercase())
}

fn sign_transcript_hash(pkey: &PKey<Private>, th: &[u8; 32]) -> std::io::Result<Vec<u8>> {
    let mut signer = if matches!(pkey.id(), PKeyId::ED25519 | PKeyId::ED448) {
        Signer::new_without_digest(pkey)
    } else {
        Signer::new(openssl::hash::MessageDigest::sha256(), pkey)
    }
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("sign init failed: {e}")))?;
    signer
        .sign_oneshot_to_vec(th)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("sign failed: {e}")))
}

fn verify_transcript_hash_sig(pkey: &PKey<Public>, th: &[u8; 32], sig: &[u8]) -> std::io::Result<()> {
    let mut verifier = if matches!(pkey.id(), PKeyId::ED25519 | PKeyId::ED448) {
        Verifier::new_without_digest(pkey)
    } else {
        Verifier::new(openssl::hash::MessageDigest::sha256(), pkey)
    }
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("verify init failed: {e}")))?;
    let ok = verifier
        .verify_oneshot(sig, th)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("verify failed: {e}")))?;
    if ok {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "signature verification failed",
        ))
    }
}

fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() {
        send_all(stream, buf, sent)?;
    }
    Ok(())
}

fn recv_blob(stream: &mut impl Read, max_len: usize, recv: &mut usize) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv_exact(stream, &mut len_buf, recv)?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("blob too large: {len}"),
        ));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        recv_exact(stream, &mut buf, recv)?;
    }
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

// ============================================================
// Server pubkey pinning
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
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "server_pub invalid"))?;
    reject_identity(&p, "pinned server_pub")?;
    Ok(Some(p))
}

fn save_server_pub(pubkey: &RistrettoPoint) -> std::io::Result<()> {
    write_private_file_atomic(SERVER_PUB_FILE, pubkey.compress().as_bytes())
}

// ============================================================
// SETUP (mutual-certificate onboarding)
// ============================================================
fn do_setup(
    server_addr: &str,
    device_id: [u8; 32],
    mut x: Scalar,
    pairing_token: Option<&str>,
    allow_tofu_setup: bool,
) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    verify_private_file_permissions(DEVICE_KEY_FILE)?;
    let device_cert_buf = read_file_all(DEVICE_CERT_FILE, MAX_CERT_FILE_SIZE)?;
    let device_key_buf = read_file_all(DEVICE_KEY_FILE, MAX_CERT_FILE_SIZE)?;
    let ca_cert_buf = read_file_all(CA_CERT_FILE, MAX_CERT_FILE_SIZE)?;

    let device_cert = load_cert_from_bytes(&device_cert_buf)?;
    let ca_cert = load_cert_from_bytes(&ca_cert_buf)?;
    let device_key = load_private_key_from_bytes(&device_key_buf)?;
    verify_cert_against_ca(&device_cert, &ca_cert)?;

    let device_static_pub = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&device_static_pub, "client device_static_pub")?;
    let device_pub_bytes = device_static_pub.compress().to_bytes();

    let expected_cn = hex::encode(device_id);
    let expected_ou = hex::encode(device_pub_bytes);

    if cert_subject_field_hex(&device_cert, openssl::nid::Nid::COMMONNAME)? != expected_cn {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "device certificate CN does not match device_id",
        ));
    }
    if cert_subject_field_hex(&device_cert, openssl::nid::Nid::ORGANIZATIONALUNITNAME)? != expected_ou {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "device certificate OU does not match device_pub",
        ));
    }

    let pinned_server_pub = load_server_pub()?;
    if pinned_server_pub.is_none() && !allow_tofu_setup {
        x.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "initial setup requires an out-of-band pinned server key; run --pin-server-pub first or use --allow-tofu-setup only in lab environments",
        ));
    }

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    println!("Client[SETUP/ZTP]: Connected to {}", server_addr);

    let client_nonce = random_bytes_32();
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
    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, &device_pub_bytes, &mut sent)?;
    send_all(&mut stream, &client_nonce, &mut sent)?;
    send_blob(&mut stream, &device_cert_buf, &mut sent)?;
    stream.flush()?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;
    let server_cert_buf = recv_blob(&mut stream, MAX_CERT_FILE_SIZE, &mut recv)?;
    let server_sig = recv_blob(&mut stream, MAX_SIG_SIZE, &mut recv)?;

    let server_cert = load_cert_from_bytes(&server_cert_buf)?;
    verify_cert_against_ca(&server_cert, &ca_cert)?;
    let server_ou = cert_subject_field_hex(&server_cert, openssl::nid::Nid::ORGANIZATIONALUNITNAME)?;
    let server_pub_raw = hex::decode(&server_ou).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server certificate OU is not valid hex",
        )
    })?;
    if server_pub_raw.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "server certificate OU wrong length",
        ));
    }

    let mut server_pub_bytes = [0u8; 32];
    server_pub_bytes.copy_from_slice(&server_pub_raw);
    let server_static_pub = CompressedRistretto(server_pub_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server cert OU is not a valid Ristretto pubkey",
            )
        })?;
    reject_identity(&server_static_pub, "server_pub(cert)")?;

    if let Some(pinned) = pinned_server_pub {
        if pinned.compress().to_bytes().ct_eq(&server_pub_bytes).unwrap_u8() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "server cert bound pubkey mismatches pinned server_pub.bin",
            ));
        }
    }

    let transcript_hash = ztp_cert_transcript_hash(
        &device_id,
        &device_pub_bytes,
        &client_nonce,
        &server_nonce,
        &device_cert_buf,
        &server_cert_buf,
    );

    let server_pubkey = server_cert
        .public_key()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("server pubkey extract failed: {e}")))?;
    verify_transcript_hash_sig(&server_pubkey, &transcript_hash, &server_sig)?;

    let (a, s) = schnorr_prove_setup(&x, &device_id, &server_nonce);
    let device_sig = sign_transcript_hash(&device_key, &transcript_hash)?;

    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    send_blob(&mut stream, &device_sig, &mut sent)?;
    stream.flush()?;

    let mut ack = [0u8; 1];
    recv_exact(&mut stream, &mut ack, &mut recv)?;
    if ack[0] != 0x01 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "enrollment failed (missing/invalid ack)",
        ));
    }

    save_server_pub(&server_static_pub)?;
    if pinned_server_pub.is_none() {
        println!("Client[SETUP/ZTP]: WARNING: trusted server key on first use for this enrollment.");
    }
    println!(
        "Client[SETUP/ZTP]: Server certificate verified. Saved server_pub for AUTH_V2: {}",
        hex::encode(server_pub_bytes)
    );
    println!(
        "Client[SETUP/ZTP]: Sent={} bytes, Received={} bytes. Enrolled with mutual cert onboarding.",
        sent, recv
    );
    println!(
        "CLIENT METRICS -> Duration: {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    x.zeroize();
    Ok(())
}

// ============================================================
// AUTH V2 (encrypted zero-privacy tunnel)
// ============================================================
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

    let client_sk = EphemeralSecret::random_from_rng(OsRng);
    let client_pk = X25519Public::from(&client_sk);

    send_all(&mut stream, &[MSG_AUTH_V2], &mut sent)?;
    send_all(&mut stream, client_pk.as_bytes(), &mut sent)?;
    stream.flush()?;

    let mut server_pk_bytes = [0u8; 32];
    recv_exact(&mut stream, &mut server_pk_bytes, &mut recv)?;
    let server_pk = X25519Public::from(server_pk_bytes);

    let shared_secret = client_sk.diffie_hellman(&server_pk);
    let mut x25519_shared_bytes: [u8; 32] = *shared_secret.as_bytes();

    let mut hasher = Blake2b512::new();
    Digest::update(&mut hasher, shared_secret.as_bytes());
    Digest::update(&mut hasher, client_pk.as_bytes());
    Digest::update(&mut hasher, server_pk_bytes);
    let hash = hasher.finalize();

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];
    rx_key.copy_from_slice(&hash[0..32]);
    tx_key.copy_from_slice(&hash[32..64]);

    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());
    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());

    let mut nonce_tx_ctr = NonceCounter::new();
    let mut nonce_rx_ctr = NonceCounter::new();

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

    let ct1 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), payload1.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    let len1 = (ct1.len() as u32).to_le_bytes();
    send_all(&mut stream, &len1, &mut sent)?;
    send_all(&mut stream, &ct1, &mut sent)?;
    stream.flush()?;

    let rx_ct = recv_encrypted_blob(&mut stream, &mut recv)?;

    let pt2 = cipher_rx
        .decrypt(&nonce_rx_ctr.next(), rx_ct.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed"))?;

    if pt2.len() != 192 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid server payload length: {} (expected 192)", pt2.len()),
        ));
    }

    let mut s_pub_bytes = [0u8; 32];
    s_pub_bytes.copy_from_slice(&pt2[0..32]);
    let mut a_s_bytes = [0u8; 32];
    a_s_bytes.copy_from_slice(&pt2[32..64]);
    let mut s_s_bytes = [0u8; 32];
    s_s_bytes.copy_from_slice(&pt2[64..96]);
    let mut nonce_s = [0u8; 32];
    nonce_s.copy_from_slice(&pt2[96..128]);
    let mut eph_s_bytes = [0u8; 32];
    eph_s_bytes.copy_from_slice(&pt2[128..160]);
    let mut tag_s = [0u8; 32];
    tag_s.copy_from_slice(&pt2[160..192]);

    let server_static_pub = CompressedRistretto(s_pub_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server_static_pub")
        })?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let a_s = CompressedRistretto(a_s_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_s"))?;
    reject_identity(&a_s, "a_s")?;

    let s_s = Option::from(Scalar::from_canonical_bytes(s_s_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical s_s"))?;

    let eph_s = CompressedRistretto(eph_s_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_s"))?;
    reject_identity(&eph_s, "eph_s")?;

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

    let mut session_key = derive_session_key(
        &eph_secret,
        &eph_s,
        &nonce_c,
        &nonce_s,
        &device_id,
        &eph_pub,
        &eph_s,
        &x25519_shared_bytes,
    );
    let th = kc_transcript_hash(
        &device_id,
        &a_c,
        &s_c,
        &nonce_c,
        &eph_pub,
        &server_static_pub,
        &a_s,
        &s_s,
        &nonce_s,
        &eph_s,
    );
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);

    let expected_tag_s = hmac_tag(&k_s2c, b"server finished", &th);

    if expected_tag_s.ct_eq(&tag_s).unwrap_u8() == 0 {
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server finished tag mismatch",
        ));
    }
    println!("Client[AUTH]: Key confirmation (server finished) OK");

    let tag_c = hmac_tag(&k_c2s, b"client finished", &th);

    let ct3 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), tag_c.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    let len3 = (ct3.len() as u32).to_le_bytes();
    send_all(&mut stream, &len3, &mut sent)?;
    send_all(&mut stream, &ct3, &mut sent)?;
    stream.flush()?;

    println!("Client[AUTH]: Sent encrypted client finished tag");

    session_key.zeroize();
    x25519_shared_bytes.zeroize();
    tx_key.zeroize();
    rx_key.zeroize();
    x.zeroize();
    eph_secret.zeroize();

    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        sent,
        recv
    );
    Ok(())
}

// ============================================================
// MAIN
// ============================================================
fn usage(prog: &str) {
    eprintln!(
        "Usage:
  {0} --server 127.0.0.1:4000 --setup [--pairing-token TOKEN] [--allow-tofu-setup]
  {0} --server 127.0.0.1:4000
  {0} --pin-server-pub <hex>
  {0} --print-device-identity",
        prog
    );
}

fn print_device_identity() -> std::io::Result<()> {
    let (device_id, x) = load_device_creds_from_root()?;
    let device_pub = RISTRETTO_BASEPOINT_POINT * x;
    println!(
        "{} {}",
        hex::encode(device_id),
        hex::encode(device_pub.compress().to_bytes())
    );
    Ok(())
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "client".to_string());
    let mut server_addr = "127.0.0.1:4000".to_string();
    let mut do_setup_flag = false;
    let mut pairing_token: Option<String> = None;
    let mut print_identity = false;
    let mut allow_tofu_setup = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 >= args.len() {
                    usage(&prog);
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
            "--print-device-identity" => {
                print_identity = true;
                i += 1;
            }
            "--allow-tofu-setup" => {
                allow_tofu_setup = true;
                i += 1;
            }
            "--pairing-token" => {
                if i + 1 >= args.len() {
                    usage(&prog);
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
                    usage(&prog);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--pin-server-pub missing value",
                    ));
                }
                let decoded = hex::decode(&args[i + 1]).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid hex for pinned key")
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
                        "pinned key is not a valid Ristretto point",
                    )
                })?;
                reject_identity(&p, "pinned server pub")?;
                save_server_pub(&p)?;
                println!("Client: Successfully pinned server pubkey out-of-band.");
                return Ok(());
            }
            _ => {
                usage(&prog);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("unknown argument: {}", args[i]),
                ));
            }
        }
    }

    if print_identity {
        return print_device_identity();
    }

    if Path::new(DEVICE_ROOT_FILE).exists() { verify_private_file_permissions(DEVICE_ROOT_FILE)?; }
    if Path::new(SERVER_PUB_FILE).exists() { verify_private_file_permissions(SERVER_PUB_FILE)?; }

    if !creds_exist() && !do_setup_flag {
        eprintln!(
            "Client: device root missing ({}). Run --setup to enroll.",
            DEVICE_ROOT_FILE
        );
        return Ok(());
    }

    let had_root_before = creds_exist();
    let (device_id, x) = load_device_creds_from_root()?;

    if do_setup_flag {
        println!(
            "Client[SETUP/ZTP]: {}",
            if had_root_before {
                "Using existing device root for setup (idempotent)."
            } else {
                "No device root found; generating NEW device root."
            }
        );
        do_setup(&server_addr, device_id, x, pairing_token.as_deref(), allow_tofu_setup)
    } else {
        do_auth_v2(&server_addr, device_id, x)
    }
}