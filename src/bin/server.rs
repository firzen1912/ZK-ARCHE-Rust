use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

type HmacSha256 = Hmac<Sha256>;

const SETUP_CHALLENGE_LEN: usize = 16;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;
const MSG_HEARTBEAT: u8 = 0x10;
const MSG_HEARTBEAT_ACK: u8 = 0x11;
const MSG_GOODBYE: u8 = 0x15;

const REGISTRY_BIN: &str = "/var/lib/iot-auth/server/registry.bin";
const REGISTRY_BAK: &str = "/var/lib/iot-auth/server/registry.bak";
const REPLAY_CACHE_BIN: &str = "/var/lib/iot-auth/server/replay_cache.bin";
const SERVER_SK_FILE: &str = "/var/lib/iot-auth/server/server_sk.bin";
const OFFLINE_COUNTERS_BIN: &str = "/var/lib/iot-auth/server/offline_counters.bin";

const T_SETUP: &[u8] = b"setup_client_schnorr_v1";
const T_SETUP_SERVER: &[u8] = b"setup_server_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";
const T_OFFLINE: &[u8] = b"offline_schnorr_v1";
const T_ATTR_ROLE: &[u8] = b"client_attr_role_v1";

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const ONLINE_IDLE_TIMEOUT: Duration = Duration::from_secs(45);

const MAX_ENCRYPTED_PAYLOAD: usize = 4096;

const REPLAY_GEN_MAX: usize = 25_000;
const REPLAY_PERSIST_EVERY_INSERTS: usize = 64;
const REPLAY_PERSIST_INTERVAL: Duration = Duration::from_secs(2);
const MAX_ACTIVE_CONNECTIONS: usize = 128;
const MAX_OFFLINE_FIELD: usize = 256;
const FAILURE_WINDOW: Duration = Duration::from_secs(60);
const FAILURE_BAN: Duration = Duration::from_secs(120);
const MAX_FAILURES_PER_WINDOW: u32 = 8;

#[derive(Clone, Copy)]
struct DeviceRecord {
    pubkey: RistrettoPoint,
    role_commitment: RistrettoPoint,
    role_code: u64,
}

/// Tracks a monotonically increasing AEAD nonce counter so each encryption uses a unique 96-bit nonce.
struct NonceCounter {
    value: u64,
}

/// Tracks a monotonically increasing AEAD nonce counter so each encryption uses a unique 96-bit nonce.
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

/// Builds a deterministic, C-compatible transcript buffer that is later hashed into protocol challenges.
struct CompatTranscript {
    buf: Vec<u8>,
}

/// Builds a deterministic, C-compatible transcript buffer that is later hashed into protocol challenges.
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

#[derive(Clone, Copy)]
/// Wraps the supported value types that can be appended into a compatibility transcript.
enum TranscriptValue<'a> {
    Bytes(&'a [u8]),
    U64(u64),
    U8(u8),
    Point(&'a RistrettoPoint),
}

/// Appends a typed transcript field by serializing the value into the exact byte format expected by the protocol.
fn append_tv(t: &mut CompatTranscript, label: &[u8], v: TranscriptValue<'_>) {
    match v {
        TranscriptValue::Bytes(b) => t.append_message(label, b),
        TranscriptValue::U64(n) => t.append_message(label, &n.to_le_bytes()),
        TranscriptValue::U8(n) => t.append_message(label, &[n]),
        TranscriptValue::Point(p) => t.append_message(label, p.compress().as_bytes()),
    }
}

/// Constructs a transcript from a domain separator and an ordered list of labeled fields.
fn build_transcript(domain: &[u8], fields: &[(&[u8], TranscriptValue<'_>)]) -> CompatTranscript {
    let mut t = CompatTranscript::new(domain);
    for (label, value) in fields {
        append_tv(&mut t, label, *value);
    }
    t
}

/// Builds a transcript and derives the Schnorr challenge scalar from its hash.
fn transcript_challenge_scalar(domain: &[u8], fields: &[(&[u8], TranscriptValue<'_>)]) -> Scalar {
    build_transcript(domain, fields).challenge_scalar()
}

/// Generates a uniformly random Ristretto scalar for ephemeral proofs or keys.
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

/// Generates 32 cryptographically secure random bytes.
fn random_bytes_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

fn hash_to_point(label: &[u8]) -> RistrettoPoint {
    let mut h = Sha512::new();
    sha2::Digest::update(&mut h, b"ristretto-hash-to-point-v1");
    sha2::Digest::update(&mut h, label);
    let digest = h.finalize();

    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    RistrettoPoint::from_uniform_bytes(&wide)
}

fn attr_h() -> RistrettoPoint {
    hash_to_point(b"iot-auth/attr-h/v1")
}

/// Rejects the neutral Ristretto point so invalid or low-order inputs are not accepted.
fn reject_identity(p: &RistrettoPoint, what: &str) -> std::io::Result<()> {
    if *p == RistrettoPoint::default() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} is the identity point"),
        ));
    }
    Ok(())
}

/// Verifies the client setup proof against the presented device public key and server static key.
fn schnorr_verify_setup(
    pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    server_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
    a: &RistrettoPoint,
    s: &Scalar,
) -> bool {
    let c = transcript_challenge_scalar(
        T_SETUP,
        &[
            (b"role", TranscriptValue::Bytes(b"client")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(pubkey)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
        ],
    );
    RISTRETTO_BASEPOINT_POINT * s == a + pubkey * c
}

/// Creates the server setup proof for raw-public-key enrollment.
fn schnorr_prove_setup_server(
    server_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    device_id: &[u8; 32],
    device_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
) -> (RistrettoPoint, Scalar) {
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_SETUP_SERVER,
        &[
            (b"role", TranscriptValue::Bytes(b"server")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(device_static_pub)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(&a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
        ],
    );
    let s = r + c * server_secret;
    (a, s)
}

/// Verifies the client online-authentication Schnorr proof against the registered device key.
fn schnorr_verify_auth(
    expected_pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    let c = transcript_challenge_scalar(
        T_CLIENT,
        &[
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"pubkey", TranscriptValue::Point(expected_pubkey)),
            (b"a", TranscriptValue::Point(a)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
        ],
    );
    RISTRETTO_BASEPOINT_POINT * s == a + expected_pubkey * c
}

/// Creates the server Schnorr proof that demonstrates possession of the pinned static secret.
fn schnorr_prove_server(
    server_secret: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * server_secret;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_SERVER,
        &[
            (b"pubkey", TranscriptValue::Point(&pubkey)),
            (b"a", TranscriptValue::Point(&a)),
            (b"nonce_s", TranscriptValue::Bytes(nonce_s)),
            (b"eph_s", TranscriptValue::Point(eph_s)),
        ],
    );
    let s = r + c * server_secret;
    (a, s)
}

fn verify_role_commitment_opening(
    commitment: &RistrettoPoint,
    a: &RistrettoPoint,
    s_attr: &Scalar,
    s_blind: &Scalar,
    device_id: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> bool {
    let h = attr_h();

    let c = transcript_challenge_scalar(
        T_ATTR_ROLE,
        &[
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"commitment", TranscriptValue::Point(commitment)),
            (b"a", TranscriptValue::Point(a)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
        ],
    );

    let lhs = (RISTRETTO_BASEPOINT_POINT * s_attr) + (h * s_blind);
    let rhs = *a + (*commitment * c);
    lhs == rhs
}

/// Derives the shared session key from the Ristretto ECDHE secret, handshake nonces, identities, and X25519 tunnel binding.
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

/// Hashes the full key-confirmation transcript so both peers MAC the exact same authenticated session state.
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

/// Derives directional key-confirmation MAC keys from the session key and transcript hash.
fn derive_kc_keys(session_key: &[u8; 32], th: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(th), session_key);
    let mut k_s2c = [0u8; 32];
    let mut k_c2s = [0u8; 32];
    hk.expand(b"kc s2c", &mut k_s2c).unwrap();
    hk.expand(b"kc c2s", &mut k_c2s).unwrap();
    (k_s2c, k_c2s)
}

/// Computes an HMAC tag over a protocol label and transcript hash.
fn hmac_tag(key: &[u8; 32], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size ok");
    mac.update(label);
    mac.update(th);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Writes the full buffer to the stream and updates the transmitted-byte counter.
fn send_all(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    *sent += buf.len();
    stream.write_all(buf)
}

/// Reads an exact number of bytes from the stream and updates the received-byte counter.
fn recv_exact(stream: &mut impl Read, buf: &mut [u8], recv: &mut usize) -> std::io::Result<()> {
    stream.read_exact(buf)?;
    *recv += buf.len();
    Ok(())
}

/// Reads a single byte from the stream.
fn recv_u8(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<u8> {
    let mut b = [0u8; 1];
    recv_exact(stream, &mut b, recv)?;
    Ok(b[0])
}

/// Reads a 32-byte device identifier from the stream.
fn recv_device_id(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<[u8; 32]> {
    let mut id = [0u8; 32];
    recv_exact(stream, &mut id, recv)?;
    Ok(id)
}

/// Reads, decompresses, and validates a Ristretto point received from the peer.
fn recv_point(stream: &mut impl Read, recv: &mut usize, label: &str) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    let p = CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("invalid point: {label}")))?;
    reject_identity(&p, label)?;
    Ok(p)
}

/// Reads and validates a canonical scalar received from the peer.
fn recv_scalar(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    Option::from(Scalar::from_canonical_bytes(b))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical scalar"))
}

/// Reads a length-prefixed ciphertext while enforcing a strict maximum payload size.
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

/// Reads the optional setup pairing token and validates its UTF-8 length constraints.
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

/// Loads the device registry mapping device identifiers to registered static public keys.
fn load_registry(path: &str) -> std::io::Result<HashMap<[u8; 32], DeviceRecord>> {
    let mut reg = HashMap::new();
    let data = fs::read(path).unwrap_or_default();
    if data.is_empty() {
        return Ok(reg);
    }
    if data.len() % 104 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "registry.bin corrupt length",
        ));
    }
    for chunk in data.chunks_exact(104) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&chunk[0..32]);
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&chunk[32..64]);
        let mut role_commitment_bytes = [0u8; 32];
        role_commitment_bytes.copy_from_slice(&chunk[64..96]);
        let role_code = u64::from_le_bytes(chunk[96..104].try_into().unwrap());

        let pubkey = CompressedRistretto(pk)
            .decompress()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "registry pubkey invalid"))?;
        let role_commitment = CompressedRistretto(role_commitment_bytes)
            .decompress()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "registry role commitment invalid"))?;

        if pubkey == RistrettoPoint::default() || role_commitment == RistrettoPoint::default() {
            continue;
        }

        reg.insert(
            id,
            DeviceRecord {
                pubkey,
                role_commitment,
                role_code,
            },
        );
    }
    Ok(reg)
}

/// Atomically persists the device registry and keeps a backup copy of the previous version.
fn save_registry_atomic(
    path: &str,
    bak_path: &str,
    reg: &HashMap<[u8; 32], DeviceRecord>,
) -> std::io::Result<()> {
    ensure_parent_dir(path)?;
    ensure_parent_dir(bak_path)?;
    if Path::new(path).exists() {
        let _ = fs::copy(path, bak_path);
    }
    let _tmp = format!("{path}.tmp");
    let mut out = Vec::with_capacity(reg.len() * 104);
    for (id, rec) in reg {
        out.extend_from_slice(id);
        out.extend_from_slice(rec.pubkey.compress().as_bytes());
        out.extend_from_slice(rec.role_commitment.compress().as_bytes());
        out.extend_from_slice(&rec.role_code.to_le_bytes());
    }
    write_private_file_atomic(path, &out)?;
    Ok(())
}

/// Atomically writes sensitive state to disk using a temporary file and private permissions.
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
/// Ensures a sensitive file is not readable by group or world on Unix systems.
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
/// Ensures a sensitive file is not readable by group or world on Unix systems.
fn verify_private_file_permissions(_path: &str) -> std::io::Result<()> {
    Ok(())
}

/// Sends a length-prefixed binary blob.
fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() { send_all(stream, buf, sent)?; }
    Ok(())
}

/// Creates the parent directory for a state file when it does not already exist.
fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

/// Loads the server static secret key from disk or creates one on first boot.
fn load_or_create_server_sk(path: &str) -> std::io::Result<Scalar> {
    if Path::new(path).exists() {
        verify_private_file_permissions(path)?;
        let b = fs::read(path)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server_sk.bin wrong length",
            ));
        }
        let mut bb = [0u8; 32];
        bb.copy_from_slice(&b);
        Option::from(Scalar::from_canonical_bytes(bb)).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "server_sk.bin not canonical")
        })
    } else {
        let sk = random_scalar();
        write_private_file_atomic(path, &sk.to_bytes())?;
        Ok(sk)
    }
}

#[derive(Default)]
/// Stores recently seen client nonces across two generations to block replayed authentication attempts.
struct ReplayCache {
    current: HashSet<[u8; 64]>,
    previous: HashSet<[u8; 64]>,
    dirty: bool,
    pending_inserts: usize,
    last_persist: Option<Instant>,
}

/// Stores recently seen client nonces across two generations to block replayed authentication attempts.
impl ReplayCache {
    fn load(path: &str) -> std::io::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        let data = fs::read(path)?;
        if data.len() < 8 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "replay cache truncated"));
        }
        let current_count = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let previous_count = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let expected = 8 + (current_count + previous_count) * 64;
        if data.len() != expected {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "replay cache length mismatch"));
        }
        let mut off = 8;
        let mut current = HashSet::with_capacity(current_count);
        let mut previous = HashSet::with_capacity(previous_count);
        for _ in 0..current_count {
            let mut entry = [0u8; 64];
            entry.copy_from_slice(&data[off..off + 64]);
            current.insert(entry);
            off += 64;
        }
        for _ in 0..previous_count {
            let mut entry = [0u8; 64];
            entry.copy_from_slice(&data[off..off + 64]);
            previous.insert(entry);
            off += 64;
        }
        Ok(Self { current, previous, dirty: false, pending_inserts: 0, last_persist: Some(Instant::now()) })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + (self.current.len() + self.previous.len()) * 64);
        out.extend_from_slice(&(self.current.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.previous.len() as u32).to_le_bytes());
        for entry in &self.current {
            out.extend_from_slice(entry);
        }
        for entry in &self.previous {
            out.extend_from_slice(entry);
        }
        out
    }

    fn check_and_insert(&mut self, device_id: &[u8; 32], nonce_c: &[u8; 32]) -> bool {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(device_id);
        k[32..].copy_from_slice(nonce_c);

        if self.current.contains(&k) || self.previous.contains(&k) {
            return false;
        }

        if self.current.len() >= REPLAY_GEN_MAX {
            self.previous = std::mem::take(&mut self.current);
            self.dirty = true;
        }

        self.current.insert(k);
        self.dirty = true;
        self.pending_inserts = self.pending_inserts.saturating_add(1);
        true
    }

    fn take_persist_blob(&mut self, force: bool) -> Option<Vec<u8>> {
        let now = Instant::now();
        let due = force
            || self.pending_inserts >= REPLAY_PERSIST_EVERY_INSERTS
            || self.last_persist.map(|t| now.duration_since(t) >= REPLAY_PERSIST_INTERVAL).unwrap_or(true);
        if !self.dirty || !due {
            return None;
        }
        let blob = self.serialize();
        self.dirty = false;
        self.pending_inserts = 0;
        self.last_persist = Some(now);
        Some(blob)
    }
}

#[derive(Clone)]
/// Defines whether zero-touch setup is currently allowed and which optional token/deadline policy applies.
struct PairingPolicy {
    enabled: bool,
    token: Option<String>,
    deadline: Option<Instant>,
}

/// Defines whether zero-touch setup is currently allowed and which optional token/deadline policy applies.
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
        match (&self.token, provided_token) {
            (Some(expected), Some(got)) => {
                expected.as_bytes().ct_eq(got.as_bytes()).into()
            }
            (Some(_), None) => false,
            (None, _) => true,
        }
    }
}

struct ServerSession {
    stream: TcpStream,
    cipher_tx: ChaCha20Poly1305,
    cipher_rx: ChaCha20Poly1305,
    nonce_tx_ctr: NonceCounter,
    nonce_rx_ctr: NonceCounter,
    sent: usize,
    recv: usize,
    device_id: [u8; 32],
    last_rx: Instant,
}

impl ServerSession {
    fn send_encrypted(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let ct = self.cipher_tx
            .encrypt(&self.nonce_tx_ctr.next(), payload)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "session encrypt failed"))?;
        send_blob(&mut self.stream, &ct, &mut self.sent)?;
        self.stream.flush()?;
        Ok(())
    }

    fn recv_encrypted(&mut self) -> std::io::Result<Vec<u8>> {
        let ct = recv_encrypted_blob(&mut self.stream, &mut self.recv)?;
        let pt = self.cipher_rx
            .decrypt(&self.nonce_rx_ctr.next(), ct.as_ref())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "session decrypt failed"))?;
        self.last_rx = Instant::now();
        Ok(pt)
    }
}

#[derive(Clone)]
/// Tracks recent failures for one peer so the server can rate-limit abusive sources.
struct FailureState {
    first_failure: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

#[derive(Default)]
/// Maintains rolling failure counters and temporary blocks for peers that exceed policy.
struct FailureTracker {
    peers: HashMap<String, FailureState>,
}

/// Maintains rolling failure counters and temporary blocks for peers that exceed policy.
impl FailureTracker {
    fn is_blocked(&mut self, peer: &str) -> bool {
        let now = Instant::now();
        self.peers.retain(|_, state| {
            state.blocked_until.map(|t| t > now).unwrap_or(false) || now.duration_since(state.first_failure) <= FAILURE_WINDOW
        });
        match self.peers.get(peer).and_then(|s| s.blocked_until) {
            Some(until) if until > now => true,
            _ => false,
        }
    }

    fn note_failure(&mut self, peer: &str) {
        let now = Instant::now();
        let state = self.peers.entry(peer.to_string()).or_insert(FailureState {
            first_failure: now,
            failures: 0,
            blocked_until: None,
        });
        if now.duration_since(state.first_failure) > FAILURE_WINDOW {
            state.first_failure = now;
            state.failures = 0;
            state.blocked_until = None;
        }
        state.failures = state.failures.saturating_add(1);
        if state.failures >= MAX_FAILURES_PER_WINDOW {
            state.blocked_until = Some(now + FAILURE_BAN);
        }
    }

    fn note_success(&mut self, peer: &str) {
        self.peers.remove(peer);
    }
}

/// RAII guard that increments the active-connection count on entry and decrements it on drop.
struct ActiveConnGuard {
    active: Arc<AtomicUsize>,
}

/// RAII guard that increments the active-connection count on entry and decrements it on drop.
impl ActiveConnGuard {
    fn try_acquire(active: Arc<AtomicUsize>) -> Option<Self> {
        loop {
            let current = active.load(Ordering::Relaxed);
            if current >= MAX_ACTIVE_CONNECTIONS {
                return None;
            }
            if active
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(Self { active });
            }
        }
    }
}

/// Implements helper methods for drop.
impl Drop for ActiveConnGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone)]
/// Represents a serialized offline authorization proof and its metadata.
struct OfflineProof {
    version: u8,
    device_id: [u8; 32],
    device_pub: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    counter: u64,
    audience: Vec<u8>,
    scope: Vec<u8>,
    request_hash: [u8; 32],
    a: [u8; 32],
    s: [u8; 32],
}

/// Represents a serialized offline authorization proof and its metadata.
impl OfflineProof {
    fn deserialize(buf: &[u8]) -> std::io::Result<Self> {
        let mut idx = 0usize;
        fn take<'a>(buf: &'a [u8], idx: &mut usize, n: usize) -> std::io::Result<&'a [u8]> {
            if buf.len().saturating_sub(*idx) < n {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "offline proof truncated"));
            }
            let out = &buf[*idx..*idx + n];
            *idx += n;
            Ok(out)
        }
        let version = take(buf, &mut idx, 1)?[0];
        let mut device_id = [0u8; 32];
        device_id.copy_from_slice(take(buf, &mut idx, 32)?);
        let mut device_pub = [0u8; 32];
        device_pub.copy_from_slice(take(buf, &mut idx, 32)?);
        let issued_at = u64::from_le_bytes(take(buf, &mut idx, 8)?.try_into().unwrap());
        let expires_at = u64::from_le_bytes(take(buf, &mut idx, 8)?.try_into().unwrap());
        let counter = u64::from_le_bytes(take(buf, &mut idx, 8)?.try_into().unwrap());
        let audience_len = u16::from_le_bytes(take(buf, &mut idx, 2)?.try_into().unwrap()) as usize;
        if audience_len == 0 || audience_len > MAX_OFFLINE_FIELD {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid offline audience length"));
        }
        let audience = take(buf, &mut idx, audience_len)?.to_vec();
        let scope_len = u16::from_le_bytes(take(buf, &mut idx, 2)?.try_into().unwrap()) as usize;
        if scope_len == 0 || scope_len > MAX_OFFLINE_FIELD {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid offline scope length"));
        }
        let scope = take(buf, &mut idx, scope_len)?.to_vec();
        let mut request_hash = [0u8; 32];
        request_hash.copy_from_slice(take(buf, &mut idx, 32)?);
        let mut a = [0u8; 32];
        a.copy_from_slice(take(buf, &mut idx, 32)?);
        let mut s = [0u8; 32];
        s.copy_from_slice(take(buf, &mut idx, 32)?);
        if idx != buf.len() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "offline proof has trailing bytes"));
        }
        Ok(Self { version, device_id, device_pub, issued_at, expires_at, counter, audience, scope, request_hash, a, s })
    }
}

#[derive(Default)]
/// Stores the highest accepted offline-proof counter for each device.
struct OfflineCounterStore {
    highest: HashMap<[u8; 32], u64>,
}

/// Stores the highest accepted offline-proof counter for each device.
impl OfflineCounterStore {
    fn load(path: &str) -> std::io::Result<Self> {
        if !Path::new(path).exists() {
            return Ok(Self::default());
        }
        let data = fs::read(path)?;
        if data.len() % 40 != 0 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "offline counter store corrupt"));
        }
        let mut highest = HashMap::new();
        for chunk in data.chunks_exact(40) {
            let mut id = [0u8; 32];
            id.copy_from_slice(&chunk[..32]);
            let ctr = u64::from_le_bytes(chunk[32..40].try_into().unwrap());
            highest.insert(id, ctr);
        }
        Ok(Self { highest })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.highest.len() * 40);
        for (id, ctr) in &self.highest {
            out.extend_from_slice(id);
            out.extend_from_slice(&ctr.to_le_bytes());
        }
        out
    }

    fn check_and_update(&mut self, device_id: &[u8; 32], counter: u64) -> std::io::Result<()> {
        match self.highest.get(device_id).copied() {
            Some(prev) if counter <= prev => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("offline counter replay detected (counter={} prev={})", counter, prev),
            )),
            _ => {
                self.highest.insert(*device_id, counter);
                Ok(())
            }
        }
    }
}

/// Returns the current Unix timestamp in seconds.
fn unix_time_now() -> std::io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("system time error: {e}")))?
        .as_secs())
}

/// Builds the challenge scalar used for offline authorization proofs.
fn offline_challenge_scalar(
    device_id: &[u8; 32],
    device_pub: &RistrettoPoint,
    audience: &[u8],
    scope: &[u8],
    issued_at: u64,
    expires_at: u64,
    counter: u64,
    request_hash: &[u8; 32],
    a: &RistrettoPoint,
) -> Scalar {
    transcript_challenge_scalar(
        T_OFFLINE,
        &[
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"pubkey", TranscriptValue::Point(device_pub)),
            (b"audience", TranscriptValue::Bytes(audience)),
            (b"scope", TranscriptValue::Bytes(scope)),
            (b"issued_at", TranscriptValue::U64(issued_at)),
            (b"expires_at", TranscriptValue::U64(expires_at)),
            (b"counter", TranscriptValue::U64(counter)),
            (b"request_hash", TranscriptValue::Bytes(request_hash)),
            (b"a", TranscriptValue::Point(a)),
        ],
    )
}

/// Verifies an offline authorization proof against registry state, scope policy, counter monotonicity, and expiry.
fn verify_offline_proof(
    proof_path: &str,
    expected_audience: &str,
    allowed_scopes: &HashSet<String>,
    reg: &HashMap<[u8; 32], RistrettoPoint>,
    counters: &mut OfflineCounterStore,
) -> std::io::Result<()> {
    let proof = OfflineProof::deserialize(&fs::read(proof_path)?)?;
    if proof.version != 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unsupported offline proof version"));
    }
    if proof.audience != expected_audience.as_bytes() {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "offline proof audience mismatch"));
    }
    let scope_str = String::from_utf8(proof.scope.clone())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "offline scope is not UTF-8"))?;
    if !allowed_scopes.contains(&scope_str) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("offline scope '{}' not allowed", scope_str)));
    }
    if proof.issued_at >= proof.expires_at {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "offline proof validity window is invalid"));
    }
    let now = unix_time_now()?;
    if now < proof.issued_at || now > proof.expires_at {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "offline proof expired or not yet valid"));
    }
    if proof.expires_at - proof.issued_at > 300 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "offline proof validity exceeds 300 seconds"));
    }
    let expected_pub = reg.get(&proof.device_id).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "offline proof device is not enrolled")
    })?;
    if expected_pub.compress().to_bytes().ct_eq(&proof.device_pub).unwrap_u8() == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "offline proof pubkey mismatch"));
    }
    let a = CompressedRistretto(proof.a)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "offline proof A invalid"))?;
    reject_identity(&a, "offline A")?;
    let s: Scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.s))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "offline proof s is non-canonical"))?;
    let c: Scalar = offline_challenge_scalar(
        &proof.device_id,
        expected_pub,
        &proof.audience,
        &proof.scope,
        proof.issued_at,
        proof.expires_at,
        proof.counter,
        &proof.request_hash,
        &a,
    );
    if RISTRETTO_BASEPOINT_POINT * s != a + (*expected_pub * c) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "offline Schnorr proof invalid"));
    }
    counters.check_and_update(&proof.device_id, proof.counter)?;
    write_private_file_atomic(OFFLINE_COUNTERS_BIN, &counters.serialize())?;
    println!(
        "Server[OFFLINE]: verified offline proof file={} device_id={} scope='{}' counter={} request_hash={}",
        proof_path,
        hex::encode(proof.device_id),
        scope_str,
        proof.counter,
        hex::encode(proof.request_hash)
    );
    Ok(())
}

/// Processes a client setup request, validates certificates and setup proofs, enforces pairing policy, and registers the client key.
/// Step 1: read the incoming setup request, pairing token, client identity, and certificate material.
fn handle_setup(
    stream: &mut TcpStream,
    policy: &PairingPolicy,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    sent: &mut usize,
    recv: &mut usize,
    failures: &Arc<Mutex<FailureTracker>>,
    peer_key: &str,
) -> std::io::Result<()> {
    if failures.lock().unwrap().is_blocked(peer_key) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer temporarily rate limited"));
    }

    let provided_token = recv_pairing_token(stream, recv)?;
    if !policy.allows_ztp_setup(provided_token.as_deref()) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "pairing rejected by policy"));
    }

    let device_id = recv_device_id(stream, recv)?;
    let device_static_pub = recv_point(stream, recv, "device_pub")?;
    let device_pub_bytes = device_static_pub.compress().to_bytes();
    let mut client_nonce = [0u8; 32];
    recv_exact(stream, &mut client_nonce, recv)?;
    let role_commitment = recv_point(stream, recv, "role_commitment")?;

    {
        let reg_r = reg.read().unwrap();
        if let Some(existing) = reg_r.get(&device_id) {
            if existing.pubkey.compress().to_bytes().ct_eq(&device_pub_bytes).unwrap_u8() == 0 {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device_id collision"));
            }
        }
    }

    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);
    let mut setup_challenge = [0u8; SETUP_CHALLENGE_LEN];
    OsRng.fill_bytes(&mut setup_challenge);

    send_all(stream, &server_nonce, sent)?;
    send_all(stream, &setup_challenge, sent)?;
    send_all(stream, server_static_pub.compress().as_bytes(), sent)?;
    let (a_s, s_s) = schnorr_prove_setup_server(
        server_static_secret,
        server_static_pub,
        &device_id,
        &device_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
    );
    send_all(stream, a_s.compress().as_bytes(), sent)?;
    send_all(stream, &s_s.to_bytes(), sent)?;
    stream.flush()?;

    let a = recv_point(stream, recv, "setup_A")?;
    let s = recv_scalar(stream, recv)?;

    if !schnorr_verify_setup(
        &device_static_pub,
        &device_id,
        server_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
        &a,
        &s,
    ) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Schnorr proof invalid"));
    }

    let upsert = {
        let mut reg_w = reg.write().unwrap();
        let existed = reg_w.contains_key(&device_id);
        reg_w.insert(device_id, DeviceRecord {
            pubkey: device_static_pub,
            role_commitment,
            role_code: 1u64,
        });
        save_registry_atomic(REGISTRY_BIN, REGISTRY_BAK, &reg_w)?;
        !existed
    };

    println!(
        "Server[SETUP/RPK]: {} device_id={} via raw-public-key onboarding",
        if upsert { "enrolled NEW" } else { "validated existing" },
        hex::encode(device_id),
    );

    send_all(stream, &[0x01u8], sent)?;
    stream.flush()?;
    Ok(())
}

/// Processes a live authentication request, enforces replay protection, verifies the registered client, derives the session, and completes key confirmation.
/// Step 1: establish the outer X25519 tunnel and receive the client's encrypted authentication payload.
fn handle_auth_v2(
    mut stream: TcpStream,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    replay: &Arc<Mutex<ReplayCache>>,
    sent: &mut usize,
    recv: &mut usize,
    failures: &Arc<Mutex<FailureTracker>>,
    peer_key: &str,
) -> std::io::Result<ServerSession> {
    let mut client_pk_bytes = [0u8; 32];
    recv_exact(&mut stream, &mut client_pk_bytes, recv)?;
    let client_pk = X25519Public::from(client_pk_bytes);

    let server_sk = EphemeralSecret::random_from_rng(OsRng);
    let server_pk = X25519Public::from(&server_sk);
    send_all(&mut stream, server_pk.as_bytes(), sent)?;
    stream.flush()?;

    let shared_secret = server_sk.diffie_hellman(&client_pk);
    let mut x25519_shared_bytes: [u8; 32] = *shared_secret.as_bytes();

    let mut hasher = Blake2b512::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(client_pk_bytes);
    hasher.update(server_pk.as_bytes());
    let hash = hasher.finalize();

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];
    rx_key.copy_from_slice(&hash[32..64]);
    tx_key.copy_from_slice(&hash[0..32]);

    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());
    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());

    let mut nonce_rx_ctr = NonceCounter::new();
    let mut nonce_tx_ctr = NonceCounter::new();

    let rx_ct = recv_encrypted_blob(&mut stream, recv)?;
    let pt = cipher_rx
        .decrypt(&nonce_rx_ctr.next(), rx_ct.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed"))?;

    if pt.len() != 288 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid payload size: {} (expected 288)", pt.len()),
        ));
    }

    let mut device_id   = [0u8; 32]; device_id.copy_from_slice(&pt[0..32]);
    let mut a_c_bytes   = [0u8; 32]; a_c_bytes.copy_from_slice(&pt[32..64]);
    let mut s_c_bytes   = [0u8; 32]; s_c_bytes.copy_from_slice(&pt[64..96]);
    let mut nonce_c     = [0u8; 32]; nonce_c.copy_from_slice(&pt[96..128]);
    let mut eph_c_bytes = [0u8; 32]; eph_c_bytes.copy_from_slice(&pt[128..160]);
    let mut role_commitment_bytes = [0u8; 32]; role_commitment_bytes.copy_from_slice(&pt[160..192]);
    let mut attr_a_bytes = [0u8; 32]; attr_a_bytes.copy_from_slice(&pt[192..224]);
    let mut attr_s_attr_bytes = [0u8; 32]; attr_s_attr_bytes.copy_from_slice(&pt[224..256]);
    let mut attr_s_blind_bytes = [0u8; 32]; attr_s_blind_bytes.copy_from_slice(&pt[256..288]);

    let a_c = CompressedRistretto(a_c_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_c"))?;
    reject_identity(&a_c, "a_c")?;

    let s_c = Option::from(Scalar::from_canonical_bytes(s_c_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical s_c"))?;

    let eph_c = CompressedRistretto(eph_c_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_c"))?;
    reject_identity(&eph_c, "eph_c")?;

    let role_commitment = CompressedRistretto(role_commitment_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid role_commitment"))?;
    reject_identity(&role_commitment, "role_commitment")?;

    let attr_a = CompressedRistretto(attr_a_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid attr_a"))?;
    reject_identity(&attr_a, "attr_a")?;

    let attr_s_attr: Scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(attr_s_attr_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical attr_s_attr"))?;

    let attr_s_blind: Scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(attr_s_blind_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical attr_s_blind"))?;

    if failures.lock().unwrap().is_blocked(peer_key) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "peer temporarily rate limited"));
    }

    let replay_persist_blob = {
        let mut rc = replay.lock().unwrap();
        if !rc.check_and_insert(&device_id, &nonce_c) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "replay detected",
            ));
        }
        rc.take_persist_blob(false)
    };
    if let Some(blob) = replay_persist_blob {
        write_private_file_atomic(REPLAY_CACHE_BIN, &blob)?;
    }

    // Step 4: look up the registered device key and verify the client Schnorr proof against it.
    let record = {
        let reg_r = reg.read().unwrap();
        match reg_r.get(&device_id) {
            Some(r) => *r,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "unknown device_id",
                ))
            }
        }
    };

    if !schnorr_verify_auth(&record.pubkey, &device_id, &a_c, &s_c, &nonce_c, &eph_c) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "client Schnorr proof invalid",
        ));
    }

    let nonce_s = random_bytes_32();
    let mut eph_s_secret = random_scalar();
    let eph_s = RISTRETTO_BASEPOINT_POINT * eph_s_secret;
    // Step 5: build the server proof, derive the authenticated session key, and send the server key-confirmation tag.
    let (a_s, s_s) = schnorr_prove_server(server_static_secret, &nonce_s, &eph_s);

    let mut session_key = derive_session_key(
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

    let ct2 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), payload2.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encrypt failed"))?;

    let len2 = (ct2.len() as u32).to_le_bytes();
    send_all(&mut stream, &len2, sent)?;
    send_all(&mut stream, &ct2, sent)?;
    stream.flush()?;

    let rx_ct2 = recv_encrypted_blob(&mut stream, recv)?;

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

    let tag_c_arr: [u8; 32] = tag_c_plain.try_into().unwrap();
    if expected_tag_c.ct_eq(&tag_c_arr).unwrap_u8() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "tag_c mismatch",
        ));
    }

    println!(
        "Server[AUTH]: device_id={} KC=OK",
        hex::encode(device_id),
    );

    if let Some(blob) = replay.lock().unwrap().take_persist_blob(true) {
        write_private_file_atomic(REPLAY_CACHE_BIN, &blob)?;
    }

    session_key.zeroize();
    eph_s_secret.zeroize();
    tx_key.zeroize();
    rx_key.zeroize();
    x25519_shared_bytes.zeroize();
    Ok(ServerSession {
        stream,
        cipher_tx,
        cipher_rx,
        nonce_tx_ctr,
        nonce_rx_ctr,
        sent: *sent,
        recv: *recv,
        device_id,
        last_rx: Instant::now(),
    })
}

fn run_server_session(mut session: ServerSession) -> std::io::Result<(usize, usize)> {
    println!("Server[ONLINE]: session established for {}", hex::encode(session.device_id));
    session.stream.set_read_timeout(Some(IO_TIMEOUT))?;
    loop {
        if session.last_rx.elapsed() >= ONLINE_IDLE_TIMEOUT {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "client idle timeout"));
        }
        let msg = session.recv_encrypted()?;
        if msg.len() != 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unexpected online payload"));
        }
        match msg[0] {
            MSG_HEARTBEAT => {
                println!("Server[HB]: heartbeat from {}", hex::encode(session.device_id));
                let ack = [MSG_HEARTBEAT_ACK];
                session.send_encrypted(&ack)?;
            }
            MSG_GOODBYE => break,
            other => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("unexpected online message: 0x{other:02x}")));
            }
        }
    }
    Ok((session.sent, session.recv))
}

/// Dispatches one inbound TCP client connection to the appropriate protocol handler.
/// Step 1: rate-limit abusive peers, cap concurrency, and identify the requested message type.
fn handle_client(
    mut stream: TcpStream,
    server_static_secret: Arc<Scalar>,
    server_static_pub: Arc<RistrettoPoint>,
    policy: PairingPolicy,
    reg: Arc<RwLock<HashMap<[u8; 32], DeviceRecord>>>,
    replay: Arc<Mutex<ReplayCache>>,
    failures: Arc<Mutex<FailureTracker>>,
    _active_guard: ActiveConnGuard,
) {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv_bytes = 0usize;
    let peer = stream.peer_addr().ok();
    let peer_key = peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unknown".to_string());

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
            &mut stream,
            &policy,
            &server_static_secret,
            &server_static_pub,
            &reg,
            &mut sent,
            &mut recv_bytes,
            &failures,
            &peer_key,
        ),
        MSG_AUTH_V2 => handle_auth_v2(
            stream, &server_static_secret, &server_static_pub,
            &reg, &replay, &mut sent, &mut recv_bytes, &failures, &peer_key,
        ).and_then(|session| {
            let (final_sent, final_recv) = run_server_session(session)?;
            sent = final_sent;
            recv_bytes = final_recv;
            Ok(())
        }),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown msg_type: 0x{msg_type:02x}"),
        )),
    };

    match res {
        Ok(()) => failures.lock().unwrap().note_success(&peer_key),
        Err(e) => {
            failures.lock().unwrap().note_failure(&peer_key);
            eprintln!("Server: request from {:?} failed: {}", peer, e);
        }
    }

    println!(
        "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        peer, start.elapsed(), sent, recv_bytes,
    );
}

/// Parses CLI arguments, loads local credentials, and dispatches to setup, live authentication, offline proof, or continuity operations.
/// Step 1: parse server flags, pairing options, verification utilities, and bind address.
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "server".to_string());

    let mut bind_addr = "0.0.0.0:4000".to_string();
    let mut pairing = false;
    let mut pairing_token: Option<String> = None;
    let mut pairing_seconds: Option<u64> = None;
    let mut print_pubkey = false;
    let mut verify_offline_path: Option<String> = None;
    let mut offline_audience: Option<String> = None;
    let mut offline_scopes: Vec<String> = Vec::new();

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
            "--verify-offline-proof" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--verify-offline-proof missing value")); }
                verify_offline_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--audience" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--audience missing value")); }
                offline_audience = Some(args[i + 1].clone());
                i += 2;
            }
            "--allow-offline-scope" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--allow-offline-scope missing value")); }
                offline_scopes.push(args[i + 1].clone());
                i += 2;
            }
            _ => {
                eprintln!("Usage: {} [--bind 0.0.0.0:4000] [--pairing] [--pairing-token TOKEN] [--pairing-seconds N] [--print-pubkey] [--verify-offline-proof FILE --audience NAME --allow-offline-scope SCOPE ...]", prog);
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

    verify_private_file_permissions(SERVER_SK_FILE)?;

    let deadline = pairing_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let policy = PairingPolicy { enabled: pairing, token: pairing_token, deadline };
    let reg_map: HashMap<[u8; 32], DeviceRecord> = load_registry(REGISTRY_BIN).unwrap_or_default();

    // Step 3: handle utility modes such as offline-proof verification or continuity-proof generation.
    if let Some(proof_path) = verify_offline_path.as_deref() {
        let audience = offline_audience.as_deref().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "--verify-offline-proof requires --audience")
        })?;
        if offline_scopes.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "--verify-offline-proof requires at least one --allow-offline-scope",
            ));
        }
        let allowed_scopes: HashSet<String> = offline_scopes.into_iter().collect();
        let mut counters = OfflineCounterStore::load(OFFLINE_COUNTERS_BIN).unwrap_or_default();
        let reg_pub: HashMap<[u8; 32], RistrettoPoint> =
            reg_map.iter().map(|(k, v)| (*k, v.pubkey)).collect();
        return verify_offline_proof(proof_path, audience, &allowed_scopes, &reg_pub, &mut counters);
    }
    // Step 4: initialize shared server state and begin accepting TCP clients.
    let reg = Arc::new(RwLock::new(reg_map));
    let replay_state = ReplayCache::load(REPLAY_CACHE_BIN).unwrap_or_default();
    let replay = Arc::new(Mutex::new(replay_state));
    let failures = Arc::new(Mutex::new(FailureTracker::default()));
    let active_connections = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(&bind_addr)?;

    println!("C-compatible Rust Server listening on {}", bind_addr);
    println!("Server public key (pin this on client): {}", hex::encode(server_static_pub.compress().to_bytes()));
    println!(
        "Server: pairing_enabled={} token_configured={} deadline={} raw_pubkey_onboarding=true",
        policy.enabled,
        policy.token.is_some(),
        if policy.deadline.is_some() { "set" } else { "none" },
    );

    let ss = Arc::new(server_static_secret);
    let sp = Arc::new(server_static_pub);

    loop {
        let (stream, _) = listener.accept()?;
        let ss2 = Arc::clone(&ss);
        let sp2 = Arc::clone(&sp);
        let pol2 = policy.clone();
        let reg2 = Arc::clone(&reg);
        let rep2 = Arc::clone(&replay);
        let failures2 = Arc::clone(&failures);
        let active2 = Arc::clone(&active_connections);
        let Some(active_guard) = ActiveConnGuard::try_acquire(active2) else {
            eprintln!("Server: rejecting connection because active connection limit ({}) was reached", MAX_ACTIVE_CONNECTIONS);
            drop(stream);
            continue;
        };
        thread::spawn(move || {
            handle_client(stream, ss2, sp2, pol2, reg2, rep2, failures2, active_guard);
        });
    }
}
