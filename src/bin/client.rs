use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::TcpStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;
const MSG_HEARTBEAT: u8 = 0x10;
const MSG_HEARTBEAT_ACK: u8 = 0x11;
const MSG_GOODBYE: u8 = 0x15;

const DEVICE_ROOT_FILE: &str = "/var/lib/iot-auth/client/device_root.bin";
const SERVER_PUB_FILE: &str = "/var/lib/iot-auth/client/server_pub.bin";
const OFFLINE_COUNTER_FILE: &str = "/var/lib/iot-auth/client/offline_counter.bin";
const CLIENT_CONTINUITY_FILE: &str = "/var/lib/iot-auth/client/continuity.bin";
const SERVER_CONTINUITY_TRACK_FILE: &str = "/var/lib/iot-auth/client/server_continuity_track.bin";

const T_SETUP: &[u8] = b"setup_client_schnorr_v1";
const T_SETUP_SERVER: &[u8] = b"setup_server_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";
const T_OFFLINE: &[u8] = b"offline_schnorr_v1";
const T_CLIENT_CONT: &[u8] = b"client_continuity_v1";
const T_SERVER_CONT: &[u8] = b"server_continuity_v1";

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ENCRYPTED_PAYLOAD: usize = 4096;
const MAX_OFFLINE_FIELD: usize = 256;

const DAEMON_BASE_BACKOFF: Duration = Duration::from_secs(1);
const DAEMON_MAX_BACKOFF: Duration = Duration::from_secs(30);
const DEFAULT_CONTINUITY_EXPIRES_IN: u64 = 300;
const DEFAULT_DAEMON_SUCCESS_SLEEP: Duration = Duration::from_secs(5);
const HEARTBEAT_ACK_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_MAX_AGE: Duration = Duration::from_secs(1800);
const MAX_MISSED_HEARTBEATS: u32 = 3;

#[derive(Clone, Debug)]
struct ClientDaemonConfig {
    enabled: bool,
    success_sleep: Duration,
    continuity_expires_in: u64,
}

impl Default for ClientDaemonConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            success_sleep: DEFAULT_DAEMON_SUCCESS_SLEEP,
            continuity_expires_in: DEFAULT_CONTINUITY_EXPIRES_IN,
        }
    }
}

#[derive(Clone, Debug)]
struct ReconnectBackoff {
    current: Duration,
    max: Duration,
}

impl ReconnectBackoff {
    fn new(base: Duration, max: Duration) -> Self {
        Self { current: base, max }
    }

    fn reset(&mut self, base: Duration) {
        self.current = base;
    }

    fn next_delay(&mut self) -> Duration {
        let base_ms = self.current.as_millis() as u64;
        let jitter_ms = if base_ms == 0 { 0 } else { (OsRng.next_u32() as u64) % (base_ms / 2 + 1) };
        let out = self.current.saturating_add(Duration::from_millis(jitter_ms));
        self.current = std::cmp::min(self.current.saturating_mul(2), self.max);
        out
    }
}

struct ClientSession {
    stream: TcpStream,
    cipher_tx: ChaCha20Poly1305,
    cipher_rx: ChaCha20Poly1305,
    nonce_tx_ctr: NonceCounter,
    nonce_rx_ctr: NonceCounter,
    established_at: Instant,
    sent: usize,
    recv: usize,
}

impl ClientSession {
    fn send_encrypted(&mut self, payload: &[u8]) -> std::io::Result<()> {
        let ct = self.cipher_tx
            .encrypt(&self.nonce_tx_ctr.next(), payload)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "session encryption failed"))?;
        send_blob(&mut self.stream, &ct, &mut self.sent)?;
        self.stream.flush()?;
        Ok(())
    }

    fn recv_encrypted(&mut self) -> std::io::Result<Vec<u8>> {
        let ct = recv_encrypted_blob(&mut self.stream, &mut self.recv)?;
        self.cipher_rx
            .decrypt(&self.nonce_rx_ctr.next(), ct.as_ref())
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "session decryption failed"))
    }
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

/// Creates the client setup proof used during raw-public-key enrollment.
fn schnorr_prove_setup(
    x: &Scalar,
    device_id: &[u8; 32],
    device_pub: &RistrettoPoint,
    server_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
) -> (RistrettoPoint, Scalar) {
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_SETUP,
        &[
            (b"role", TranscriptValue::Bytes(b"client")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(device_pub)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(&a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
        ],
    );
    let s = r + c * x;
    (a, s)
}

/// Verifies the server setup proof during enrollment.
fn schnorr_verify_setup_server(
    server_static_pub: &RistrettoPoint,
    device_id: &[u8; 32],
    device_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
) -> bool {
    let c = transcript_challenge_scalar(
        T_SETUP_SERVER,
        &[
            (b"role", TranscriptValue::Bytes(b"server")),
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"device_pub", TranscriptValue::Point(device_pub)),
            (b"server_pub", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(a)),
            (b"client_nonce", TranscriptValue::Bytes(client_nonce)),
            (b"server_nonce", TranscriptValue::Bytes(server_nonce)),
        ],
    );
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
}

/// Creates the client Schnorr proof bound to the live authentication exchange.
fn schnorr_prove_auth(
    x: &Scalar,
    device_id: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = transcript_challenge_scalar(
        T_CLIENT,
        &[
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"pubkey", TranscriptValue::Point(&pubkey)),
            (b"a", TranscriptValue::Point(&a)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
        ],
    );
    let s = r + c * x;
    (a, s)
}

/// Verifies the server Schnorr proof received during online authentication.
fn schnorr_verify_server(
    server_static_pub: &RistrettoPoint,
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> bool {
    let c = transcript_challenge_scalar(
        T_SERVER,
        &[
            (b"pubkey", TranscriptValue::Point(server_static_pub)),
            (b"a", TranscriptValue::Point(a)),
            (b"nonce_s", TranscriptValue::Bytes(nonce_s)),
            (b"eph_s", TranscriptValue::Point(eph_s)),
        ],
    );
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
}

/// Derives the shared session key from the Ristretto ECDHE secret, handshake nonces, identities, and X25519 tunnel binding.
fn derive_session_key(
    eph_secret: &Scalar,
    peer_eph_pub: &RistrettoPoint,
    nonce_c: &[u8; 32],
    nonce_s: &[u8; 32],
    device_id: &[u8; 32],
    server_static_pub: &RistrettoPoint,
    eph_c: &RistrettoPoint,
    eph_s: &RistrettoPoint,
) -> [u8; 32] {
    let shared = peer_eph_pub * eph_secret;
    let shared_bytes = shared.compress().to_bytes();

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(nonce_c);
    salt[32..].copy_from_slice(nonce_s);

    let mut info = Vec::with_capacity(11 + 32 + 32 + 32 + 32);
    info.extend_from_slice(b"session key");
    info.extend_from_slice(device_id);
    info.extend_from_slice(server_static_pub.compress().as_bytes());
    info.extend_from_slice(eph_c.compress().as_bytes());
    info.extend_from_slice(eph_s.compress().as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
    okm
}

/// Hashes the one-ZKP AUTH transcript so both peers MAC the exact same authenticated session state.
fn kc_transcript_hash(
    device_id: &[u8; 32],
    a_c: &RistrettoPoint,
    s_c: &Scalar,
    nonce_c: &[u8; 32],
    server_pub: &RistrettoPoint,
    nonce_s: &[u8; 32],
    eph_c: &RistrettoPoint,
    eph_s: &RistrettoPoint,
) -> [u8; 32] {
    let mut t = CompatTranscript::new(T_KC);
    t.append_message(b"device_id", device_id);
    t.append_message(b"a_c", a_c.compress().as_bytes());
    t.append_message(b"s_c", &s_c.to_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"server_pub", server_pub.compress().as_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());
    t.append_message(b"eph_s", eph_s.compress().as_bytes());

    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, &t.buf);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Derives the server-finish MAC key and directional transport AEAD keys from the session key and transcript hash.
fn derive_auth_keys(session_key: &[u8; 32], th: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(th), session_key);
    let mut k_finish = [0u8; 32];
    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    hk.expand(b"auth finish", &mut k_finish).unwrap();
    hk.expand(b"transport c2s", &mut k_c2s).unwrap();
    hk.expand(b"transport s2c", &mut k_s2c).unwrap();
    (k_finish, k_c2s, k_s2c)
}

/// Computes an HMAC tag over a protocol label and transcript hash.
fn hmac_tag(key: &[u8; 32], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size ok");
    Mac::update(&mut mac, label);
    Mac::update(&mut mac, th);
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

/// Reads a length-prefixed ciphertext while enforcing a strict maximum payload size.
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

/// Creates the parent directory for a state file when it does not already exist.
fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
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

/// Loads the client root secret from disk or creates a new one on first use.
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

/// Deterministically derives the public device identifier from the client root secret.
fn derive_device_id(root: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("invalid Blake2b output length");
    Update::update(&mut h, b"device-id");
    Update::update(&mut h, root);

    let mut device_id = [0u8; 32];
    h.finalize_variable(&mut device_id)
        .expect("failed to finalize Blake2b-256");
    device_id
}

/// Deterministically derives the client static authentication scalar from the root secret.
fn derive_device_scalar(root: &[u8; 32]) -> Scalar {
    let mut h = Blake2b512::new();
    Digest::update(&mut h, b"device-auth-v1");
    Digest::update(&mut h, root);
    let digest = h.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest[..64]);
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Loads the client root secret, derives the device identifier and static scalar, then zeroizes the root.
fn load_device_creds_from_root() -> std::io::Result<([u8; 32], Scalar)> {
    let mut root = load_or_create_device_root()?;
    let device_id = derive_device_id(&root);
    let x = derive_device_scalar(&root);
    root.zeroize();
    Ok((device_id, x))
}

/// Returns whether the client root credential file already exists.
fn creds_exist() -> bool {
    Path::new(DEVICE_ROOT_FILE).exists()
}

/// Sends a length-prefixed binary blob.
fn send_blob(stream: &mut impl Write, buf: &[u8], sent: &mut usize) -> std::io::Result<()> {
    send_all(stream, &(buf.len() as u32).to_le_bytes(), sent)?;
    if !buf.is_empty() {
        send_all(stream, buf, sent)?;
    }
    Ok(())
}

/// Loads the locally pinned server static public key from disk.
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

/// Stores the pinned server static public key on disk.
fn save_server_pub(pubkey: &RistrettoPoint) -> std::io::Result<()> {
    write_private_file_atomic(SERVER_PUB_FILE, pubkey.compress().as_bytes())
}

/// Runs the client-side raw-public-key setup flow and pins the server static key.
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

    let device_static_pub = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&device_static_pub, "client device_static_pub")?;
    let device_pub_bytes = device_static_pub.compress().to_bytes();

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
    println!("Client[SETUP/RPK]: Connected to {}", server_addr);

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
    stream.flush()?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;
    let mut server_pub_bytes = [0u8; 32];
    recv_exact(&mut stream, &mut server_pub_bytes, &mut recv)?;
    let server_static_pub = CompressedRistretto(server_pub_bytes)
        .decompress()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "server static public key is not a valid Ristretto pubkey",
            )
        })?;
    reject_identity(&server_static_pub, "server_pub(setup)")?;

    let a_s = recv_point(&mut stream, &mut recv, "setup_server_A")?;
    let s_s = recv_scalar(&mut stream, &mut recv)?;

    if let Some(pinned) = pinned_server_pub {
        if pinned.compress().to_bytes().ct_eq(&server_pub_bytes).unwrap_u8() == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "server raw public key mismatches pinned server_pub.bin",
            ));
        }
    } else {
        save_server_pub(&server_static_pub)?;
        println!("Client[SETUP/RPK]: TOFU pin accepted for server public key");
    }

    if !schnorr_verify_setup_server(
        &server_static_pub,
        &device_id,
        &device_static_pub,
        &client_nonce,
        &server_nonce,
        &a_s,
        &s_s,
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server setup proof invalid",
        ));
    }

    let (a, s) = schnorr_prove_setup(
        &x,
        &device_id,
        &device_static_pub,
        &server_static_pub,
        &client_nonce,
        &server_nonce,
    );

    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    stream.flush()?;

    let mut ack = [0u8; 1];
    recv_exact(&mut stream, &mut ack, &mut recv)?;
    if ack != [0x01] {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "enrollment failed (missing/invalid ack)",
        ));
    }

    save_server_pub(&server_static_pub)?;
    println!(
        "Client[SETUP/RPK]: enrollment OK; server_pub={} elapsed={:?} sent={} recv={}",
        hex::encode(server_pub_bytes),
        start.elapsed(),
        sent,
        recv
    );

    x.zeroize();
    Ok(())
}

/// Runs the client-side authenticated session handshake, including the X25519 tunnel, Schnorr proof exchange, session-key derivation, and key confirmation.
/// Step 1: require a pinned server key before attempting online authentication.
fn do_auth_v2_session(server_addr: &str, device_id: [u8; 32], mut x: Scalar, _continuity_expires_in: u64) -> std::io::Result<ClientSession> {
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

    send_all(&mut stream, &[MSG_AUTH_V2], &mut sent)?;

    let mut nonce_c = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_c);

    let mut eph_secret = random_scalar();
    let eph_pub = RISTRETTO_BASEPOINT_POINT * eph_secret;
    reject_identity(&eph_pub, "eph_c")?;
    let (a_c, s_c) = schnorr_prove_auth(&x, &device_id, &nonce_c, &eph_pub);

    let mut payload1 = Vec::with_capacity(160);
    payload1.extend_from_slice(&device_id);
    payload1.extend_from_slice(a_c.compress().as_bytes());
    payload1.extend_from_slice(&s_c.to_bytes());
    payload1.extend_from_slice(&nonce_c);
    payload1.extend_from_slice(eph_pub.compress().as_bytes());
    send_blob(&mut stream, &payload1, &mut sent)?;
    stream.flush()?;

    let pt2 = recv_encrypted_blob(&mut stream, &mut recv)?;
    if pt2.len() != 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid server payload length: {} (expected 128)", pt2.len()),
        ));
    }

    let mut s_pub_bytes = [0u8; 32];
    s_pub_bytes.copy_from_slice(&pt2[0..32]);
    let mut nonce_s = [0u8; 32];
    nonce_s.copy_from_slice(&pt2[32..64]);
    let mut eph_s_bytes = [0u8; 32];
    eph_s_bytes.copy_from_slice(&pt2[64..96]);
    let mut tag_s = [0u8; 32];
    tag_s.copy_from_slice(&pt2[96..128]);

    let server_static_pub = CompressedRistretto(s_pub_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server_static_pub"))?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let eph_s = CompressedRistretto(eph_s_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_s"))?;
    reject_identity(&eph_s, "eph_s")?;

    if pinned_server_pub.compress().to_bytes().ct_eq(&server_static_pub.compress().to_bytes()).unwrap_u8() == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Server pubkey mismatch — possible MITM"));
    }

    let mut session_key = derive_session_key(
        &eph_secret,
        &eph_s,
        &nonce_c,
        &nonce_s,
        &device_id,
        &server_static_pub,
        &eph_pub,
        &eph_s,
    );
    let th = kc_transcript_hash(&device_id, &a_c, &s_c, &nonce_c, &server_static_pub, &nonce_s, &eph_pub, &eph_s);
    let (k_finish, tx_key, rx_key) = derive_auth_keys(&session_key, &th);

    let expected_tag_s = hmac_tag(&k_finish, b"server finished", &th);
    if expected_tag_s.ct_eq(&tag_s).unwrap_u8() == 0 {
        x.zeroize();
        eph_secret.zeroize();
        session_key.zeroize();
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server finished tag mismatch"));
    }
    println!("Client[AUTH]: transcript-authenticated server finish OK");

    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());
    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());
    let nonce_tx_ctr = NonceCounter::new();
    let nonce_rx_ctr = NonceCounter::new();

    session_key.zeroize();
    x.zeroize();
    eph_secret.zeroize();

    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        sent,
        recv
    );

    Ok(ClientSession {
        stream,
        cipher_tx,
        cipher_rx,
        nonce_tx_ctr,
        nonce_rx_ctr,
        established_at: Instant::now(),
        sent,
        recv,
    })
}

fn do_auth_v2(server_addr: &str, device_id: [u8; 32], x: Scalar, _continuity_expires_in: u64) -> std::io::Result<()> {
    let mut sess = do_auth_v2_session(server_addr, device_id, x, 0)?;
    let goodbye = [MSG_GOODBYE];
    let _ = sess.send_encrypted(&goodbye);
    Ok(())
}

fn run_online_session(mut session: ClientSession, heartbeat_interval: Duration) -> std::io::Result<()> {
    let mut missed_heartbeats = 0u32;
    println!("Client[ONLINE]: session established");
    loop {
        if session.established_at.elapsed() >= SESSION_MAX_AGE {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "session expired"));
        }

        let hb = [MSG_HEARTBEAT];
        session.send_encrypted(&hb)?;
        println!("Client[HB]: sent");
        session.stream.set_read_timeout(Some(HEARTBEAT_ACK_TIMEOUT))?;
        match session.recv_encrypted() {
            Ok(msg) => {
                if msg.len() == 1 && msg[0] == MSG_HEARTBEAT_ACK {
                    println!("Client[HB]: ack");
                    missed_heartbeats = 0;
                } else if msg.len() == 1 && msg[0] == MSG_GOODBYE {
                    return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "server closed session"));
                } else {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unexpected online message"));
                }
            }
            Err(e) => {
                missed_heartbeats = missed_heartbeats.saturating_add(1);
                eprintln!("Client[HB]: missed {} ({})", missed_heartbeats, e);
                if missed_heartbeats >= MAX_MISSED_HEARTBEATS {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "heartbeat failure"));
                }
                continue;
            }
        }
        session.stream.set_read_timeout(Some(IO_TIMEOUT))?;
        thread::sleep(heartbeat_interval);
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
    fn serialize(&self) -> std::io::Result<Vec<u8>> {
        if self.audience.len() > MAX_OFFLINE_FIELD || self.scope.len() > MAX_OFFLINE_FIELD {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "offline proof field too long",
            ));
        }
        let mut out = Vec::with_capacity(1 + 32 + 32 + 8 + 8 + 8 + 2 + self.audience.len() + 2 + self.scope.len() + 32 + 32 + 32);
        out.push(self.version);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.device_pub);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&(self.audience.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.audience);
        out.extend_from_slice(&(self.scope.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.scope);
        out.extend_from_slice(&self.request_hash);
        out.extend_from_slice(&self.a);
        out.extend_from_slice(&self.s);
        Ok(out)
    }
}

#[derive(Clone, Debug)]
/// Stores continuity-tracking state that links one successful session to the next.
struct ContinuityState {
    version: u8,
    role: u8,
    identity: [u8; 32],
    pubkey: [u8; 32],
    continuity_counter: u64,
    reconnect_epoch: u64,
    last_peer_id: [u8; 32],
    last_checkpoint_hash: [u8; 32],
    state_hash: [u8; 32],
}

#[derive(Clone, Debug)]
/// Represents a continuity proof used to bind reconnects to prior state.
struct ContinuityProof {
    version: u8,
    role: u8,
    identity: [u8; 32],
    pubkey: [u8; 32],
    peer_id: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    continuity_counter: u64,
    reconnect_epoch: u64,
    prev_checkpoint_hash: [u8; 32],
    state_hash: [u8; 32],
    checkpoint_hash: [u8; 32],
    a: [u8; 32],
    s: [u8; 32],
}

/// Stores continuity-tracking state that links one successful session to the next.
impl ContinuityState {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(178);
        out.push(self.version);
        out.push(self.role);
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.continuity_counter.to_le_bytes());
        out.extend_from_slice(&self.reconnect_epoch.to_le_bytes());
        out.extend_from_slice(&self.last_peer_id);
        out.extend_from_slice(&self.last_checkpoint_hash);
        out.extend_from_slice(&self.state_hash);
        out
    }

    fn deserialize(buf: &[u8]) -> std::io::Result<Self> {
        if buf.len() != 178 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "continuity state wrong length"));
        }
        let mut off = 0usize;
        let version = buf[off]; off += 1;
        let role = buf[off]; off += 1;
        let mut identity = [0u8; 32]; identity.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut pubkey = [0u8; 32]; pubkey.copy_from_slice(&buf[off..off + 32]); off += 32;
        let continuity_counter = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
        let reconnect_epoch = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
        let mut last_peer_id = [0u8; 32]; last_peer_id.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut last_checkpoint_hash = [0u8; 32]; last_checkpoint_hash.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut state_hash = [0u8; 32]; state_hash.copy_from_slice(&buf[off..off + 32]);
        Ok(Self { version, role, identity, pubkey, continuity_counter, reconnect_epoch, last_peer_id, last_checkpoint_hash, state_hash })
    }
}

/// Represents a continuity proof used to bind reconnects to prior state.
impl ContinuityProof {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(290);
        out.push(self.version);
        out.push(self.role);
        out.extend_from_slice(&self.identity);
        out.extend_from_slice(&self.pubkey);
        out.extend_from_slice(&self.peer_id);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.continuity_counter.to_le_bytes());
        out.extend_from_slice(&self.reconnect_epoch.to_le_bytes());
        out.extend_from_slice(&self.prev_checkpoint_hash);
        out.extend_from_slice(&self.state_hash);
        out.extend_from_slice(&self.checkpoint_hash);
        out.extend_from_slice(&self.a);
        out.extend_from_slice(&self.s);
        out
    }

    fn deserialize(buf: &[u8]) -> std::io::Result<Self> {
        if buf.len() != 290 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "continuity proof wrong length"));
        }
        let mut off = 0usize;
        let version = buf[off]; off += 1;
        let role = buf[off]; off += 1;
        let mut identity = [0u8; 32]; identity.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut pubkey = [0u8; 32]; pubkey.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut peer_id = [0u8; 32]; peer_id.copy_from_slice(&buf[off..off + 32]); off += 32;
        let issued_at = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
        let expires_at = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
        let continuity_counter = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
        let reconnect_epoch = u64::from_le_bytes(buf[off..off + 8].try_into().unwrap()); off += 8;
        let mut prev_checkpoint_hash = [0u8; 32]; prev_checkpoint_hash.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut state_hash = [0u8; 32]; state_hash.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut checkpoint_hash = [0u8; 32]; checkpoint_hash.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut a = [0u8; 32]; a.copy_from_slice(&buf[off..off + 32]); off += 32;
        let mut s = [0u8; 32]; s.copy_from_slice(&buf[off..off + 32]);
        Ok(Self { version, role, identity, pubkey, peer_id, issued_at, expires_at, continuity_counter, reconnect_epoch, prev_checkpoint_hash, state_hash, checkpoint_hash, a, s })
    }
}

/// Hashes the client continuity state that is chained across reconnects.
fn hash_client_continuity_state(
    identity: &[u8; 32],
    pubkey: &[u8; 32],
    pinned_server_pub: &[u8; 32],
    continuity_counter: u64,
    reconnect_epoch: u64,
) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"client-state-v1");
    sha2::Digest::update(&mut h, identity);
    sha2::Digest::update(&mut h, pubkey);
    sha2::Digest::update(&mut h, pinned_server_pub);
    sha2::Digest::update(&mut h, &continuity_counter.to_le_bytes());
    sha2::Digest::update(&mut h, &reconnect_epoch.to_le_bytes());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Hashes the server-side tracking state associated with a client continuity chain.
fn hash_server_track_state(peer_id: &[u8; 32], highest_counter: u64, reconnect_epoch: u64, checkpoint_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"server-track-v1");
    sha2::Digest::update(&mut h, peer_id);
    sha2::Digest::update(&mut h, &highest_counter.to_le_bytes());
    sha2::Digest::update(&mut h, &reconnect_epoch.to_le_bytes());
    sha2::Digest::update(&mut h, checkpoint_hash);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Derives the next continuity checkpoint hash from the previous checkpoint and current state.
fn next_checkpoint_hash(prev_checkpoint_hash: &[u8; 32], state_hash: &[u8; 32], continuity_counter: u64, reconnect_epoch: u64, peer_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"continuity-checkpoint-v1");
    sha2::Digest::update(&mut h, prev_checkpoint_hash);
    sha2::Digest::update(&mut h, state_hash);
    sha2::Digest::update(&mut h, &continuity_counter.to_le_bytes());
    sha2::Digest::update(&mut h, &reconnect_epoch.to_le_bytes());
    sha2::Digest::update(&mut h, peer_id);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Builds the Schnorr-style challenge scalar used for continuity proofs.
fn continuity_challenge_scalar(domain: &[u8], role: u8, identity: &[u8; 32], pubkey: &RistrettoPoint, peer_id: &[u8; 32], issued_at: u64, expires_at: u64, continuity_counter: u64, reconnect_epoch: u64, prev_checkpoint_hash: &[u8; 32], state_hash: &[u8; 32], checkpoint_hash: &[u8; 32], a: &RistrettoPoint) -> Scalar {
    transcript_challenge_scalar(
        domain,
        &[
            (b"role", TranscriptValue::U8(role)),
            (b"identity", TranscriptValue::Bytes(identity)),
            (b"pubkey", TranscriptValue::Point(pubkey)),
            (b"peer_id", TranscriptValue::Bytes(peer_id)),
            (b"issued_at", TranscriptValue::U64(issued_at)),
            (b"expires_at", TranscriptValue::U64(expires_at)),
            (b"continuity_counter", TranscriptValue::U64(continuity_counter)),
            (b"reconnect_epoch", TranscriptValue::U64(reconnect_epoch)),
            (b"prev_checkpoint_hash", TranscriptValue::Bytes(prev_checkpoint_hash)),
            (b"state_hash", TranscriptValue::Bytes(state_hash)),
            (b"checkpoint_hash", TranscriptValue::Bytes(checkpoint_hash)),
            (b"a", TranscriptValue::Point(a)),
        ],
    )
}

/// Derives a stable server peer identifier from the pinned server public key.
fn server_peer_id_from_pinned_pub(p: &RistrettoPoint) -> [u8; 32] {
    let mut h = Sha256::new();
    sha2::Digest::update(&mut h, b"server-id-v1");
    sha2::Digest::update(&mut h, p.compress().as_bytes());
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Loads the client continuity state from disk or initializes a fresh chain.
fn load_or_init_client_continuity_state(device_id: &[u8; 32], x: &Scalar, pinned_server_pub: &RistrettoPoint) -> std::io::Result<ContinuityState> {
    let pubkey = (RISTRETTO_BASEPOINT_POINT * x).compress().to_bytes();
    let peer_id = server_peer_id_from_pinned_pub(pinned_server_pub);
    if Path::new(CLIENT_CONTINUITY_FILE).exists() {
        verify_private_file_permissions(CLIENT_CONTINUITY_FILE)?;
        let st = ContinuityState::deserialize(&fs::read(CLIENT_CONTINUITY_FILE)?)?;
        if st.identity != *device_id || st.pubkey != pubkey {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "client continuity state mismatch"));
        }
        return Ok(st);
    }
    let state_hash = hash_client_continuity_state(device_id, &pubkey, pinned_server_pub.compress().as_bytes(), 0, 0);
    let st = ContinuityState {
        version: 1,
        role: 1,
        identity: *device_id,
        pubkey,
        continuity_counter: 0,
        reconnect_epoch: 0,
        last_peer_id: peer_id,
        last_checkpoint_hash: [0u8; 32],
        state_hash,
    };
    write_private_file_atomic(CLIENT_CONTINUITY_FILE, &st.serialize())?;
    Ok(st)
}

/// Persists the client continuity state to disk.
fn save_client_continuity_state(st: &ContinuityState) -> std::io::Result<()> {
    write_private_file_atomic(CLIENT_CONTINUITY_FILE, &st.serialize())
}

/// Loads the last server continuity track recorded by the client.
fn load_server_track() -> std::io::Result<Option<ContinuityState>> {
    if !Path::new(SERVER_CONTINUITY_TRACK_FILE).exists() {
        return Ok(None);
    }
    verify_private_file_permissions(SERVER_CONTINUITY_TRACK_FILE)?;
    Ok(Some(ContinuityState::deserialize(&fs::read(SERVER_CONTINUITY_TRACK_FILE)?)?))
}

/// Persists the server continuity track recorded by the client.
fn save_server_track(st: &ContinuityState) -> std::io::Result<()> {
    write_private_file_atomic(SERVER_CONTINUITY_TRACK_FILE, &st.serialize())
}

/// Builds a candidate client continuity proof without persisting the new local state yet.
fn prepare_client_continuity_proof(device_id: [u8; 32], x: &Scalar, expires_in: u64) -> std::io::Result<(ContinuityProof, ContinuityState)> {
    if expires_in == 0 || expires_in > 300 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--continuity-expires-in must be between 1 and 300"));
    }
    let pinned_server_pub = load_server_pub()?.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no pinned server pub for continuity"))?;
    let current = load_or_init_client_continuity_state(&device_id, x, &pinned_server_pub)?;
    let mut pending = current.clone();
    pending.continuity_counter = pending.continuity_counter.checked_add(1).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "continuity counter exhausted"))?;
    pending.reconnect_epoch = pending.reconnect_epoch.checked_add(1).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "reconnect epoch exhausted"))?;
    pending.state_hash = hash_client_continuity_state(&pending.identity, &pending.pubkey, pinned_server_pub.compress().as_bytes(), pending.continuity_counter, pending.reconnect_epoch);

    let pubkey_point = RISTRETTO_BASEPOINT_POINT * x;
    let checkpoint_hash = next_checkpoint_hash(&current.last_checkpoint_hash, &pending.state_hash, pending.continuity_counter, pending.reconnect_epoch, &pending.last_peer_id);
    let issued_at = unix_time_now()?;
    let expires_at = issued_at.checked_add(expires_in).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "expires_at overflow"))?;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = continuity_challenge_scalar(T_CLIENT_CONT, pending.role, &pending.identity, &pubkey_point, &pending.last_peer_id, issued_at, expires_at, pending.continuity_counter, pending.reconnect_epoch, &current.last_checkpoint_hash, &pending.state_hash, &checkpoint_hash, &a);
    let s = r + c * x;
    let proof = ContinuityProof {
        version: 1,
        role: pending.role,
        identity: pending.identity,
        pubkey: pending.pubkey,
        peer_id: pending.last_peer_id,
        issued_at,
        expires_at,
        continuity_counter: pending.continuity_counter,
        reconnect_epoch: pending.reconnect_epoch,
        prev_checkpoint_hash: current.last_checkpoint_hash,
        state_hash: pending.state_hash,
        checkpoint_hash,
        a: a.compress().to_bytes(),
        s: s.to_bytes(),
    };
    pending.last_checkpoint_hash = checkpoint_hash;
    Ok((proof, pending))
}

/// Builds a client continuity proof and persists the new local state.
fn build_client_continuity_proof(device_id: [u8; 32], x: &Scalar, expires_in: u64) -> std::io::Result<(ContinuityProof, ContinuityState)> {
    let (proof, pending) = prepare_client_continuity_proof(device_id, x, expires_in)?;
    save_client_continuity_state(&pending)?;
    Ok((proof, pending))
}

/// Verifies a server continuity proof and optionally persists the updated tracked state.
fn verify_server_continuity_proof(proof: &ContinuityProof, persist: bool) -> std::io::Result<ContinuityState> {
    let pinned_server_pub = load_server_pub()?.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no pinned server pub for continuity verification"))?;
    let expected_identity = server_peer_id_from_pinned_pub(&pinned_server_pub);
    if proof.role != 2 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "proof is not a server continuity proof"));
    }
    if proof.identity != expected_identity {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity identity mismatch"));
    }
    if proof.pubkey.ct_eq(pinned_server_pub.compress().as_bytes()).unwrap_u8() == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity pubkey mismatch"));
    }
    let (device_id, _x) = load_device_creds_from_root()?;
    if proof.peer_id != device_id {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity peer binding mismatch"));
    }
    let mut track = load_server_track()?.unwrap_or(ContinuityState {
        version: 1, role: 2, identity: expected_identity, pubkey: pinned_server_pub.compress().to_bytes(),
        continuity_counter: 0, reconnect_epoch: 0, last_peer_id: device_id, last_checkpoint_hash: [0u8; 32],
        state_hash: hash_server_track_state(&device_id, 0, 0, &[0u8; 32]),
    });
    let now = unix_time_now()?;
    if proof.issued_at >= proof.expires_at || now < proof.issued_at || now > proof.expires_at {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity proof expired or not yet valid"));
    }
    if proof.continuity_counter <= track.continuity_counter {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity replay detected"));
    }
    if proof.prev_checkpoint_hash != track.last_checkpoint_hash {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity checkpoint chain mismatch"));
    }
    let recomputed_checkpoint = next_checkpoint_hash(&proof.prev_checkpoint_hash, &proof.state_hash, proof.continuity_counter, proof.reconnect_epoch, &proof.peer_id);
    if recomputed_checkpoint != proof.checkpoint_hash {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity checkpoint hash mismatch"));
    }
    let a = CompressedRistretto(proof.a).decompress().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "continuity A invalid"))?;
    reject_identity(&a, "server continuity A")?;
    let s: Scalar = Option::<Scalar>::from(Scalar::from_canonical_bytes(proof.s)).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "continuity s non-canonical"))?;
    let c = continuity_challenge_scalar(T_SERVER_CONT, proof.role, &proof.identity, &pinned_server_pub, &proof.peer_id, proof.issued_at, proof.expires_at, proof.continuity_counter, proof.reconnect_epoch, &proof.prev_checkpoint_hash, &proof.state_hash, &proof.checkpoint_hash, &a);
    if RISTRETTO_BASEPOINT_POINT * s != a + (pinned_server_pub * c) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server continuity Schnorr proof invalid"));
    }
    track.continuity_counter = proof.continuity_counter;
    track.reconnect_epoch = proof.reconnect_epoch;
    track.last_checkpoint_hash = proof.checkpoint_hash;
    track.state_hash = hash_server_track_state(&proof.peer_id, track.continuity_counter, track.reconnect_epoch, &track.last_checkpoint_hash);
    if persist {
        save_server_track(&track)?;
    }
    Ok(track)
}

/// Parses and verifies a server continuity proof file using the pinned server identity.
fn verify_server_continuity_proof_from_file(path: &str) -> std::io::Result<()> {
    let proof = ContinuityProof::deserialize(&fs::read(path)?)?;
    let track = verify_server_continuity_proof(&proof, true)?;
    println!("Client[CONTINUITY]: verified returning server continuity proof file={} counter={} reconnect_epoch={}", path, track.continuity_counter, track.reconnect_epoch);
    Ok(())
}

/// Creates a client continuity proof file from the current local state.
fn do_make_client_continuity_proof(output_path: &str, device_id: [u8; 32], mut x: Scalar, expires_in: u64) -> std::io::Result<()> {
    let (proof, st) = build_client_continuity_proof(device_id, &x, expires_in)?;
    write_private_file_atomic(output_path, &proof.serialize())?;
    println!("Client[CONTINUITY]: wrote client continuity proof to {} counter={} reconnect_epoch={} checkpoint_hash={}", output_path, st.continuity_counter, st.reconnect_epoch, hex::encode(proof.checkpoint_hash));
    x.zeroize();
    Ok(())
}

/// Returns the current Unix timestamp in seconds.
fn unix_time_now() -> std::io::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("system time error: {e}")))?
        .as_secs())
}

/// Loads, increments, and persists the client offline-proof counter.
fn load_and_increment_offline_counter() -> std::io::Result<u64> {
    let current = if Path::new(OFFLINE_COUNTER_FILE).exists() {
        verify_private_file_permissions(OFFLINE_COUNTER_FILE)?;
        let data = fs::read(OFFLINE_COUNTER_FILE)?;
        if data.len() != 8 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "offline_counter.bin wrong length",
            ));
        }
        u64::from_le_bytes(data[..8].try_into().unwrap())
    } else {
        0
    };
    let next = current.checked_add(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "offline counter exhausted")
    })?;
    write_private_file_atomic(OFFLINE_COUNTER_FILE, &next.to_le_bytes())?;
    Ok(next)
}

/// Parses a 32-byte value from a 64-character hexadecimal string.
fn parse_hash32_hex(s: &str) -> std::io::Result<[u8; 32]> {
    let raw = hex::decode(s).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "request hash must be valid hex")
    })?;
    if raw.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "request hash must be exactly 32 bytes",
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// Computes the SHA-256 digest of a file on disk.
fn sha256_file(path: &str) -> std::io::Result<[u8; 32]> {
    let data = fs::read(path)?;
    let digest = Sha256::digest(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
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

/// Creates a signed offline authorization proof bound to the target audience, scope, request hash, and expiry.
fn build_offline_proof(
    device_id: [u8; 32],
    x: &Scalar,
    audience: &str,
    scope: &str,
    expires_in: u64,
    request_hash: [u8; 32],
) -> std::io::Result<OfflineProof> {
    if audience.is_empty() || audience.len() > MAX_OFFLINE_FIELD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "audience must be 1..=256 bytes",
        ));
    }
    if scope.is_empty() || scope.len() > MAX_OFFLINE_FIELD {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "scope must be 1..=256 bytes",
        ));
    }
    if expires_in == 0 || expires_in > 300 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "--offline-expires-in must be between 1 and 300 seconds",
        ));
    }

    let issued_at = unix_time_now()?;
    let expires_at = issued_at.checked_add(expires_in).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "expiration overflow")
    })?;
    let counter = load_and_increment_offline_counter()?;
    let device_pub = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&device_pub, "offline device_pub")?;

    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;
    let c = offline_challenge_scalar(
        &device_id,
        &device_pub,
        audience.as_bytes(),
        scope.as_bytes(),
        issued_at,
        expires_at,
        counter,
        &request_hash,
        &a,
    );
    let s = r + c * x;

    Ok(OfflineProof {
        version: 1,
        device_id,
        device_pub: device_pub.compress().to_bytes(),
        issued_at,
        expires_at,
        counter,
        audience: audience.as_bytes().to_vec(),
        scope: scope.as_bytes().to_vec(),
        request_hash,
        a: a.compress().to_bytes(),
        s: s.to_bytes(),
    })
}

/// Loads local credentials and writes a serialized offline proof file.
fn do_make_offline_proof(
    output_path: &str,
    device_id: [u8; 32],
    mut x: Scalar,
    audience: &str,
    scope: &str,
    expires_in: u64,
    request_hash: [u8; 32],
) -> std::io::Result<()> {
    if Path::new(DEVICE_ROOT_FILE).exists() { verify_private_file_permissions(DEVICE_ROOT_FILE)?; }
    let proof = build_offline_proof(device_id, &x, audience, scope, expires_in, request_hash)?;
    let serialized = proof.serialize()?;
    write_private_file_atomic(output_path, &serialized)?;
    println!(
        "Client[OFFLINE]: wrote offline proof to {} for audience='{}' scope='{}' counter={} issued_at={} expires_at={} request_hash={}",
        output_path,
        String::from_utf8_lossy(&proof.audience),
        String::from_utf8_lossy(&proof.scope),
        proof.counter,
        proof.issued_at,
        proof.expires_at,
        hex::encode(proof.request_hash)
    );
    x.zeroize();
    Ok(())
}

/// Prints the supported command-line arguments for the binary.
fn usage(prog: &str) {
    eprintln!(
        "Usage:
  {0} --server 127.0.0.1:4000 --setup [--pairing-token TOKEN] [--allow-tofu-setup (debug-only)]
  {0} --server 127.0.0.1:4000
  {0} --server 127.0.0.1:4000 --daemon [--daemon-interval-secs N] [--continuity-expires-in <1..300>]
  {0} --pin-server-pub <hex>
  {0} --print-device-identity
  {0} --make-offline-proof <file> --audience <name> --scope <scope> [--offline-expires-in <1..300>] [--request-hash <hex>|--request-file <path>]
  {0} --make-client-continuity-proof <file> [--continuity-expires-in <1..300>]
  {0} --verify-server-continuity-proof <file>",
        prog
    );
}

fn print_device_identity() -> std::io::Result<()> {
    let (device_id, x) = load_device_creds_from_root()?;
    let device_pub = RISTRETTO_BASEPOINT_POINT * x;
    println!("{} {}", hex::encode(device_id), hex::encode(device_pub.compress().to_bytes()));
    Ok(())
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

fn run_client_daemon(server_addr: &str, device_id: [u8; 32], heartbeat_interval: Duration, continuity_expires_in: u64) -> std::io::Result<()> {
    let mut backoff = ReconnectBackoff::new(DAEMON_BASE_BACKOFF, DAEMON_MAX_BACKOFF);
    loop {
        let (_, x) = load_device_creds_from_root()?;
        match do_auth_v2_session(server_addr, device_id, x, continuity_expires_in) {
            Ok(session) => {
                backoff.reset(DAEMON_BASE_BACKOFF);
                match run_online_session(session, heartbeat_interval) {
                    Ok(()) => eprintln!("Client[DAEMON]: session closed cleanly"),
                    Err(e) => eprintln!("Client[DAEMON]: session lost: {}", e),
                }
            }
            Err(e) => {
                eprintln!("Client[DAEMON]: connect/auth failed: {}", e);
            }
        }
        let delay = backoff.next_delay();
        eprintln!("Client[DAEMON]: reconnecting after {:?}", delay);
        thread::sleep(delay);
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let prog = args.get(0).cloned().unwrap_or_else(|| "client".to_string());
    let mut server_addr = "127.0.0.1:4000".to_string();
    let mut do_setup_flag = false;
    let mut pairing_token: Option<String> = None;
    let mut print_identity = false;
    let mut allow_tofu_setup = false;
    let mut offline_output: Option<String> = None;
    let mut offline_audience: Option<String> = None;
    let mut offline_scope: Option<String> = None;
    let mut offline_expires_in: u64 = 300;
    let mut offline_request_hash: Option<[u8; 32]> = None;
    let mut continuity_output: Option<String> = None;
    let mut verify_server_continuity_path: Option<String> = None;
    let mut continuity_expires_in: u64 = DEFAULT_CONTINUITY_EXPIRES_IN;
    let mut daemon_cfg = ClientDaemonConfig::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--server missing value")); }
                server_addr = args[i + 1].clone();
                i += 2;
            }
            "--setup" => { do_setup_flag = true; i += 1; }
            "--daemon" => { daemon_cfg.enabled = true; i += 1; }
            "--daemon-interval-secs" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--daemon-interval-secs missing value")); }
                let secs: u64 = args[i + 1].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --daemon-interval-secs"))?;
                daemon_cfg.success_sleep = Duration::from_secs(secs.max(1));
                i += 2;
            }
            "--print-device-identity" => { print_identity = true; i += 1; }
            "--allow-tofu-setup" => {
                if !cfg!(debug_assertions) {
                    return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "--allow-tofu-setup is disabled in production builds; pin the server key out-of-band instead"));
                }
                allow_tofu_setup = true;
                i += 1;
            }
            "--pairing-token" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pairing-token missing value")); }
                pairing_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--make-offline-proof" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof missing value")); }
                offline_output = Some(args[i + 1].clone());
                i += 2;
            }
            "--make-client-continuity-proof" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-client-continuity-proof missing value")); }
                continuity_output = Some(args[i + 1].clone());
                i += 2;
            }
            "--verify-server-continuity-proof" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--verify-server-continuity-proof missing value")); }
                verify_server_continuity_path = Some(args[i + 1].clone());
                i += 2;
            }
            "--audience" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--audience missing value")); }
                offline_audience = Some(args[i + 1].clone());
                i += 2;
            }
            "--scope" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--scope missing value")); }
                offline_scope = Some(args[i + 1].clone());
                i += 2;
            }
            "--offline-expires-in" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--offline-expires-in missing value")); }
                offline_expires_in = args[i + 1].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --offline-expires-in"))?;
                i += 2;
            }
            "--continuity-expires-in" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--continuity-expires-in missing value")); }
                continuity_expires_in = args[i + 1].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --continuity-expires-in"))?;
                daemon_cfg.continuity_expires_in = continuity_expires_in;
                i += 2;
            }
            "--request-hash" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--request-hash missing value")); }
                offline_request_hash = Some(parse_hash32_hex(&args[i + 1])?);
                i += 2;
            }
            "--request-file" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--request-file missing value")); }
                offline_request_hash = Some(sha256_file(&args[i + 1])?);
                i += 2;
            }
            "--pin-server-pub" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pin-server-pub missing value")); }
                let decoded = hex::decode(&args[i + 1]).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid hex for pinned key"))?;
                if decoded.len() != 32 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "pinned key must be 32 bytes")); }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&decoded);
                let p = CompressedRistretto(key_bytes).decompress().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "pinned key is not a valid Ristretto point"))?;
                reject_identity(&p, "pinned server pub")?;
                save_server_pub(&p)?;
                println!("Client: Successfully pinned server pubkey out-of-band.");
                return Ok(());
            }
            _ => {
                usage(&prog);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("unknown argument: {}", args[i])));
            }
        }
    }

    if print_identity { return print_device_identity(); }
    if let Some(path) = verify_server_continuity_path.as_deref() { return verify_server_continuity_proof_from_file(path); }

    if let Some(output_path) = offline_output.as_deref() {
        let audience = offline_audience.as_deref().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof requires --audience"))?;
        let scope = offline_scope.as_deref().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof requires --scope"))?;
        let request_hash = offline_request_hash.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof requires --request-hash or --request-file"))?;
        let (device_id, x) = load_device_creds_from_root()?;
        return do_make_offline_proof(output_path, device_id, x, audience, scope, offline_expires_in, request_hash);
    }

    if let Some(output_path) = continuity_output.as_deref() {
        let (device_id, x) = load_device_creds_from_root()?;
        return do_make_client_continuity_proof(output_path, device_id, x, continuity_expires_in);
    }

    if Path::new(DEVICE_ROOT_FILE).exists() { verify_private_file_permissions(DEVICE_ROOT_FILE)?; }
    if Path::new(SERVER_PUB_FILE).exists() { verify_private_file_permissions(SERVER_PUB_FILE)?; }

    if !creds_exist() && !do_setup_flag {
        eprintln!("Client: device root missing ({}). Run --setup to enroll.", DEVICE_ROOT_FILE);
        return Ok(());
    }

    let had_root_before = creds_exist();
    let (device_id, x) = load_device_creds_from_root()?;

    if do_setup_flag {
        println!("Client[SETUP/RPK]: {}", if had_root_before { "Using existing device root for setup (idempotent)." } else { "No device root found; generating NEW device root." });
        do_setup(&server_addr, device_id, x, pairing_token.as_deref(), allow_tofu_setup)
    } else if daemon_cfg.enabled {
        run_client_daemon(&server_addr, device_id, daemon_cfg.success_sleep, daemon_cfg.continuity_expires_in)
    } else {
        do_auth_v2(&server_addr, device_id, x, continuity_expires_in)
    }
}
