use std::env;
use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::net::TcpStream;
use std::path::Path;
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
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const NONCE_LEN: usize = 32;
const SETUP_CHALLENGE_LEN: usize = 16;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03;
const MSG_GOODBYE: u8 = 0x15;

const DEVICE_ROOT_FILE: &str = "/var/lib/iot-auth/client/device_root.bin";
const SERVER_PUB_FILE: &str = "/var/lib/iot-auth/client/server_pub.bin";
const OFFLINE_COUNTER_FILE: &str = "/var/lib/iot-auth/client/offline_counter.bin";
const ROLE_CRED_FILE: &str = "/var/lib/iot-auth/client/role_cred.bin";

const T_SETUP: &[u8] = b"setup_client_schnorr_v1";
const T_SETUP_SERVER: &[u8] = b"setup_server_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";
const T_OFFLINE: &[u8] = b"offline_schnorr_v1";
const T_ATTR_ROLE: &[u8] = b"client_attr_role_v1";

const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ENCRYPTED_PAYLOAD: usize = 4096;
const MAX_OFFLINE_FIELD: usize = 256;


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


#[derive(Clone)]
struct RoleCredential {
    role_code: u64,
    role_scalar: Scalar,
    blind: Scalar,
    commitment: RistrettoPoint,
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

fn encode_role(role_code: u64) -> Scalar {
    Scalar::from(role_code)
}

fn make_role_commitment(role_scalar: &Scalar, blind: &Scalar) -> RistrettoPoint {
    let h = attr_h();
    (RISTRETTO_BASEPOINT_POINT * role_scalar) + (h * blind)
}

fn prove_role_commitment_opening(
    role_scalar: &Scalar,
    blind: &Scalar,
    commitment: &RistrettoPoint,
    device_id: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
) -> (RistrettoPoint, Scalar, Scalar) {
    let h = attr_h();

    let u = random_scalar();
    let v = random_scalar();
    let a = (RISTRETTO_BASEPOINT_POINT * u) + (h * v);

    let c = transcript_challenge_scalar(
        T_ATTR_ROLE,
        &[
            (b"device_id", TranscriptValue::Bytes(device_id)),
            (b"commitment", TranscriptValue::Point(commitment)),
            (b"a", TranscriptValue::Point(&a)),
            (b"nonce_c", TranscriptValue::Bytes(nonce_c)),
            (b"eph_c", TranscriptValue::Point(eph_c)),
        ],
    );

    let s_attr = u + c * role_scalar;
    let s_blind = v + c * blind;
    (a, s_attr, s_blind)
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

fn save_role_credential(cred: &RoleCredential) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(8 + 32 + 32);
    out.extend_from_slice(&cred.role_code.to_le_bytes());
    out.extend_from_slice(&cred.blind.to_bytes());
    out.extend_from_slice(cred.commitment.compress().as_bytes());
    write_private_file_atomic(ROLE_CRED_FILE, &out)
}

fn load_role_credential() -> std::io::Result<RoleCredential> {
    verify_private_file_permissions(ROLE_CRED_FILE)?;
    let data = fs::read(ROLE_CRED_FILE)?;
    if data.len() != 72 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "role_cred.bin wrong length",
        ));
    }

    let mut role_code_bytes = [0u8; 8];
    role_code_bytes.copy_from_slice(&data[0..8]);
    let role_code = u64::from_le_bytes(role_code_bytes);
    let role_scalar = encode_role(role_code);

    let mut blind_bytes = [0u8; 32];
    blind_bytes.copy_from_slice(&data[8..40]);
    let blind = Option::from(Scalar::from_canonical_bytes(blind_bytes))
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "role blind not canonical"))?;

    let mut commitment_bytes = [0u8; 32];
    commitment_bytes.copy_from_slice(&data[40..72]);
    let commitment = CompressedRistretto(commitment_bytes)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "role commitment invalid"))?;
    reject_identity(&commitment, "role commitment")?;

    let expected = make_role_commitment(&role_scalar, &blind);
    if expected.compress().to_bytes() != commitment.compress().to_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "role credential commitment mismatch",
        ));
    }

    Ok(RoleCredential {
        role_code,
        role_scalar,
        blind,
        commitment,
    })
}

fn load_or_create_role_credential() -> std::io::Result<RoleCredential> {
    if Path::new(ROLE_CRED_FILE).exists() {
        return load_role_credential();
    }

    let role_code = 1u64;
    let role_scalar = encode_role(role_code);
    let blind = random_scalar();
    let commitment = make_role_commitment(&role_scalar, &blind);
    let cred = RoleCredential {
        role_code,
        role_scalar,
        blind,
        commitment,
    };
    save_role_credential(&cred)?;
    Ok(cred)
}

/// Creates the client setup proof used during raw-public-key enrollment.
fn schnorr_prove_setup(
    x: &Scalar,
    device_id: &[u8; 32],
    device_pub: &RistrettoPoint,
    server_static_pub: &RistrettoPoint,
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
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
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
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
    setup_challenge: &[u8; SETUP_CHALLENGE_LEN],
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
            (b"setup_challenge", TranscriptValue::Bytes(setup_challenge)),
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
    let role_cred = load_or_create_role_credential()?;

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
    println!("Client[SETUP]: Connected to {}", server_addr);

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
    send_all(&mut stream, role_cred.commitment.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;
    let mut setup_challenge = [0u8; SETUP_CHALLENGE_LEN];
    recv_exact(&mut stream, &mut setup_challenge, &mut recv)?;
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
        println!("Client[SETUP]: TOFU pin accepted for server public key");
    }

    if !schnorr_verify_setup_server(
        &server_static_pub,
        &device_id,
        &device_static_pub,
        &client_nonce,
        &server_nonce,
        &setup_challenge,
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
        &setup_challenge,
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
    println!("Client[SETUP]: Enrollment OK");
    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        start.elapsed(),
        sent,
        recv
    );
    println!(
        "Client[SETUP]: Server public key pinned: {}",
        hex::encode(server_pub_bytes)
    );

    x.zeroize();
    Ok(())
}

/// Runs the client-side authenticated session handshake, including the X25519 tunnel, Schnorr proof exchange, session-key derivation, and key confirmation.
/// Step 1: require a pinned server key before attempting online authentication.
fn do_auth_v2_session(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
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
    let role_cred = load_or_create_role_credential()?;
    let (attr_a, attr_s_attr, attr_s_blind) = prove_role_commitment_opening(
        &role_cred.role_scalar,
        &role_cred.blind,
        &role_cred.commitment,
        &device_id,
        &nonce_c,
        &eph_pub,
    );

    let mut payload1 = Vec::with_capacity(288);
    payload1.extend_from_slice(&device_id);
    payload1.extend_from_slice(a_c.compress().as_bytes());
    payload1.extend_from_slice(&s_c.to_bytes());
    payload1.extend_from_slice(&nonce_c);
    payload1.extend_from_slice(eph_pub.compress().as_bytes());
    payload1.extend_from_slice(role_cred.commitment.compress().as_bytes());
    payload1.extend_from_slice(attr_a.compress().as_bytes());
    payload1.extend_from_slice(&attr_s_attr.to_bytes());
    payload1.extend_from_slice(&attr_s_blind.to_bytes());

    let ct1 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), payload1.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    send_blob(&mut stream, &ct1, &mut sent)?;
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
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server_static_pub"))?;
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

    if pinned_server_pub.compress().to_bytes().ct_eq(&server_static_pub.compress().to_bytes()).unwrap_u8() == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Server pubkey mismatch — possible MITM"));
    }

    if !schnorr_verify_server(&server_static_pub, &a_s, &s_s, &nonce_s, &eph_s) {
        eprintln!("Client[AUTH]: Server Schnorr proof FAILED");
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server Schnorr proof invalid"));
    }
    println!("Client[AUTH]: Server Schnorr proof OK");

    let mut session_key = derive_session_key(&eph_secret, &eph_s, &nonce_c, &nonce_s, &device_id, &eph_pub, &eph_s, &x25519_shared_bytes);
    let th = kc_transcript_hash(&device_id, &a_c, &s_c, &nonce_c, &eph_pub, &server_static_pub, &a_s, &s_s, &nonce_s, &eph_s);
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);

    let expected_tag_s = hmac_tag(&k_s2c, b"server finished", &th);

    if expected_tag_s.ct_eq(&tag_s).unwrap_u8() == 0 {
        x.zeroize();
        eph_secret.zeroize();
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "server finished tag mismatch"));
    }
    println!("Client[AUTH]: Key confirmation (server finished) OK");

    let tag_c = hmac_tag(&k_c2s, b"client finished", &th);

    let ct3 = cipher_tx
        .encrypt(&nonce_tx_ctr.next(), tag_c.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    send_blob(&mut stream, &ct3, &mut sent)?;
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

    let _ = stream.shutdown(std::net::Shutdown::Both);
    Ok(())
}

fn do_auth_v2(server_addr: &str, device_id: [u8; 32], x: Scalar) -> std::io::Result<()> {
    do_auth_v2_session(server_addr, device_id, x)
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
  {0} --pin-server-pub <hex>
  {0} --print-device-identity
  {0} --make-offline-proof <file> --audience <name> --scope <scope> [--offline-expires-in <1..300>] [--request-hash <hex>|--request-file <path>]",
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

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--server" => {
                if i + 1 >= args.len() { usage(&prog); return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--server missing value")); }
                server_addr = args[i + 1].clone();
                i += 2;
            }
            "--setup" => { do_setup_flag = true; i += 1; }            "--print-device-identity" => { print_identity = true; i += 1; }
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
    if let Some(output_path) = offline_output.as_deref() {
        let audience = offline_audience.as_deref().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof requires --audience"))?;
        let scope = offline_scope.as_deref().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof requires --scope"))?;
        let request_hash = offline_request_hash.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "--make-offline-proof requires --request-hash or --request-file"))?;
        let (device_id, x) = load_device_creds_from_root()?;
        return do_make_offline_proof(output_path, device_id, x, audience, scope, offline_expires_in, request_hash);
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
        println!("Client[SETUP]: {}", if had_root_before { "Using existing device root for setup (idempotent)." } else { "No device root found; generating NEW device root." });
        do_setup(&server_addr, device_id, x, pairing_token.as_deref(), allow_tofu_setup)
    } else {
        do_auth_v2(&server_addr, device_id, x)
    }
}
