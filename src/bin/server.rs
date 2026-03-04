// ==============================
// server.rs (V2: Zero Privacy + TOFU Pinning & Key Confirmation)
// ==============================
//
// Goals:
//   1) Let clients learn/pin server identity during SETUP by sending server_static_pub.
//   2) Mutual auth: server proves possession of its static secret during AUTH.
//   3) Zero Privacy: Hide identity via ECDHE (X25519) + ChaCha20Poly1305 tunnel during AUTH.
//   4) Replay protection: persistent nonce tracking (dropped time-based TTL for DoS fix).
//   5) Key confirmation MACs: server sends tag_s, client replies tag_c over the secure tunnel.
//
// Dependencies (Cargo.toml):
//   curve25519-dalek = "4"
//   x25519-dalek = "2.0"
//   chacha20poly1305 = "0.10"
//   blake2 = "0.10"
//   rand = "0.8"
//   sha2 = "0.10"
//   hkdf = "0.12"
//   hmac = "0.12"
//   hex = "0.4"
//   zeroize = "1"
//

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::io::{Read, Write};
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
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03; // Bumped to 0x03 for encrypted tunnel

const REGISTRY_BIN: &str = "registry.bin";
const REGISTRY_BAK: &str = "registry.bak";
const SERVER_SK_FILE: &str = "server_sk.bin";

// Transcript domains (versioned; must match client and C if interop)
const T_SETUP: &[u8] = b"setup_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";

// IO hardening
const IO_TIMEOUT: Duration = Duration::from_secs(5);

// Replay cache parameters (AUTH) - Time TTL removed for DoS protection
const REPLAY_MAX: usize = 50_000;

// ----------------------------------------------------
// C-compatible transcript (replaces merlin::Transcript)
// ----------------------------------------------------
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
        let digest = h.finalize(); // 64 bytes
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        Scalar::from_bytes_mod_order_wide(&wide)
    }
}

// ----------------------------------------------------
// Crypto helpers
// ----------------------------------------------------
fn random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    OsRng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}

fn reject_identity(p: &RistrettoPoint, what: &str) -> std::io::Result<()> {
    if *p == RistrettoPoint::default() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{what} is identity"),
        ));
    }
    Ok(())
}

// ----------------------------------------------------
// Schnorr verify/prove
// ----------------------------------------------------
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

// ----------------------------------------------------
// Session key derivation
// ----------------------------------------------------
fn derive_session_key(
    eph_secret: &Scalar,
    peer_eph_pub: &RistrettoPoint,
    nonce_c: &[u8; 32],
    nonce_s: &[u8; 32],
    device_id: &[u8; 32],
    eph_c: &RistrettoPoint,
    eph_s: &RistrettoPoint,
) -> [u8; 32] {
    let shared = peer_eph_pub * eph_secret;
    let shared_bytes = shared.compress().to_bytes();

    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(nonce_c);
    salt[32..].copy_from_slice(nonce_s);

    let mut info = Vec::with_capacity(11 + 32 + 32 + 32);
    info.extend_from_slice(b"session key"); // 11 bytes
    info.extend_from_slice(device_id);
    info.extend_from_slice(eph_c.compress().as_bytes());
    info.extend_from_slice(eph_s.compress().as_bytes());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &shared_bytes);
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm).unwrap();
    okm
}

// ----------------------------------------------------
// Key confirmation (KC)
// ----------------------------------------------------
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
    // Explicitly cast to the Mac trait to resolve the naming collision
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC key size ok");
    mac.update(label);
    mac.update(th);
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

// ----------------------------------------------------
// Network helpers WITH BYTE COUNTING
// ----------------------------------------------------
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

fn recv_point(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid point"))
}

fn recv_scalar(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Scalar> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    let ct = Scalar::from_canonical_bytes(b);
    if ct.is_some().unwrap_u8() == 1 {
        Ok(ct.unwrap())
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid scalar"))
    }
}

// ----------------------------------------------------
// Registry persistence
// ----------------------------------------------------
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
    if Path::new(path).exists() {
        let _ = fs::copy(path, bak_path);
    }
    let tmp = format!("{}.tmp", path);
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

fn load_or_create_server_sk(path: &str) -> std::io::Result<Scalar> {
    if Path::new(path).exists() {
        let b = fs::read(path)?;
        if b.len() != 32 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "server_sk.bin wrong length"));
        }
        let mut bb = [0u8; 32];
        bb.copy_from_slice(&b);
        let ct = Scalar::from_canonical_bytes(bb);
        if ct.is_some().unwrap_u8() != 1 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "server_sk.bin not canonical"));
        }
        Ok(ct.unwrap())
    } else {
        let sk = random_scalar();
        fs::write(path, sk.to_bytes())?;
        Ok(sk)
    }
}

// ----------------------------------------------------
// Replay cache (AUTH): Infinite-TTL, Bounded-Size
// ----------------------------------------------------
#[derive(Default)]
struct ReplayCache {
    seen_nonces: HashSet<[u8; 64]>,
}

impl ReplayCache {
    fn check_and_insert(&mut self, device_id: &[u8; 32], nonce_c: &[u8; 32]) -> bool {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(device_id);
        k[32..].copy_from_slice(nonce_c);

        if self.seen_nonces.contains(&k) {
            return false; // Replay detected!
        }
        
        // Prevent memory exhaustion
        if self.seen_nonces.len() >= REPLAY_MAX {
            self.seen_nonces.clear();
        }
        
        self.seen_nonces.insert(k);
        true
    }
}

// ----------------------------------------------------
// Pairing config
// ----------------------------------------------------
#[derive(Clone)]
struct PairingPolicy {
    enabled: bool,
    token: Option<String>,
    deadline: Option<Instant>,
}

impl PairingPolicy {
    fn allows_setup(&self, token_seen: Option<&str>) -> bool {
        if !self.enabled {
            return false;
        }
        if let Some(dl) = self.deadline {
            if Instant::now() > dl {
                return false;
            }
        }
        match (&self.token, token_seen) {
            (None, _) => true,
            (Some(expected), Some(got)) => expected == got,
            (Some(_), None) => false,
        }
    }
}

fn recv_setup_token(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Option<String>> {
    let len = recv_u8(stream, recv)?;
    if len == 0 {
        return Ok(None);
    }
    if len > 64 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "token too long"));
    }
    let mut b = vec![0u8; len as usize];
    recv_exact(stream, &mut b, recv)?;
    let s = String::from_utf8(b).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token not utf8"))?;
    Ok(Some(s))
}

// ----------------------------------------------------
// Handlers
// ----------------------------------------------------

fn handle_setup(
    stream: &mut TcpStream,
    policy: &PairingPolicy,
    server_static_pub: &RistrettoPoint,
    reg: &Arc<RwLock<HashMap<[u8; 32], RistrettoPoint>>>,
    sent: &mut usize,
    recv: &mut usize,
) -> std::io::Result<()> {
    let token_seen = recv_setup_token(stream, recv)?;
    if !policy.allows_setup(token_seen.as_deref()) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "pairing not allowed"));
    }

    let device_id = recv_device_id(stream, recv)?;
    let device_static_pub = recv_point(stream, recv)?;
    reject_identity(&device_static_pub, "device_static_pub")?;

    let mut is_new = false;
    {
        let reg_r = reg.read().unwrap();
        if let Some(existing) = reg_r.get(&device_id) {
            if existing.compress().to_bytes() != device_static_pub.compress().to_bytes() {
                return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "device_id mismatch"));
            }
        } else {
            is_new = true;
        }
    }

    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);

    send_all(stream, server_static_pub.compress().as_bytes(), sent)?;
    send_all(stream, &server_nonce, sent)?;
    stream.flush()?;

    let a = recv_point(stream, recv)?;
    let s = recv_scalar(stream, recv)?;

    let ok = schnorr_verify_setup(&device_static_pub, &device_id, &server_nonce, &a, &s);
    if !ok {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "setup PoP invalid"));
    }

    if is_new {
        let mut reg_w = reg.write().unwrap();
        reg_w.insert(device_id, device_static_pub);
        save_registry_atomic(REGISTRY_BIN, REGISTRY_BAK, &reg_w)?;
        println!("Server[SETUP]: enrolled NEW device_id={}", hex::encode(device_id));
    } else {
        println!("Server[SETUP]: validated existing device_id={}", hex::encode(device_id));
    }

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
    // 1. ANONYMOUS EPHEMERAL KEY EXCHANGE (ECDHE)
    let mut client_pk_bytes = [0u8; 32];
    recv_exact(stream, &mut client_pk_bytes, recv)?;
    let client_pk = X25519Public::from(client_pk_bytes);

    let server_sk = EphemeralSecret::random_from_rng(OsRng);
    let server_pk = X25519Public::from(&server_sk);
    send_all(stream, server_pk.as_bytes(), sent)?;
    stream.flush()?;

    // Derive Session Keys (Matching libsodium's crypto_kx exactly)
    let shared_secret = server_sk.diffie_hellman(&client_pk);
    let mut hasher = Blake2b512::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(client_pk_bytes);
    hasher.update(server_pk.as_bytes());
    let hash = hasher.finalize();

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];
    rx_key.copy_from_slice(&hash[32..64]); // C->S (Server's RX)
    tx_key.copy_from_slice(&hash[0..32]);  // S->C (Server's TX)

    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());
    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());

    // 2. READ ENCRYPTED CLIENT PAYLOAD
    let mut len_buf = [0u8; 4];
    recv_exact(stream, &mut len_buf, recv)?;
    let rx_len = u32::from_le_bytes(len_buf) as usize;

    let mut rx_ct = vec![0u8; rx_len];
    recv_exact(stream, &mut rx_ct, recv)?;

    let nonce_rx = Nonce::from_slice(&[0u8; 12]);
    let pt = cipher_rx.decrypt(nonce_rx, rx_ct.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed"))?;

    if pt.len() != 160 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid payload size"));
    }

    let mut device_id = [0u8; 32]; device_id.copy_from_slice(&pt[0..32]);
    let mut a_c_bytes = [0u8; 32]; a_c_bytes.copy_from_slice(&pt[32..64]);
    let mut s_c_bytes = [0u8; 32]; s_c_bytes.copy_from_slice(&pt[64..96]);
    let mut nonce_c = [0u8; 32];   nonce_c.copy_from_slice(&pt[96..128]);
    let mut eph_c_bytes = [0u8; 32]; eph_c_bytes.copy_from_slice(&pt[128..160]);

    let a_c = CompressedRistretto(a_c_bytes).decompress().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid a_c")
    })?;
    let ct = Scalar::from_canonical_bytes(s_c_bytes);
    if ct.is_some().unwrap_u8() != 1 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid s_c"));
    }
    let s_c = ct.unwrap();
    let eph_c = CompressedRistretto(eph_c_bytes).decompress().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid eph_c")
    })?;
    reject_identity(&eph_c, "eph_c")?;

    // 3. REPLAY & SCHNORR VERIFICATION
    {
        let mut rc = replay.lock().unwrap();
        if !rc.check_and_insert(&device_id, &nonce_c) {
            return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "replay detected"));
        }
    }

    let expected_pub = {
        let reg_r = reg.read().unwrap();
        match reg_r.get(&device_id) {
            Some(p) => *p,
            None => return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unknown device_id")),
        }
    };

    let ok = schnorr_verify_auth(&expected_pub, &device_id, &a_c, &s_c, &nonce_c, &eph_c);
    if !ok {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "client proof invalid"));
    }

    // 4. GENERATE ENCRYPTED RESPONSE
    let mut nonce_s = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_s);

    let mut eph_s_secret = random_scalar();
    let eph_s = RISTRETTO_BASEPOINT_POINT * eph_s_secret;
    let (a_s, s_s) = schnorr_prove_server(server_static_secret, &nonce_s, &eph_s);

    let session_key = derive_session_key(&eph_s_secret, &eph_c, &nonce_c, &nonce_s, &device_id, &eph_c, &eph_s);
    let th = kc_transcript_hash(&device_id, &a_c, &s_c, &nonce_c, &eph_c, server_static_pub, &a_s, &s_s, &nonce_s, &eph_s);
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);

    let tag_s = hmac_tag(&k_s2c, b"server finished", &th);

    let mut payload2 = Vec::with_capacity(192);
    payload2.extend_from_slice(server_static_pub.compress().as_bytes());
    payload2.extend_from_slice(a_s.compress().as_bytes());
    payload2.extend_from_slice(&s_s.to_bytes());
    payload2.extend_from_slice(&nonce_s);
    payload2.extend_from_slice(eph_s.compress().as_bytes());
    payload2.extend_from_slice(&tag_s);

    let nonce_tx_1 = Nonce::from_slice(&[0u8; 12]);
    let ct2 = cipher_tx.encrypt(nonce_tx_1, payload2.as_ref()).unwrap();
    let len2 = (ct2.len() as u32).to_le_bytes();
    send_all(stream, &len2, sent)?;
    send_all(stream, &ct2, sent)?;
    stream.flush()?;

    // 5. DECRYPT CLIENT CONFIRMATION (tag_c)
    let mut len_buf2 = [0u8; 4];
    recv_exact(stream, &mut len_buf2, recv)?;
    let rx_len2 = u32::from_le_bytes(len_buf2) as usize;

    let mut rx_ct2 = vec![0u8; rx_len2];
    recv_exact(stream, &mut rx_ct2, recv)?;

    // Client increments nonce because it reuses its TX key
    let mut nonce_rx_2_bytes = [0u8; 12];
    nonce_rx_2_bytes[0] = 1;
    let nonce_rx_2 = Nonce::from_slice(&nonce_rx_2_bytes);

    let tag_c = cipher_rx.decrypt(nonce_rx_2, rx_ct2.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed on tag_c"))?;

    let expected_tag_c = hmac_tag(&k_c2s, b"client finished", &th);
    if expected_tag_c != tag_c[..] {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "tag_c mismatch"));
    }

    println!("Server[AUTH]: device_id={} session_key={} KC=OK", hex::encode(device_id), hex::encode(session_key));

    eph_s_secret.zeroize();
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    server_static_secret: Arc<Scalar>,
    server_static_pub: Arc<RistrettoPoint>,
    policy: PairingPolicy,
    reg: Arc<RwLock<HashMap<[u8; 32], RistrettoPoint>>>,
    replay: Arc<Mutex<ReplayCache>>,
) {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;
    let peer = stream.peer_addr().ok();

    if let Err(e) = stream.set_nodelay(true) {
        eprintln!("Server: set_nodelay error: {}", e);
        return;
    }
    if let Err(e) = stream.set_read_timeout(Some(IO_TIMEOUT)) {
        eprintln!("Server: set_read_timeout error: {}", e);
        return;
    }
    if let Err(e) = stream.set_write_timeout(Some(IO_TIMEOUT)) {
        eprintln!("Server: set_write_timeout error: {}", e);
        return;
    }

    let msg_type = match recv_u8(&mut stream, &mut recv) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Server: read msg_type error from {:?}: {}", peer, e);
            return;
        }
    };

    let res = match msg_type {
        MSG_SETUP => handle_setup(&mut stream, &policy, &server_static_pub, &reg, &mut sent, &mut recv),
        MSG_AUTH_V2 => handle_auth_v2(&mut stream, &server_static_secret, &server_static_pub, &reg, &replay, &mut sent, &mut recv),
        _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unknown msg_type")),
    };

    if let Err(e) = res {
        eprintln!("Server: request from {:?} failed: {}", peer, e);
    }

    println!("SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes", peer, start.elapsed(), sent, recv);
}

// ----------------------------------------------------
// MAIN
// ----------------------------------------------------
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut bind_addr = "0.0.0.0:4000".to_string();
    let mut pairing = false;
    let mut pairing_token: Option<String> = None;
    let mut pairing_seconds: Option<u64> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing val")); }
                bind_addr = args[i + 1].clone();
                i += 2;
            }
            "--pairing" => {
                pairing = true;
                i += 1;
            }
            "--pairing-token" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing val")); }
                pairing_token = Some(args[i + 1].clone());
                i += 2;
            }
            "--pairing-seconds" => {
                if i + 1 >= args.len() { return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "missing val")); }
                pairing_seconds = Some(args[i + 1].parse().map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad sec"))?);
                i += 2;
            }
            _ => return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown argument")),
        }
    }

    let deadline = pairing_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let policy = PairingPolicy { enabled: pairing, token: pairing_token, deadline };

    println!("Server: Listening on {}", bind_addr);
    println!("Server: pairing_enabled={} token_required={} deadline={:?}", policy.enabled, policy.token.is_some(), policy.deadline);

    let reg_map = load_registry(REGISTRY_BIN).unwrap_or_default();
    let reg = Arc::new(RwLock::new(reg_map));
    let replay = Arc::new(Mutex::new(ReplayCache::default()));
    let listener = TcpListener::bind(&bind_addr)?;

    let server_static_secret = load_or_create_server_sk(SERVER_SK_FILE)?;
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let ss = Arc::new(server_static_secret);
    let sp = Arc::new(server_static_pub);

    loop {
        let (stream, _) = listener.accept()?;
        let ss2 = Arc::clone(&ss);
        let sp2 = Arc::clone(&sp);
        let pol2 = policy.clone();
        let reg2 = Arc::clone(&reg);
        let rep2 = Arc::clone(&replay);

        thread::spawn(move || {
            handle_client(stream, ss2, sp2, pol2, reg2, rep2);
        });
    }
}