// ==============================
// server.rs
// ==============================
//
// Supports:
//   - SETUP (0x01): register device_id -> static pubkey with PoP (Schnorr)
//   - AUTH  (0x02): authenticate device using registry lookup + Schnorr ZKP
//
// Registry persistence:
//   - registry.bin (current)
//   - registry.bak (previous snapshot)
//
// Pairing control:
//   - By default, SETUP is rejected.
//   - Enable pairing by starting server with: --pairing
//   - Optional: enforce token with --pairing-token <token>
//   - Optional: pairing window with --pairing-seconds <seconds>
//
// Wire protocol (1-byte msg_type):
//   MSG_SETUP = 0x01
//     C->S: 0x01 | token_len(u8) | token_bytes | device_id(32) | static_pub(32)
//     S->C: server_nonce(32)
//     C->S: A(32) | s(32)          (Schnorr PoP bound to device_id + server_nonce)
//
//   MSG_AUTH  = 0x02
//     C->S: 0x02 | device_id(32) | A(32) | s(32) | nonce_c(32) | eph_c(32)
//     S->C:       server_static_pub(32) | A_s(32) | s_s(32) | nonce_s(32) | eph_s(32)
//
// IMPORTANT: This version replaces merlin::Transcript with a C-compatible transcript:
//   domain_len(u8)||domain
//   for each field: label_len(u8)||label||value_len(u32 LE)||value
//   challenge scalar: c = Scalar::from_bytes_mod_order_wide(SHA512(transcript))
//
// This MUST match the C implementation's transcript to interoperate.
//

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH: u8 = 0x02;

const REGISTRY_BIN: &str = "registry.bin";
const REGISTRY_BAK: &str = "registry.bak";

// Demo constant server identity binding (matches the C code you’re using)
static SERVER_ID: [u8; 32] = [0x53u8; 32];

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
        h.update(&self.buf);
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

// Setup verify: binds device_id + pubkey + A + server_nonce
fn schnorr_verify_setup(
    pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    server_nonce: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
) -> bool {
    let mut t = CompatTranscript::new(b"setup_schnorr");
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"server_nonce", server_nonce);

    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + pubkey * c
}

// Auth verify: binds device_id + expected pubkey + A + nonce_c + eph_c
fn schnorr_verify_auth(
    expected_pubkey: &RistrettoPoint,
    device_id: &[u8; 32],
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    label: &'static [u8], // b"client_schnorr"
) -> bool {
    let mut t = CompatTranscript::new(label);
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", expected_pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_c", nonce_c);
    t.append_message(b"eph_c", eph_c.compress().as_bytes());

    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + expected_pubkey * c
}

// Server prove (mutual auth): binds server_id + pubkey + A + nonce_s + eph_s
fn schnorr_prove_server(
    server_secret: &Scalar,
    server_id: &[u8; 32],
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
    label: &'static [u8], // b"server_schnorr"
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * server_secret;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;

    let mut t = CompatTranscript::new(label);
    t.append_message(b"server_id", server_id);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());

    let c = t.challenge_scalar();
    let s = r + c * server_secret;
    (a, s)
}

// HKDF matches the C implementation:
// shared = peer_eph_pub * eph_secret
// salt = nonce_c || nonce_s
// info = "session key" || device_id || eph_c || eph_s
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
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid scalar",
        ))
    }
}

fn recv_nonce(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<[u8; 32]> {
    let mut n = [0u8; 32];
    recv_exact(stream, &mut n, recv)?;
    Ok(n)
}

// ----------------------------------------------------
// Registry persistence
// Format: repeated records of (device_id 32 bytes || pubkey 32 bytes)
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
            reg.insert(id, p);
        }
    }
    Ok(reg)
}

fn save_registry_atomic(
    path: &str,
    bak_path: &str,
    reg: &HashMap<[u8; 32], RistrettoPoint>,
) -> std::io::Result<()> {
    // Backup existing
    if Path::new(path).exists() {
        let _ = fs::copy(path, bak_path);
    }

    // Write tmp then rename
    let tmp = format!("{}.tmp", path);
    let mut out = Vec::with_capacity(reg.len() * 64);
    for (id, pk) in reg {
        out.extend_from_slice(id);
        out.extend_from_slice(pk.compress().as_bytes());
    }
    fs::write(&tmp, out)?;
    fs::rename(&tmp, path)?;
    Ok(())
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

// SETUP request includes token:
//   0x01 | token_len(u8) | token_bytes | device_id(32) | static_pub(32)
fn recv_setup_token(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<Option<String>> {
    let len = recv_u8(stream, recv)?;
    if len == 0 {
        return Ok(None);
    }
    let mut b = vec![0u8; len as usize];
    recv_exact(stream, &mut b, recv)?;
    let s = String::from_utf8(b)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "token not utf8"))?;
    Ok(Some(s))
}

// ----------------------------------------------------
// Handlers
// ----------------------------------------------------
fn handle_setup(
    stream: &mut TcpStream,
    policy: &PairingPolicy,
    reg: &mut HashMap<[u8; 32], RistrettoPoint>,
    sent: &mut usize,
    recv: &mut usize,
) -> std::io::Result<()> {
    let token_seen = recv_setup_token(stream, recv)?;
    if !policy.allows_setup(token_seen.as_deref()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "pairing not allowed",
        ));
    }

    let device_id = recv_device_id(stream, recv)?;
    let static_pub = recv_point(stream, recv)?;

    // If already registered, require same pubkey; still do PoP.
    let mut is_new = false;
    if let Some(existing) = reg.get(&device_id) {
        if existing.compress().to_bytes() != static_pub.compress().to_bytes() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "device_id already registered (mismatch)",
            ));
        }
    } else {
        is_new = true;
    }

    // Challenge
    let mut server_nonce = [0u8; 32];
    OsRng.fill_bytes(&mut server_nonce);
    send_all(stream, &server_nonce, sent)?;
    stream.flush()?;

    // PoP
    let a = recv_point(stream, recv)?;
    let s = recv_scalar(stream, recv)?;
    let ok = schnorr_verify_setup(&static_pub, &device_id, &server_nonce, &a, &s);
    if !ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "setup PoP invalid",
        ));
    }

    // Store + persist only if new
    if is_new {
        reg.insert(device_id, static_pub);
        save_registry_atomic(REGISTRY_BIN, REGISTRY_BAK, reg)?;
        println!("Server[SETUP]: enrolled NEW device_id={}", hex::encode(device_id));
    } else {
        println!(
            "Server[SETUP]: validated existing device_id={}",
            hex::encode(device_id)
        );
    }

    Ok(())
}

fn handle_auth(
    stream: &mut TcpStream,
    server_static_secret: &Scalar,
    server_static_pub: &RistrettoPoint,
    reg: &HashMap<[u8; 32], RistrettoPoint>,
    sent: &mut usize,
    recv: &mut usize,
) -> std::io::Result<()> {
    let device_id = recv_device_id(stream, recv)?;
    let a_c = recv_point(stream, recv)?;
    let s_c = recv_scalar(stream, recv)?;
    let nonce_c = recv_nonce(stream, recv)?;
    let eph_c = recv_point(stream, recv)?;

    let expected_pub = match reg.get(&device_id) {
        Some(p) => p,
        None => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unknown device_id",
            ))
        }
    };

    let ok = schnorr_verify_auth(
        expected_pub,
        &device_id,
        &a_c,
        &s_c,
        &nonce_c,
        &eph_c,
        b"client_schnorr",
    );
    if !ok {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "client proof invalid",
        ));
    }

    // Server response
    let mut nonce_s = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_s);

    let mut eph_s_secret = random_scalar();
    let eph_s = RISTRETTO_BASEPOINT_POINT * eph_s_secret;

    let (a_s, s_s) = schnorr_prove_server(
        server_static_secret,
        &SERVER_ID,
        &nonce_s,
        &eph_s,
        b"server_schnorr",
    );

    // send: server_static_pub | A_s | s_s | nonce_s | eph_s
    send_all(stream, server_static_pub.compress().as_bytes(), sent)?;
    send_all(stream, a_s.compress().as_bytes(), sent)?;
    send_all(stream, &s_s.to_bytes(), sent)?;
    send_all(stream, &nonce_s, sent)?;
    send_all(stream, eph_s.compress().as_bytes(), sent)?;
    stream.flush()?;

    // derive session key (matches C logic)
    let key = derive_session_key(
        &eph_s_secret,
        &eph_c,
        &nonce_c,
        &nonce_s,
        &device_id,
        &eph_c,
        &eph_s,
    );

    println!(
        "Server[AUTH]: device_id={} key={}",
        hex::encode(device_id),
        hex::encode(key)
    );

    eph_s_secret.zeroize();
    Ok(())
}

fn handle_client(
    mut stream: TcpStream,
    server_static_secret: Scalar,
    server_static_pub: RistrettoPoint,
    policy: PairingPolicy,
) {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    // Load registry each connection (simple + safe for demo).
    let mut reg = load_registry(REGISTRY_BIN).unwrap_or_default();

    let peer = stream.peer_addr().ok();
    let msg_type = match recv_u8(&mut stream, &mut recv) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Server: read msg_type error: {}", e);
            return;
        }
    };

    let res = match msg_type {
        MSG_SETUP => handle_setup(&mut stream, &policy, &mut reg, &mut sent, &mut recv),
        MSG_AUTH => handle_auth(
            &mut stream,
            &server_static_secret,
            &server_static_pub,
            &reg,
            &mut sent,
            &mut recv,
        ),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unknown msg_type",
        )),
    };

    if let Err(e) = res {
        eprintln!("Server: request from {:?} failed: {}", peer, e);
    }

    let duration = start.elapsed();
    println!(
        "SERVER METRICS -> {:?} Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        peer, duration, sent, recv
    );
}

// ----------------------------------------------------
// MAIN
// Usage:
//   server --bind 0.0.0.0:4000 [--pairing] [--pairing-token TOKEN] [--pairing-seconds 60]
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
                if i + 1 >= args.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--bind missing value",
                    ));
                }
                bind_addr = args[i + 1].clone();
                i += 2;
            }
            "--pairing" => {
                pairing = true;
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
            "--pairing-seconds" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "--pairing-seconds missing value",
                    ));
                }
                pairing_seconds = Some(args[i + 1].parse().map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad --pairing-seconds")
                })?);
                i += 2;
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unknown argument",
                ))
            }
        }
    }

    let deadline = pairing_seconds.map(|s| Instant::now() + Duration::from_secs(s));
    let policy = PairingPolicy {
        enabled: pairing,
        token: pairing_token,
        deadline,
    };

    println!("Server: Listening on {}", bind_addr);
    println!(
        "Server: pairing_enabled={} token_required={} deadline={:?}",
        policy.enabled,
        policy.token.is_some(),
        policy.deadline
    );

    let listener = TcpListener::bind(&bind_addr)?;

    // Server static key (ephemeral per run, matches your original Rust design).
    // If you want persistence like the C server_sk.bin approach, tell me and I’ll provide it.
    let server_static_secret = random_scalar();
    let server_static_pub = RISTRETTO_BASEPOINT_POINT * server_static_secret;

    loop {
        let (stream, _) = listener.accept()?;
        let ss = server_static_secret.clone();
        let sp = server_static_pub.clone();
        let pol = policy.clone();

        thread::spawn(move || {
            handle_client(stream, ss, sp, pol);
        });
    }
}
