// ==============================
// client.rs (DESIGN A: TOFU pin server pubkey + KEY CONFIRMATION MACs)
// ==============================
//
// Goals:
//   1) Record server identity during provisioning (SETUP) using TOFU pinning of server_static_pub.
//   2) Enforce pinned server_static_pub during AUTH (reject MITM / wrong server).
//   3) Add key confirmation MACs: "server finished" and "client finished".
//
// C-compat transcript (NO merlin):
//   domain_len(u8)||domain
//   for each field: label_len(u8)||label||value_len(u32 LE)||value
//   challenge scalar: c = Scalar::from_bytes_mod_order_wide(SHA512(transcript))
//
// Wire protocol (1-byte msg_type):
//   MSG_SETUP = 0x01
//     C->S: 0x01 | token_len(u8)=0 | device_id(32) | device_static_pub(32)
//     S->C: server_static_pub(32) | server_nonce(32)         [UPDATED]
//     C->S: A(32) | s(32)     (Schnorr PoP over device key, bound to device_id + device_pub + A + server_nonce)
//
//   MSG_AUTH  = 0x02
//     C->S: 0x02 | device_id(32) | A(32) | s(32) | nonce_c(32) | eph_c(32)
//     S->C: server_static_pub(32) | A_s(32) | s_s(32) | nonce_s(32) | eph_s(32) | tag_s(32)   [UPDATED]
//     C->S: tag_c(32)                                                                    [UPDATED]
//
// Files (client):
//   device_id.bin   (32 bytes)
//   device_x.bin    (32 bytes scalar)
//   server_pub.bin  (32 bytes compressed Ristretto)  <-- pinned server identity (TOFU)
//
// Dependencies (Cargo.toml):
//   curve25519-dalek = "4"
//   rand = "0.8"
//   sha2 = "0.10"
//   hkdf = "0.12"
//   hmac = "0.12"
//   hex = "0.4"
//   zeroize = "1"
//
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const DEVICE_ID_LEN: usize = 32;
const NONCE_LEN: usize = 32;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH: u8 = 0x02;

const DEVICE_ID_FILE: &str = "device_id.bin";
const DEVICE_X_FILE: &str = "device_x.bin";
const SERVER_PUB_FILE: &str = "server_pub.bin";

// Transcript domains (versioned; must match server and C if you interop)
const T_SETUP: &[u8] = b"setup_schnorr_v1";
const T_CLIENT: &[u8] = b"client_schnorr_v1";
const T_SERVER: &[u8] = b"server_schnorr_v1";
const T_KC: &[u8] = b"kc_v1";

// Networking hardening
const IO_TIMEOUT: Duration = Duration::from_secs(5);

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

fn random_bytes_32() -> [u8; 32] {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    b
}

/// Reject identity points (hardening).
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
// Schnorr proofs
// ----------------------------------------------------

/// Setup proof-of-possession (PoP): binds device_id + device_pub + A + server_nonce.
/// This demonstrates the client actually controls x corresponding to device_pub.
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

/// Auth proof: binds device_id + expected pubkey + A + nonce_c + eph_c.
/// This proves the connecting party still controls the registered static secret x.
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

/// Verify server Schnorr proof: binds server_pub + A_s + nonce_s + eph_s.
/// NOTE: With Design A, we don’t need a hardcoded SERVER_ID. The server identity is its pinned pubkey.
fn schnorr_verify_server(
    server_static_pub: &RistrettoPoint,
    a: &RistrettoPoint,
    s: &Scalar,
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
) -> bool {
    let mut t = CompatTranscript::new(T_SERVER);
    // We bind the server pubkey explicitly.
    t.append_message(b"pubkey", server_static_pub.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());

    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
}

// ----------------------------------------------------
// Session key derivation (same as your original)
// ----------------------------------------------------
/// HKDF derivation:
///   shared = peer_eph_pub * eph_secret
///   salt   = nonce_c || nonce_s
///   info   = "session key" || device_id || eph_c || eph_s
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
// Key confirmation (KC): transcript hash + HMACs
// ----------------------------------------------------

/// Compute a transcript hash that both sides can reproduce.
/// We use CompatTranscript for deterministic binary encoding, then SHA-256 of the transcript buffer.
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
    h.update(&t.buf);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Derive separate KC keys from the session key.
/// This avoids reusing the raw session key directly for MACing.
fn derive_kc_keys(session_key: &[u8; 32], th: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(th), session_key);

    let mut k_s2c = [0u8; 32];
    let mut k_c2s = [0u8; 32];

    hk.expand(b"kc s2c", &mut k_s2c).unwrap();
    hk.expand(b"kc c2s", &mut k_c2s).unwrap();

    (k_s2c, k_c2s)
}

fn hmac_tag(key: &[u8; 32], label: &[u8], th: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key size ok");
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
// Local credential storage (simple demo)
// ----------------------------------------------------
fn load_device_creds() -> std::io::Result<([u8; 32], Scalar)> {
    let id_bytes = fs::read(DEVICE_ID_FILE)?;
    if id_bytes.len() != DEVICE_ID_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device_id.bin wrong length",
        ));
    }
    let mut device_id = [0u8; 32];
    device_id.copy_from_slice(&id_bytes);

    let x_bytes = fs::read(DEVICE_X_FILE)?;
    if x_bytes.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device_x.bin wrong length",
        ));
    }
    let mut xb = [0u8; 32];
    xb.copy_from_slice(&x_bytes);

    let ct = Scalar::from_canonical_bytes(xb);
    if ct.is_some().unwrap_u8() != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "device_x.bin not canonical scalar",
        ));
    }
    Ok((device_id, ct.unwrap()))
}

fn save_device_creds(device_id: &[u8; 32], x: &Scalar) -> std::io::Result<()> {
    fs::write(DEVICE_ID_FILE, device_id)?;
    fs::write(DEVICE_X_FILE, x.to_bytes())?;
    Ok(())
}

fn creds_exist() -> bool {
    Path::new(DEVICE_ID_FILE).exists() && Path::new(DEVICE_X_FILE).exists()
}

// ----------------------------------------------------
// Server pubkey pinning (TOFU)
// ----------------------------------------------------
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
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "server_pub.bin invalid point"))?;
    reject_identity(&p, "pinned server_pub")?;
    Ok(Some(p))
}

fn save_server_pub(pubkey: &RistrettoPoint) -> std::io::Result<()> {
    fs::write(SERVER_PUB_FILE, pubkey.compress().as_bytes())?;
    Ok(())
}

// ----------------------------------------------------
// SETUP (provisioning handshake)
// ----------------------------------------------------
fn do_setup(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let mut sent = 0usize;
    let mut recv = 0usize;

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    println!("Client[SETUP]: Connected to {}", server_addr);

    // msg_type
    send_all(&mut stream, &[MSG_SETUP], &mut sent)?;

    // token_len(u8) = 0 (kept for C-compat; if you want a token, extend this)
    send_all(&mut stream, &[0u8], &mut sent)?;

    // send device_id + device_static_pub
    let device_static_pub = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&device_static_pub, "client device_static_pub")?;

    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, device_static_pub.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    // recv server_static_pub + server_nonce  [UPDATED]
    let server_static_pub = recv_point(&mut stream, &mut recv)?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;

    // TOFU pinning: if no pinned server, store it now; else enforce match
    match load_server_pub()? {
        None => {
            println!("Client[SETUP]: Pinning server pubkey (TOFU) to {}", SERVER_PUB_FILE);
            save_server_pub(&server_static_pub)?;
        }
        Some(pinned) => {
            if pinned.compress().to_bytes() != server_static_pub.compress().to_bytes() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "server pubkey mismatch vs pinned (refuse setup)",
                ));
            }
            println!("Client[SETUP]: Server pubkey matches pinned value.");
        }
    }

    // prove possession of device key
    let (a, s) = schnorr_prove_setup(&x, &device_id, &server_nonce);
    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    stream.flush()?;

    println!(
        "Client[SETUP]: Sent={} bytes, Received={} bytes. Enrolled device_id={}",
        sent,
        recv,
        hex::encode(device_id)
    );

    x.zeroize();
    Ok(())
}

// ----------------------------------------------------
// AUTH (normal handshake) + KC MACs
// ----------------------------------------------------
fn do_auth(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    // Must have pinned server identity to proceed (Design A)
    let pinned_server_pub = load_server_pub()?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "no pinned server_pub.bin; run client --setup first",
        )
    })?;

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    println!("Client[AUTH]: Connected to {}", server_addr);

    // Client nonce + ephemeral ECDH key
    let mut nonce_c = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_c);

    let mut eph_secret = random_scalar();
    let eph_pub = RISTRETTO_BASEPOINT_POINT * eph_secret;
    reject_identity(&eph_pub, "client eph_pub")?;

    // Client Schnorr auth proof over static x
    let (a_c, s_c) = schnorr_prove_auth(&x, &device_id, &nonce_c, &eph_pub);

    // Send AUTH request
    send_all(&mut stream, &[MSG_AUTH], &mut sent)?;
    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, a_c.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s_c.to_bytes(), &mut sent)?;
    send_all(&mut stream, &nonce_c, &mut sent)?;
    send_all(&mut stream, eph_pub.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    // Receive server response
    let server_static_pub = recv_point(&mut stream, &mut recv)?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    // Enforce pinned server identity
    if server_static_pub.compress().to_bytes() != pinned_server_pub.compress().to_bytes() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server pubkey mismatch vs pinned (refuse auth)",
        ));
    }

    let a_s = recv_point(&mut stream, &mut recv)?;
    let s_s = recv_scalar(&mut stream, &mut recv)?;

    let mut nonce_s = [0u8; NONCE_LEN];
    recv_exact(&mut stream, &mut nonce_s, &mut recv)?;

    let eph_s = recv_point(&mut stream, &mut recv)?;
    reject_identity(&eph_s, "server eph_s")?;

    // Verify server Schnorr proof using pinned pubkey
    let ok = schnorr_verify_server(&server_static_pub, &a_s, &s_s, &nonce_s, &eph_s);
    println!("Client[AUTH]: Server Schnorr authentication = {}", ok);
    if !ok {
        eprintln!("Client[AUTH]: Authentication FAILED");
        x.zeroize();
        eph_secret.zeroize();
        return Ok(());
    }

    // Derive session key
    let session_key = derive_session_key(&eph_secret, &eph_s, &nonce_c, &nonce_s, &device_id, &eph_pub, &eph_s);
    println!("Client[AUTH]: Session key = {}", hex::encode(session_key));

    // -------- Key Confirmation (KC) --------
    // Receive tag_s then verify, then send tag_c.
    let mut tag_s = [0u8; 32];
    recv_exact(&mut stream, &mut tag_s, &mut recv)?;

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
    if expected_tag_s != tag_s {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "server key confirmation failed (tag_s mismatch)",
        ));
    }
    println!("Client[AUTH]: Key confirmation (server finished) OK");

    let tag_c = hmac_tag(&k_c2s, b"client finished", &th);
    send_all(&mut stream, &tag_c, &mut sent)?;
    stream.flush()?;
    println!("Client[AUTH]: Sent client finished tag");

    // Cleanup secrets
    x.zeroize();
    eph_secret.zeroize();

    let duration = start.elapsed();
    println!(
        "CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes",
        duration, sent, recv
    );

    Ok(())
}

// ----------------------------------------------------
// MAIN
// Usage:
//   client --setup --server 127.0.0.1:4000
//   client --server 127.0.0.1:4000
// ----------------------------------------------------
fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut server_addr = "127.0.0.1:4000".to_string();
    let mut do_setup_flag = false;

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
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unknown argument",
                ));
            }
        }
    }

    // If creds missing, force explicit setup
    if !creds_exist() && !do_setup_flag {
        eprintln!(
            "Client: device creds missing ({} / {}). Refusing AUTH. Run with --setup to enroll.",
            DEVICE_ID_FILE, DEVICE_X_FILE
        );
        return Ok(());
    }

    if do_setup_flag {
        // Create new identity if missing; otherwise reuse existing identity for idempotent setup
        let (device_id, x) = if creds_exist() {
            println!("Client[SETUP]: Using existing creds for setup (idempotent).");
            load_device_creds()?
        } else {
            println!("Client[SETUP]: No creds found; generating NEW device identity (re-enroll).");
            let device_id = random_bytes_32();
            let x = random_scalar();
            save_device_creds(&device_id, &x)?;
            (device_id, x)
        };

        do_setup(&server_addr, device_id, x)?;
        return Ok(());
    }

    // Normal auth path
    let (device_id, x) = load_device_creds()?;
    do_auth(&server_addr, device_id, x)
}