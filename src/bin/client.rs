// ==============================
// client.rs (C-COMPATIBLE TRANSCRIPT, NO MERLIN)
// ==============================
//
// Wire protocol (1-byte msg_type):
//   MSG_SETUP = 0x01
//     C->S: 0x01 | token_len(u8)=0 | device_id(32) | static_pub(32)
//     S->C: server_nonce(32)
//     C->S: A(32) | s(32)          (Schnorr PoP bound to device_id + server_nonce)
//
//   MSG_AUTH  = 0x02
//     C->S: 0x02 | device_id(32) | A(32) | s(32) | nonce_c(32) | eph_c(32)
//     S->C:       server_static_pub(32) | A_s(32) | s_s(32) | nonce_s(32) | eph_s(32)
//
// Files (client):
//   device_id.bin (32 bytes)
//   device_x.bin  (32 bytes scalar)
//
// NOTE: This version replaces merlin::Transcript with a C-compatible transcript:
//   domain_len(u8)||domain
//   for each field: label_len(u8)||label||value_len(u32 LE)||value
//   challenge scalar: c = Scalar::from_bytes_mod_order_wide(SHA512(transcript))
//
// This MUST match the C implementation's transcript to interoperate.
//

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Instant;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

const DEVICE_ID_LEN: usize = 32;
const NONCE_LEN: usize = 32;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH: u8 = 0x02;

const DEVICE_ID_FILE: &str = "device_id.bin";
const DEVICE_X_FILE: &str = "device_x.bin";

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

// Setup proof-of-possession (PoP): binds device_id + pubkey + A + server_nonce
fn schnorr_prove_setup(
    x: &Scalar,
    device_id: &[u8; 32],
    server_nonce: &[u8; 32],
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;

    let mut t = CompatTranscript::new(b"setup_schnorr");
    t.append_message(b"device_id", device_id);
    t.append_message(b"pubkey", pubkey.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"server_nonce", server_nonce);

    let c = t.challenge_scalar();
    let s = r + c * x;
    (a, s)
}

// Auth proof: binds device_id + expected pubkey + A + nonce_c + eph_c
fn schnorr_prove_auth(
    x: &Scalar,
    device_id: &[u8; 32],
    nonce_c: &[u8; 32],
    eph_c: &RistrettoPoint,
    label: &'static [u8], // must be b"client_schnorr"
) -> (RistrettoPoint, Scalar) {
    let pubkey = RISTRETTO_BASEPOINT_POINT * x;
    let r = random_scalar();
    let a = RISTRETTO_BASEPOINT_POINT * r;

    let mut t = CompatTranscript::new(label);
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
    server_id: &[u8; 32],
    nonce_s: &[u8; 32],
    eph_s: &RistrettoPoint,
    label: &'static [u8], // must be b"server_schnorr"
) -> bool {
    let mut t = CompatTranscript::new(label);
    t.append_message(b"server_id", server_id);
    t.append_message(b"pubkey", server_static_pub.compress().as_bytes());
    t.append_message(b"a", a.compress().as_bytes());
    t.append_message(b"nonce_s", nonce_s);
    t.append_message(b"eph_s", eph_s.compress().as_bytes());

    let c = t.challenge_scalar();
    RISTRETTO_BASEPOINT_POINT * s == a + server_static_pub * c
}

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

    // salt = nonce_c || nonce_s
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(nonce_c);
    salt[32..].copy_from_slice(nonce_s);

    // info = "session key" || device_id || eph_c || eph_s
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

// ----------------------------------------------------
// Local credential storage (simple demo)
// ----------------------------------------------------
fn load_device_creds() -> std::io::Result<([u8; 32], Scalar)> {
    let id_bytes = fs::read(DEVICE_ID_FILE)?;
    if id_bytes.len() != 32 {
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
// SETUP (provisioning handshake)
// ----------------------------------------------------
fn do_setup(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let mut sent = 0usize;
    let mut recv = 0usize;

    let mut stream = TcpStream::connect(server_addr)?;
    println!("Client[SETUP]: Connected to {}", server_addr);

    // msg_type
    send_all(&mut stream, &[MSG_SETUP], &mut sent)?;

    // token_len(u8) = 0 (matches your server behavior)
    send_all(&mut stream, &[0u8], &mut sent)?;

    // send device_id + static_pub
    let static_pub = RISTRETTO_BASEPOINT_POINT * x;
    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, static_pub.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    // recv server_nonce
    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;

    // prove possession
    let (a, s) = schnorr_prove_setup(&x, &device_id, &server_nonce);
    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    stream.flush()?;

    println!(
        "Client[SETUP]: Sent={} bytes, Received={} bytes. Registered device_id={}",
        sent,
        recv,
        hex::encode(device_id)
    );

    x.zeroize();
    Ok(())
}

// ----------------------------------------------------
// AUTH (normal handshake)
// ----------------------------------------------------

// Demo constant server identity binding (matches C).
static SERVER_ID: [u8; 32] = [0x53u8; 32];

fn do_auth(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    let mut stream = TcpStream::connect(server_addr)?;
    println!("Client[AUTH]: Connected to {}", server_addr);

    let mut nonce_c = [0u8; 32];
    OsRng.fill_bytes(&mut nonce_c);

    let mut eph_secret = random_scalar();
    let eph_pub = RISTRETTO_BASEPOINT_POINT * eph_secret;

    // msg_type + identity-bound proof
    let (a, s) = schnorr_prove_auth(&x, &device_id, &nonce_c, &eph_pub, b"client_schnorr");

    send_all(&mut stream, &[MSG_AUTH], &mut sent)?;
    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    send_all(&mut stream, &nonce_c, &mut sent)?;
    send_all(&mut stream, eph_pub.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    // recv server response
    let server_static_pub = recv_point(&mut stream, &mut recv)?;
    let server_a = recv_point(&mut stream, &mut recv)?;
    let server_s = recv_scalar(&mut stream, &mut recv)?;
    let mut nonce_s = [0u8; 32];
    recv_exact(&mut stream, &mut nonce_s, &mut recv)?;
    let eph_s = recv_point(&mut stream, &mut recv)?;

    // verify server
    let ok = schnorr_verify_server(
        &server_static_pub,
        &server_a,
        &server_s,
        &SERVER_ID,
        &nonce_s,
        &eph_s,
        b"server_schnorr",
    );
    println!("Client[AUTH]: Server authentication = {}", ok);
    if !ok {
        eprintln!("Client[AUTH]: Authentication FAILED");
        x.zeroize();
        eph_secret.zeroize();
        return Ok(());
    }

    let key = derive_session_key(
        &eph_secret,
        &eph_s,
        &nonce_c,
        &nonce_s,
        &device_id,
        &eph_pub,
        &eph_s,
    );
    println!("Client[AUTH]: Session key = {}", hex::encode(key));

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
