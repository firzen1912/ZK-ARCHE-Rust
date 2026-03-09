// ==============================
// client.rs (V2: Zero Privacy + TOFU Pinning & Key Confirmation)
// ==============================
//
// Goals:
//   1) Record server identity via TOFU or out-of-band pinning (--pin-server-pub).
//   2) Enforce pinned server_static_pub during SETUP and AUTH (reject MITM).
//   3) Zero Privacy: Hide identity (device_id) during AUTH using X25519 ECDHE tunnel.
//   4) Add key confirmation MACs: "server finished" and "client finished".
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
use rand::{rngs::OsRng, RngCore};
use sha2::{Sha256, Sha512};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519Public};
use zeroize::Zeroize;

type HmacSha256 = Hmac<Sha256>;

const DEVICE_ID_LEN: usize = 32;
const NONCE_LEN: usize = 32;

const MSG_SETUP: u8 = 0x01;
const MSG_AUTH_V2: u8 = 0x03; // Bumped to 0x03 for encrypted tunnel

const DEVICE_ROOT_FILE: &str = "/var/lib/iot-auth/device_root.bin";
const SERVER_PUB_FILE: &str = "/var/lib/iot-auth/server_pub.bin";

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
// Key confirmation (KC): transcript hash + HMACs
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

fn recv_point(stream: &mut impl Read, recv: &mut usize) -> std::io::Result<RistrettoPoint> {
    let mut b = [0u8; 32];
    recv_exact(stream, &mut b, recv)?;
    CompressedRistretto(b)
        .decompress()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid point"))
}

// ----------------------------------------------------
// Local credential storage (root-secret model)
// ----------------------------------------------------
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

// ----------------------------------------------------
// Server pubkey pinning (TOFU & Out-of-band)
// ----------------------------------------------------
fn load_server_pub() -> std::io::Result<Option<RistrettoPoint>> {
    if !Path::new(SERVER_PUB_FILE).exists() {
        return Ok(None);
    }
    let b = fs::read(SERVER_PUB_FILE)?;
    if b.len() != 32 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "server_pub.bin wrong length"));
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

    send_all(&mut stream, &[MSG_SETUP], &mut sent)?;
    send_all(&mut stream, &[0u8], &mut sent)?;

    let device_static_pub = RISTRETTO_BASEPOINT_POINT * x;
    reject_identity(&device_static_pub, "client device_static_pub")?;

    send_all(&mut stream, &device_id, &mut sent)?;
    send_all(&mut stream, device_static_pub.compress().as_bytes(), &mut sent)?;
    stream.flush()?;

    let server_static_pub = recv_point(&mut stream, &mut recv)?;
    reject_identity(&server_static_pub, "server_static_pub")?;

    let mut server_nonce = [0u8; 32];
    recv_exact(&mut stream, &mut server_nonce, &mut recv)?;

    // MITM Protection: Enforce out-of-band pin if it exists, otherwise TOFU
    match load_server_pub()? {
        None => {
            println!("Client[SETUP]: Pinning server pubkey (TOFU) to {}", SERVER_PUB_FILE);
            save_server_pub(&server_static_pub)?;
        }
        Some(pinned) => {
            if pinned.compress().to_bytes() != server_static_pub.compress().to_bytes() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "MITM ALERT: Server offered a different public key than our pinned key!",
                ));
            }
            println!("Client[SETUP]: Server pubkey matches pinned value.");
        }
    }

    let (a, s) = schnorr_prove_setup(&x, &device_id, &server_nonce);
    send_all(&mut stream, a.compress().as_bytes(), &mut sent)?;
    send_all(&mut stream, &s.to_bytes(), &mut sent)?;
    stream.flush()?;

    println!("Client[SETUP]: Sent={} bytes, Received={} bytes. Enrolled.", sent, recv);
    x.zeroize();
    Ok(())
}

// ----------------------------------------------------
// AUTH V2 (Encrypted Zero-Privacy Tunnel)
// ----------------------------------------------------
fn do_auth_v2(server_addr: &str, device_id: [u8; 32], mut x: Scalar) -> std::io::Result<()> {
    let start = Instant::now();
    let mut sent = 0usize;
    let mut recv = 0usize;

    let pinned_server_pub = load_server_pub()?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::PermissionDenied, "No pinned server_pub.bin")
    })?;

    let mut stream = TcpStream::connect(server_addr)?;
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    println!("Client[AUTH]: Connected to {}", server_addr);

    // 1. ANONYMOUS EPHEMERAL KEY EXCHANGE (ECDHE)
    let client_sk = EphemeralSecret::random_from_rng(OsRng);
    let client_pk = X25519Public::from(&client_sk);

    send_all(&mut stream, &[MSG_AUTH_V2], &mut sent)?;
    send_all(&mut stream, client_pk.as_bytes(), &mut sent)?;
    stream.flush()?;

    let mut server_pk_bytes = [0u8; 32];
    recv_exact(&mut stream, &mut server_pk_bytes, &mut recv)?;
    let server_pk = X25519Public::from(server_pk_bytes);

    // Derive Session Keys (Matching libsodium's crypto_kx exactly)
    let shared_secret = client_sk.diffie_hellman(&server_pk);
    let mut hasher = Blake2b512::new();
    hasher.update(shared_secret.as_bytes());
    hasher.update(client_pk.as_bytes());
    hasher.update(server_pk_bytes);
    let hash = hasher.finalize();

    let mut rx_key = [0u8; 32];
    let mut tx_key = [0u8; 32];
    rx_key.copy_from_slice(&hash[0..32]);  // S->C
    tx_key.copy_from_slice(&hash[32..64]); // C->S

    let cipher_tx = ChaCha20Poly1305::new(&tx_key.into());
    let cipher_rx = ChaCha20Poly1305::new(&rx_key.into());

    // 2. ENCRYPT IDENTITY AND SCHNORR PROOF
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

    let nonce_tx_1 = Nonce::from_slice(&[0u8; 12]); // Safe for 1st msg
    let ct1 = cipher_tx.encrypt(nonce_tx_1, payload1.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "encryption failed"))?;

    let len1 = (ct1.len() as u32).to_le_bytes();
    send_all(&mut stream, &len1, &mut sent)?;
    send_all(&mut stream, &ct1, &mut sent)?;
    stream.flush()?;

    // 3. READ ENCRYPTED SERVER RESPONSE
    let mut len_buf = [0u8; 4];
    recv_exact(&mut stream, &mut len_buf, &mut recv)?;
    let rx_len = u32::from_le_bytes(len_buf) as usize;

    let mut rx_ct = vec![0u8; rx_len];
    recv_exact(&mut stream, &mut rx_ct, &mut recv)?;

    let nonce_rx = Nonce::from_slice(&[0u8; 12]); // Safe on RX key
    let pt2 = cipher_rx.decrypt(nonce_rx, rx_ct.as_ref())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::Other, "decryption failed"))?;

    if pt2.len() != 192 {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid server payload"));
    }

    let mut s_pub_bytes = [0u8; 32]; s_pub_bytes.copy_from_slice(&pt2[0..32]);
    let mut a_s_bytes = [0u8; 32]; a_s_bytes.copy_from_slice(&pt2[32..64]);
    let mut s_s_bytes = [0u8; 32]; s_s_bytes.copy_from_slice(&pt2[64..96]);
    let mut nonce_s = [0u8; 32]; nonce_s.copy_from_slice(&pt2[96..128]);
    let mut eph_s_bytes = [0u8; 32]; eph_s_bytes.copy_from_slice(&pt2[128..160]);
    let mut tag_s = [0u8; 32]; tag_s.copy_from_slice(&pt2[160..192]);

    let server_static_pub = CompressedRistretto(s_pub_bytes).decompress().unwrap();
    let a_s = CompressedRistretto(a_s_bytes).decompress().unwrap();
    let s_s = Scalar::from_canonical_bytes(s_s_bytes).unwrap();
    let eph_s = CompressedRistretto(eph_s_bytes).decompress().unwrap();

    // Verify pinned server identity
    if server_static_pub.compress().to_bytes() != pinned_server_pub.compress().to_bytes() {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Server pubkey mismatch"));
    }

    let ok = schnorr_verify_server(&server_static_pub, &a_s, &s_s, &nonce_s, &eph_s);
    println!("Client[AUTH]: Server Schnorr authentication = {}", ok);
    if !ok {
        eprintln!("Client[AUTH]: Authentication FAILED");
        x.zeroize();
        eph_secret.zeroize();
        return Ok(());
    }

    let session_key = derive_session_key(&eph_secret, &eph_s, &nonce_c, &nonce_s, &device_id, &eph_pub, &eph_s);
    let th = kc_transcript_hash(&device_id, &a_c, &s_c, &nonce_c, &eph_pub, &server_static_pub, &a_s, &s_s, &nonce_s, &eph_s);
    let (k_s2c, k_c2s) = derive_kc_keys(&session_key, &th);

    let expected_tag_s = hmac_tag(&k_s2c, b"server finished", &th);
    if expected_tag_s != tag_s {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "tag_s mismatch"));
    }
    println!("Client[AUTH]: Key confirmation (server finished) OK");

    // 4. SEND ENCRYPTED CLIENT CONFIRMATION (tag_c)
    let tag_c = hmac_tag(&k_c2s, b"client finished", &th);
    
    // MUST increment nonce because we are reusing the TX key
    let mut nonce_tx_2_bytes = [0u8; 12];
    nonce_tx_2_bytes[0] = 1; 
    let nonce_tx_2 = Nonce::from_slice(&nonce_tx_2_bytes);

    let ct3 = cipher_tx.encrypt(nonce_tx_2, tag_c.as_ref()).unwrap();
    let len3 = (ct3.len() as u32).to_le_bytes();
    send_all(&mut stream, &len3, &mut sent)?;
    send_all(&mut stream, &ct3, &mut sent)?;
    stream.flush()?;

    println!("Client[AUTH]: Sent encrypted client finished tag");

    x.zeroize();
    eph_secret.zeroize();

    println!("CLIENT METRICS -> Duration: {:?}, Sent: {} bytes, Received: {} bytes", start.elapsed(), sent, recv);
    Ok(())
}

// ----------------------------------------------------
// MAIN
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
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--server missing value"));
                }
                server_addr = args[i + 1].clone();
                i += 2;
            }
            "--setup" => {
                do_setup_flag = true;
                i += 1;
            }
            "--pin-server-pub" => {
                if i + 1 >= args.len() {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "--pin-server-pub missing value"));
                }
                let hex_str = args[i + 1].clone();
                let decoded = hex::decode(&hex_str).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid hex"))?;
                if decoded.len() != 32 {
                    return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "pinned key must be 32 bytes"));
                }
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(&decoded);
                let p = CompressedRistretto(key_bytes).decompress().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid ristretto point")
                })?;
                save_server_pub(&p)?;
                println!("Client: Successfully pinned server pubkey out-of-band.");
                i += 2;
            }
            _ => {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "unknown argument"));
            }
        }
    }

    if !creds_exist() && !do_setup_flag {
        eprintln!(
            "Client: device root missing ({}). Refusing AUTH. Run with --setup to enroll.",
            DEVICE_ROOT_FILE
        );
        return Ok(());
    }

    if do_setup_flag {
        if creds_exist() {
            println!("Client[SETUP]: Using existing device root for setup (idempotent).");
        } else {
            println!("Client[SETUP]: No device root found; generating NEW device root (re-enroll).");
        }
        let (device_id, x) = load_device_creds_from_root()?;
        do_setup(&server_addr, device_id, x)?;
        return Ok(());
    }

    let (device_id, x) = load_device_creds_from_root()?;
    do_auth_v2(&server_addr, device_id, x)
}