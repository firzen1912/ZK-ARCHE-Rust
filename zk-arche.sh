#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BASE_STATE_DIR="/var/lib/iot-auth"
SERVER_STATE_DIR="${BASE_STATE_DIR}/server"
CLIENT_STATE_DIR="${BASE_STATE_DIR}/client"
GENERATED_DIR="${BASE_STATE_DIR}/generated"

SERVER_BIN="${PROJECT_ROOT}/target/release/server"
CLIENT_BIN="${PROJECT_ROOT}/target/release/client"

CLIENT_DEVICE_ROOT="${CLIENT_STATE_DIR}/device_root.bin"
CLIENT_SERVER_PUB="${CLIENT_STATE_DIR}/server_pub.bin"
CLIENT_DEVICE_CERT="${CLIENT_STATE_DIR}/device_cert.pem"
CLIENT_DEVICE_KEY="${CLIENT_STATE_DIR}/device_key.pem"
CLIENT_CA_CERT="${CLIENT_STATE_DIR}/ca_cert.pem"

SERVER_SK_FILE="${SERVER_STATE_DIR}/server_sk.bin"
SERVER_PUB_HEX_FILE="${SERVER_STATE_DIR}/server_pub.hex"
SERVER_REGISTRY="${SERVER_STATE_DIR}/registry.bin"
SERVER_REGISTRY_BAK="${SERVER_STATE_DIR}/registry.bak"
SERVER_REPLAY_CACHE="${SERVER_STATE_DIR}/replay_cache.bin"
SERVER_OFFLINE_COUNTERS="${SERVER_STATE_DIR}/offline_counters.bin"

OFFLINE_PROOF_FILE="${GENERATED_DIR}/offline_proof.bin"
OFFLINE_REQUEST_FILE="${GENERATED_DIR}/offline_request.bin"
DEFAULT_OFFLINE_AUDIENCE="gateway-A"
DEFAULT_OFFLINE_SCOPE="telemetry_upload"
DEFAULT_OFFLINE_EXPIRES_IN=120
CLIENT_CONTINUITY_PROOF_FILE="${GENERATED_DIR}/client_continuity_proof.bin"
SERVER_CONTINUITY_PROOF_FILE="${GENERATED_DIR}/server_continuity_proof.bin"
DEFAULT_CONTINUITY_EXPIRES_IN=300

DEFAULT_DAEMON_INTERVAL_SECS=5
DEFAULT_DAEMON_RUNTIME_SECS=30
CLIENT_DAEMON_LOG="${GENERATED_DIR}/client-daemon.log"
SERVER_LOG_FILE="${GENERATED_DIR}/server.log"
SERVER_RESTART_LOG_FILE="${GENERATED_DIR}/server-restart.log"
SERVER_PID_FILE="${GENERATED_DIR}/server.pid"
CLIENT_DAEMON_PID_FILE="${GENERATED_DIR}/client-daemon.pid"

SERVER_CERT="${SERVER_STATE_DIR}/server_cert.pem"
SERVER_CERT_KEY="${SERVER_STATE_DIR}/server_cert_key.pem"
SERVER_CA_CERT="${SERVER_STATE_DIR}/ca_cert.pem"
SERVER_CA_KEY="${SERVER_STATE_DIR}/ca_key.pem"

GEN_DEVICE_CERT="${GENERATED_DIR}/device_cert.pem"
GEN_DEVICE_KEY="${GENERATED_DIR}/device_key.pem"

SERVER_CSR="${GENERATED_DIR}/server.csr"
DEVICE_CSR="${GENERATED_DIR}/device.csr"
CA_SERIAL="${GENERATED_DIR}/ca_cert.srl"
OPENSSL_EXT="${GENERATED_DIR}/openssl-ext.cnf"

IDENT_HELPER_SRC="${GENERATED_DIR}/.zk_arche_ident_helper.c"
IDENT_HELPER_BIN="${GENERATED_DIR}/.zk_arche_ident_helper"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
  _B='\033[0;34m' _C='\033[0;36m' _W='\033[1;37m' _N='\033[0m'
else
  _R='' _G='' _Y='' _B='' _C='' _W='' _N=''
fi

log_info() { echo -e "${_B}[INFO]${_N}  $*"; }
log_ok() { echo -e "${_G}[OK]${_N}    $*"; }
log_warn() { echo -e "${_Y}[WARN]${_N}  $*"; }
log_error() { echo -e "${_R}[ERROR]${_N} $*" >&2; }
log_step() { echo -e "${_C}[STEP]${_N}  $*"; }
log_header() { echo -e "\n${_W}==> $*${_N}"; }
log_val() { echo -e "    ${_Y}$1${_N}  $2"; }
die() { log_error "$*"; exit 1; }

require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin
Build first with: ./zk-arche.sh build"
}

require_file() {
  local f="$1"
  sudo test -f "$f" || die "Required file not found: $f"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

validate_hex32() {
  local val="$1" label="$2"
  [[ "$val" =~ ^[0-9a-fA-F]{64}$ ]] || die "$label must be exactly 32 bytes (64 hex characters)"
}

sudo_write_file() {
  local src="$1" dst="$2" mode="$3"
  sudo install -m "$mode" "$src" "$dst"
}

secure_delete() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u "$path"
  else
    dd if=/dev/urandom of="$path" bs=1 count="$(wc -c < "$path")" conv=notrunc 2>/dev/null || true
    rm -f "$path"
  fi
}

ensure_state_dirs() {
  sudo mkdir -p "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR" "$GENERATED_DIR"
  sudo chmod 700 "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR" "$GENERATED_DIR"
}

ensure_client_state_dir() {
  ensure_state_dirs
}

ensure_server_state_dir() {
  ensure_state_dirs
}

ensure_client_root() {
  ensure_state_dirs
  if ! sudo test -f "$CLIENT_DEVICE_ROOT"; then
    log_step "Creating client device root at $CLIENT_DEVICE_ROOT"
    local tmp
    tmp="$(mktemp)"
    openssl rand 32 > "$tmp"
    sudo_write_file "$tmp" "$CLIENT_DEVICE_ROOT" 600
    secure_delete "$tmp"
    log_ok "Created client device root"
  fi
}

build_ident_helper() {
  require_cmd gcc
  cat > "$IDENT_HELPER_SRC" <<'EOF_HELPER'
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void bin2hex_lower(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    sodium_bin2hex(out, out_len, in, in_len);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <device_root.bin>\n", argv[0]);
        return 1;
    }
    if (sodium_init() < 0) {
        fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }

    uint8_t root[32], device_id[32], wide[64], x[32], device_pub[32];
    size_t n = fread(root, 1, sizeof root, f);
    fclose(f);
    if (n != sizeof root) {
        fprintf(stderr, "device root must be exactly 32 bytes\n");
        return 1;
    }

    crypto_generichash_state st;

    crypto_generichash_init(&st, NULL, 0, 32);
    crypto_generichash_update(&st, (const unsigned char *)"device-id", 9);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, device_id, 32);

    crypto_generichash_init(&st, NULL, 0, 64);
    crypto_generichash_update(&st, (const unsigned char *)"device-auth-v1", 14);
    crypto_generichash_update(&st, root, 32);
    crypto_generichash_final(&st, wide, 64);

    crypto_core_ristretto255_scalar_reduce(x, wide);
    crypto_scalarmult_ristretto255_base(device_pub, x);

    char id_hex[65], pub_hex[65];
    bin2hex_lower(device_id, 32, id_hex, sizeof id_hex);
    bin2hex_lower(device_pub, 32, pub_hex, sizeof pub_hex);

    printf("%s %s\n", id_hex, pub_hex);

    sodium_memzero(root, sizeof root);
    sodium_memzero(wide, sizeof wide);
    sodium_memzero(x, sizeof x);
    return 0;
}
EOF_HELPER
  gcc -O2 -std=c11 -Wall -Wextra "$IDENT_HELPER_SRC" -o "$IDENT_HELPER_BIN" -lsodium
}

derive_client_identity_hex() {
  ensure_client_root
  [[ -x "$IDENT_HELPER_BIN" ]] || build_ident_helper
  sudo "$IDENT_HELPER_BIN" "$CLIENT_DEVICE_ROOT"
}

derive_server_pub_hex() {
  require_bin "$SERVER_BIN"
  ensure_server_state_dir
  (
    cd "$SERVER_STATE_DIR"
    sudo "$SERVER_BIN" --print-pubkey
  )
}

write_openssl_ext_file() {
  local device_id="$1"
  local device_pub="$2"
  local server_pub="$3"

  cat > "$OPENSSL_EXT" <<EOF
[ ca_ext ]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

[ server_ext ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
1.3.6.1.4.1.55555.1.2 = ASN1:UTF8String:${server_pub}

[ device_ext ]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
1.3.6.1.4.1.55555.1.1 = ASN1:UTF8String:${device_id}
1.3.6.1.4.1.55555.1.3 = ASN1:UTF8String:${device_pub}
EOF
}

print_cert_summary() {
  local cert="$1" label="$2"
  if [[ -f "$cert" ]]; then
    log_header "$label certificate summary"
    openssl x509 -in "$cert" -noout -subject -issuer -dates
    echo
    openssl x509 -in "$cert" -noout -text | grep -A 3 "X509v3 Extended Key Usage" || true
    openssl x509 -in "$cert" -noout -text | grep -A 8 "1.3.6.1.4.1.55555" || true
  fi
}

generate_bound_certs() {
  require_bin "$SERVER_BIN"
  require_cmd openssl

  ensure_state_dirs
  ensure_client_root

  local derived
  derived="$(derive_client_identity_hex)"
  local device_id device_pub server_pub
  device_id="$(awk '{print $1}' <<<"$derived")"
  device_pub="$(awk '{print $2}' <<<"$derived")"
  server_pub="$(derive_server_pub_hex)"

  validate_hex32 "$device_id" "device_id"
  validate_hex32 "$device_pub" "device_pub"
  validate_hex32 "$server_pub" "server_pub"

  write_openssl_ext_file "$device_id" "$device_pub" "$server_pub"

  log_header "Generating CA, server cert, and device cert"
  log_val "device_id:" "$device_id"
  log_val "device_pub:" "$device_pub"
  log_val "server_pub:" "$server_pub"

  rm -f "$SERVER_CSR" "$DEVICE_CSR" "$CA_SERIAL" "$GEN_DEVICE_CERT" "$GEN_DEVICE_KEY"
  sudo rm -f "$SERVER_CA_KEY" "$SERVER_CA_CERT" "$SERVER_CERT" "$SERVER_CERT_KEY" \
             "$SERVER_PUB_HEX_FILE" "${SERVER_STATE_DIR}/ca_cert.srl"

  openssl genpkey -algorithm Ed25519 -out "$SERVER_CA_KEY.tmp" >/dev/null 2>&1

  openssl req -x509 -new -key "$SERVER_CA_KEY.tmp" \
    -out "$SERVER_CA_CERT.tmp" -days 365 \
    -subj "/CN=ZK-ARCHE Demo CA" \
    -extensions ca_ext -config "$OPENSSL_EXT" >/dev/null 2>&1

  openssl genpkey -algorithm Ed25519 -out "$SERVER_CERT_KEY.tmp" >/dev/null 2>&1

  openssl req -new -key "$SERVER_CERT_KEY.tmp" -out "$SERVER_CSR" \
    -subj "/CN=zk-arche-server/OU=${server_pub}" >/dev/null 2>&1

  openssl x509 -req -in "$SERVER_CSR" \
    -CA "$SERVER_CA_CERT.tmp" -CAkey "$SERVER_CA_KEY.tmp" -CAcreateserial \
    -out "$SERVER_CERT.tmp" -days 30 \
    -extfile "$OPENSSL_EXT" -extensions server_ext >/dev/null 2>&1

  if [[ -f "./ca_cert.srl" ]]; then
    mv -f "./ca_cert.srl" "$CA_SERIAL"
  fi

  openssl genpkey -algorithm Ed25519 -out "$GEN_DEVICE_KEY" >/dev/null 2>&1

  openssl req -new -key "$GEN_DEVICE_KEY" -out "$DEVICE_CSR" \
    -subj "/CN=${device_id}/OU=${device_pub}" >/dev/null 2>&1

  openssl x509 -req -in "$DEVICE_CSR" \
    -CA "$SERVER_CA_CERT.tmp" -CAkey "$SERVER_CA_KEY.tmp" -CAcreateserial \
    -out "$GEN_DEVICE_CERT" -days 30 \
    -extfile "$OPENSSL_EXT" -extensions device_ext >/dev/null 2>&1

  if [[ -f "./ca_cert.srl" ]]; then
    mv -f "./ca_cert.srl" "$CA_SERIAL"
  fi

  printf '%s\n' "$server_pub" > "$SERVER_PUB_HEX_FILE.tmp"

  sudo_write_file "$SERVER_CA_KEY.tmp" "$SERVER_CA_KEY" 600
  sudo_write_file "$SERVER_CA_CERT.tmp" "$SERVER_CA_CERT" 644
  sudo_write_file "$SERVER_CERT_KEY.tmp" "$SERVER_CERT_KEY" 600
  sudo_write_file "$SERVER_CERT.tmp" "$SERVER_CERT" 644
  sudo_write_file "$SERVER_PUB_HEX_FILE.tmp" "$SERVER_PUB_HEX_FILE" 644

  secure_delete "$SERVER_CA_KEY.tmp"
  rm -f "$SERVER_CA_CERT.tmp" "$SERVER_CERT_KEY.tmp" "$SERVER_CERT.tmp" "$SERVER_PUB_HEX_FILE.tmp"

  chmod 600 "$GEN_DEVICE_KEY" 2>/dev/null || true
  chmod 644 "$GEN_DEVICE_CERT" 2>/dev/null || true

  print_cert_summary "$SERVER_CERT" "Server"
  print_cert_summary "$GEN_DEVICE_CERT" "Device"

  rm -f "$OPENSSL_EXT"

  log_ok "Generated matching CA/server/device certs"
  log_val "CA cert:" "$SERVER_CA_CERT"
  log_val "Server cert:" "$SERVER_CERT"
  log_val "Server key:" "$SERVER_CERT_KEY"
  log_val "Device cert:" "$GEN_DEVICE_CERT"
  log_val "Device key:" "$GEN_DEVICE_KEY"
  log_warn "CA private key is on disk at: $SERVER_CA_KEY"
  log_warn "For production use, run './zk-arche.sh export-ca-key' to move it offline."
}

install_client_certs_from_generated() {
  require_file "$GEN_DEVICE_CERT"
  require_file "$GEN_DEVICE_KEY"
  require_file "$SERVER_CA_CERT"

  ensure_client_state_dir
  sudo install -m 644 "$GEN_DEVICE_CERT" "$CLIENT_DEVICE_CERT"
  sudo install -m 600 "$GEN_DEVICE_KEY" "$CLIENT_DEVICE_KEY"
  sudo install -m 644 "$SERVER_CA_CERT" "$CLIENT_CA_CERT"

  log_step "Securely removing device private key from generated dir..."
  secure_delete "$GEN_DEVICE_KEY"
  log_ok "Client cert material installed in $CLIENT_STATE_DIR"
  log_ok "Device private key removed from $GENERATED_DIR"
}

ensure_existing_server_material() {
  ensure_server_state_dir
  require_file "$SERVER_CA_CERT"
  require_file "$SERVER_CERT"
  require_file "$SERVER_CERT_KEY"
}

ensure_existing_client_material() {
  ensure_client_state_dir
  require_file "$CLIENT_DEVICE_ROOT"
  require_file "$CLIENT_DEVICE_CERT"
  require_file "$CLIENT_DEVICE_KEY"
  require_file "$CLIENT_CA_CERT"
}

ensure_existing_demo_material() {
  require_bin "$SERVER_BIN"
  require_bin "$CLIENT_BIN"
  ensure_existing_server_material
  ensure_existing_client_material
}

usage() {
  cat <<EOF2

${_W}ZK-ARCHE automation script (Rust version, /var/lib/iot-auth layout)${_N}

${_C}USAGE${_N}
  ./zk-arche.sh <command> [options]

${_C}BUILD${_N}
  build

${_C}CERTIFICATE COMMANDS${_N}
  make-certs
  install-client-certs
  check-server-certs
  check-client-certs
  export-ca-key

${_C}SERVER COMMANDS${_N}
  start-server <bind_addr> [opts]
  server-local <bind_addr> [--pairing-token <token>] [--pairing-seconds <n>]
  reset-server

${_C}CLIENT COMMANDS${_N}
  setup-device <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup]
  auth-device <server_ip:port>
  auth-device-daemon <server_ip:port> [--interval-secs <n>]
  make-offline-proof [--output <file>] [--audience <name>] [--scope <scope>] [--expires-in <1..300>] [--request-file <path>|--request-text <text>|--request-hash <hex>]
  show-pinned-key
  pin-server <server_pub_hex>
  make-client-continuity-proof [--output <file>] [--expires-in <1..300>]
  verify-server-continuity-proof [--proof <file>]
  reset-client
  status

${_C}OFFLINE TEST COMMANDS${_N}
  verify-offline-proof [--proof <file>] [--audience <name>] [--allow-scope <scope>]...
  offline-local [--audience <name>] [--scope <scope>] [--expires-in <1..300>] [--request-file <path>|--request-text <text>|--request-hash <hex>]
  make-server-continuity-proof --peer-id <client_device_id_hex> [--output <file>] [--expires-in <1..300>]
  verify-client-continuity-proof [--proof <file>]
  continuity-local [--expires-in <1..300>]

${_C}COMBINED FLOWS${_N}
  client-local <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup]
  client-daemon-local <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup] [--interval-secs <n>]
  daemon-local <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup] [--interval-secs <n>] [--runtime-secs <n>]
  full-device-onboard <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup]
  reset-all

${_C}RECOMMENDED LOCAL TEST FLOW${_N}
  ./zk-arche.sh build
  sudo ./zk-arche.sh reset-all
  ./zk-arche.sh make-certs
  sudo ./zk-arche.sh server-local 127.0.0.1:4000
  sudo ./zk-arche.sh client-local 127.0.0.1:4000
  sudo ./zk-arche.sh auth-device-daemon 127.0.0.1:4000 --interval-secs 5
  ./zk-arche.sh offline-local --request-text "cached telemetry payload"
  ./zk-arche.sh continuity-local

EOF2
}

cmd_build() {
  require_cmd cargo
  log_header "Building Rust binaries"
  (cd "$PROJECT_ROOT" && cargo build --release)
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
}

cmd_make_certs() {
  require_bin "$SERVER_BIN"
  require_bin "$CLIENT_BIN"
  generate_bound_certs
  install_client_certs_from_generated

  local server_pub
  server_pub="$(derive_server_pub_hex)"
  cmd_pin_server "$server_pub"
}

cmd_install_client_certs() {
  log_header "Installing client cert material from existing generated files"
  require_bin "$CLIENT_BIN"
  install_client_certs_from_generated
}

cmd_check_server_certs() {
  log_header "Server certificate files"
  _status_file "$SERVER_CA_CERT" "ca cert"
  _status_file "$SERVER_CA_KEY" "ca key"
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"
  _status_file "$SERVER_SK_FILE" "server static key"
  _status_file "$SERVER_REGISTRY" "device registry"
  _status_file "$SERVER_REPLAY_CACHE" "replay cache"
  _status_file "$SERVER_OFFLINE_COUNTERS" "offline counter store"
  _status_file "$SERVER_PUB_HEX_FILE" "server pub hex"
}

cmd_check_client_certs() {
  log_header "Client certificate files"
  _status_file "$CLIENT_DEVICE_ROOT" "device root"
  _status_file "$CLIENT_DEVICE_CERT" "device cert"
  _status_file "$CLIENT_DEVICE_KEY" "device key"
  _status_file "$CLIENT_CA_CERT" "ca cert"
  _status_file "$CLIENT_SERVER_PUB" "pinned server pub"
}

cmd_start_server() {
  require_bin "$SERVER_BIN"
  [[ $# -ge 1 ]] || die "start-server requires <bind_addr>"
  local bind_addr="$1"; shift

  ensure_existing_server_material

  log_header "Starting server"
  log_info "Bind: $bind_addr"
  [[ $# -gt 0 ]] && log_info "Flags: $*"

  cd "$SERVER_STATE_DIR"
  exec sudo "$SERVER_BIN" --bind "$bind_addr" "$@"
}

cmd_server_local() {
  require_bin "$SERVER_BIN"
  [[ $# -ge 1 ]] || die "server-local requires <bind_addr>"
  local bind_addr="$1"; shift
  local extra_flags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        extra_flags+=(--pairing-token "$2"); shift 2 ;;
      --pairing-seconds)
        [[ $# -ge 2 ]] || die "--pairing-seconds requires a value"
        extra_flags+=(--pairing-seconds "$2"); shift 2 ;;
      *) die "server-local: unknown option: $1" ;;
    esac
  done

  ensure_existing_demo_material

  log_header "Local test mode — server"
  log_info "Bind: $bind_addr"
  log_info "Pairing: enabled"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  echo
  log_info "In a second terminal run:"
  echo -e "    ${_Y}sudo ./zk-arche.sh client-local $bind_addr${_N}"
  echo -e "    ${_Y}sudo ./zk-arche.sh auth-device-daemon $bind_addr --interval-secs 5${_N}"
  echo

  cd "$SERVER_STATE_DIR"
  exec sudo "$SERVER_BIN" --bind "$bind_addr" --pairing "${extra_flags[@]}"
}

cmd_pin_server() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "pin-server requires <server_pub_hex>"
  local server_pub="$1"
  validate_hex32 "$server_pub" "server_pub_hex"

  log_step "Pinning server public key..."
  sudo "$CLIENT_BIN" --pin-server-pub "$server_pub"

  local tmp
  tmp="$(mktemp)"
  printf '%s\n' "$server_pub" > "$tmp"
  sudo_write_file "$tmp" "$SERVER_PUB_HEX_FILE" 644
  rm -f "$tmp"

  log_ok "Server public key pinned"
}

cmd_export_ca_key() {
  if ! sudo test -f "$SERVER_CA_KEY"; then
    log_warn "CA key not found at: $SERVER_CA_KEY"
    return
  fi
  log_header "CA private key export (production hardening)"
  log_warn "Copy the key below to secure offline storage, then it will be removed from this machine."
  echo
  sudo cat "$SERVER_CA_KEY"
  echo
  log_step "Removing CA private key from server..."
  sudo shred -u "$SERVER_CA_KEY" 2>/dev/null || sudo rm -f "$SERVER_CA_KEY"
  log_ok "CA private key removed from $SERVER_STATE_DIR"
  log_warn "Store the printed key securely offline. Without it you cannot issue new device certificates."
}

cmd_setup_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "setup-device requires <server_ip:port>"
  local server_addr="$1"; shift
  local extra_flags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        extra_flags+=(--pairing-token "$2"); shift 2 ;;
      --allow-tofu-setup)
        extra_flags+=(--allow-tofu-setup); shift ;;
      *) die "setup-device: unknown option: $1" ;;
    esac
  done

  ensure_existing_client_material

  log_header "Device setup (mutual certificate onboarding)"
  log_info "Server: $server_addr"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  sudo "$CLIENT_BIN" --server "$server_addr" --setup "${extra_flags[@]}"

  if sudo test -f "$CLIENT_SERVER_PUB"; then
    local pinned_hex
    pinned_hex="$(sudo xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Device enrolled. Operational server key present."
    [[ -n "$pinned_hex" ]] && log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Device enrolled"
  fi
}

cmd_auth_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"
  ensure_existing_client_material
  log_header "Device authentication"
  log_info "Server: $1"
  sudo "$CLIENT_BIN" --server "$1"
  log_ok "Authentication complete"
}

cmd_auth_device_daemon() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "auth-device-daemon requires <server_ip:port>"

  local server_addr="$1"; shift
  local interval_secs="$DEFAULT_DAEMON_INTERVAL_SECS"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --interval-secs)
        [[ $# -ge 2 ]] || die "--interval-secs requires a value"
        interval_secs="$2"; shift 2 ;;
      *)
        die "auth-device-daemon: unknown option: $1" ;;
    esac
  done

  ensure_existing_client_material

  log_header "Device authentication daemon"
  log_info "Server: $server_addr"
  log_info "Interval: ${interval_secs}s"

  sudo "$CLIENT_BIN" \
    --server "$server_addr" \
    --daemon \
    --daemon-interval-secs "$interval_secs"
}

cmd_show_pinned_key() {
  if ! sudo test -f "$CLIENT_SERVER_PUB"; then
    log_warn "No pinned server key found at: $CLIENT_SERVER_PUB"
    return
  fi
  local hex
  hex="$(sudo xxd -p -c 32 "$CLIENT_SERVER_PUB")"
  log_ok "Pinned server public key:"
  log_val "File:" "$CLIENT_SERVER_PUB"
  log_val "Fingerprint:" "$hex"
}

_status_file() {
  local path="$1" label="$2"
  if sudo test -f "$path"; then
    local size
    size="$(sudo wc -c < "$path" | tr -d ' ')"
    log_ok "$label: present (${size}B)"
  else
    log_warn "$label: absent"
  fi
}

cmd_status() {
  log_header "ZK-ARCHE status (Rust version)"
  echo -e "\n${_W}Binaries${_N}"
  [[ -x "$SERVER_BIN" ]] && log_ok "server binary: $SERVER_BIN" || log_warn "server binary: not built ($SERVER_BIN)"
  [[ -x "$CLIENT_BIN" ]] && log_ok "client binary: $CLIENT_BIN" || log_warn "client binary: not built ($CLIENT_BIN)"

  echo -e "\n${_W}State root${_N}"
  log_val "path:" "$BASE_STATE_DIR"

  echo -e "\n${_W}Server state${_N}  ($SERVER_STATE_DIR)"
  _status_file "$SERVER_REGISTRY" "device registry"
  _status_file "$SERVER_REGISTRY_BAK" "device registry backup"
  _status_file "$SERVER_REPLAY_CACHE" "replay cache"
  _status_file "$SERVER_OFFLINE_COUNTERS" "offline counter store"
  _status_file "$SERVER_SK_FILE" "server static key"
  _status_file "$SERVER_CA_CERT" "ca cert"
  if sudo test -f "$SERVER_CA_KEY"; then
    log_warn "ca key: present on server (consider running 'export-ca-key' for production)"
  else
    log_ok "ca key: absent (offline — good)"
  fi
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"
  _status_file "$SERVER_PUB_HEX_FILE" "server pub hex"

  if [[ -x "$SERVER_BIN" ]]; then
    local spub
    spub="$(derive_server_pub_hex 2>/dev/null || true)"
    [[ -n "$spub" ]] && log_val "live server_pub:" "$spub"
  fi

  echo -e "\n${_W}Client state${_N}  ($CLIENT_STATE_DIR)"
  _status_file "$CLIENT_DEVICE_ROOT" "device root"
  _status_file "$CLIENT_DEVICE_CERT" "device cert"
  _status_file "$CLIENT_DEVICE_KEY" "device key"
  _status_file "$CLIENT_CA_CERT" "ca cert"
  _status_file "$CLIENT_SERVER_PUB" "pinned server pub"

  if sudo test -f "$CLIENT_DEVICE_ROOT"; then
    local derived did dpub
    derived="$(derive_client_identity_hex 2>/dev/null || true)"
    did="$(awk '{print $1}' <<<"$derived")"
    dpub="$(awk '{print $2}' <<<"$derived")"
    [[ -n "$did" ]] && log_val "device_id:" "$did"
    [[ -n "$dpub" ]] && log_val "device_pub:" "$dpub"
  fi

  if sudo test -f "$CLIENT_SERVER_PUB"; then
    local hex
    hex="$(sudo xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    [[ -n "$hex" ]] && log_val "pinned server_pub:" "$hex"
  fi

  echo -e "\n${_W}Generated files${_N}  ($GENERATED_DIR)"
  if [[ -f "$GEN_DEVICE_CERT" ]]; then _status_file "$GEN_DEVICE_CERT" "generated device cert"; else log_ok "generated device cert: absent (cleaned up — good)"; fi
  if [[ -f "$GEN_DEVICE_KEY" ]]; then
    log_warn "generated device key: present (run install-client-certs to install and remove)"
  else
    log_ok "generated device key: absent (cleaned up — good)"
  fi
  if [[ -f "$SERVER_CSR" ]]; then _status_file "$SERVER_CSR" "server csr"; else log_warn "server csr: absent"; fi
  if [[ -f "$DEVICE_CSR" ]]; then _status_file "$DEVICE_CSR" "device csr"; else log_warn "device csr: absent"; fi
  if [[ -f "$CA_SERIAL" ]]; then _status_file "$CA_SERIAL" "ca serial"; else log_warn "ca serial: absent"; fi
  if [[ -f "$OPENSSL_EXT" ]]; then _status_file "$OPENSSL_EXT" "openssl ext config"; else log_ok "openssl ext config: absent (cleaned up — good)"; fi
  if [[ -f "$OFFLINE_PROOF_FILE" ]]; then _status_file "$OFFLINE_PROOF_FILE" "offline proof artifact"; else log_warn "offline proof artifact: absent"; fi
  if [[ -f "$OFFLINE_REQUEST_FILE" ]]; then _status_file "$OFFLINE_REQUEST_FILE" "offline request sample"; else log_warn "offline request sample: absent"; fi
  if [[ -f "$CLIENT_CONTINUITY_PROOF_FILE" ]]; then _status_file "$CLIENT_CONTINUITY_PROOF_FILE" "client continuity proof"; else log_warn "client continuity proof: absent"; fi
  if [[ -f "$SERVER_CONTINUITY_PROOF_FILE" ]]; then _status_file "$SERVER_CONTINUITY_PROOF_FILE" "server continuity proof"; else log_warn "server continuity proof: absent"; fi
  if [[ -f "$CLIENT_DAEMON_LOG" ]]; then _status_file "$CLIENT_DAEMON_LOG" "client daemon log"; else log_warn "client daemon log: absent"; fi
  if [[ -f "$SERVER_LOG_FILE" ]]; then _status_file "$SERVER_LOG_FILE" "server log"; else log_warn "server log: absent"; fi
  if [[ -f "$SERVER_RESTART_LOG_FILE" ]]; then _status_file "$SERVER_RESTART_LOG_FILE" "server restart log"; else log_warn "server restart log: absent"; fi
}

cmd_client_local() {
  [[ $# -ge 1 ]] || die "client-local requires <server_ip:port>"
  local server_addr="$1"; shift
  local pairing_token_flags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        pairing_token_flags+=(--pairing-token "$2"); shift 2 ;;
      --allow-tofu-setup)
        pairing_token_flags+=(--allow-tofu-setup); shift ;;
      *) die "client-local: unknown option: $1" ;;
    esac
  done

  ensure_existing_demo_material

  log_header "Local onboarding — client terminal"
  log_info "Server: $server_addr"
  log_step "Running device setup..."
  sudo "$CLIENT_BIN" --server "$server_addr" --setup "${pairing_token_flags[@]}"
  log_ok "Setup complete"
}

cmd_client_daemon_local() {
  [[ $# -ge 1 ]] || die "client-daemon-local requires <server_ip:port>"

  local server_addr="$1"; shift
  local pairing_token_flags=()
  local interval_secs="$DEFAULT_DAEMON_INTERVAL_SECS"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        pairing_token_flags+=(--pairing-token "$2"); shift 2 ;;
      --allow-tofu-setup)
        pairing_token_flags+=(--allow-tofu-setup); shift ;;
      --interval-secs)
        [[ $# -ge 2 ]] || die "--interval-secs requires a value"
        interval_secs="$2"; shift 2 ;;
      *)
        die "client-daemon-local: unknown option: $1" ;;
    esac
  done

  ensure_existing_demo_material

  log_header "Local onboarding + daemon auth — client terminal"
  log_info "Server: $server_addr"

  log_step "Running device setup..."
  sudo "$CLIENT_BIN" --server "$server_addr" --setup "${pairing_token_flags[@]}"
  log_ok "Setup complete"

  log_step "Starting client daemon..."
  sudo "$CLIENT_BIN" \
    --server "$server_addr" \
    --daemon \
    --daemon-interval-secs "$interval_secs"
}

cmd_full_device_onboard() {
  [[ $# -ge 1 ]] || die "full-device-onboard requires <server_ip:port>"
  local server_addr="$1"; shift
  local setup_args=("$server_addr")

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        setup_args+=(--pairing-token "$2"); shift 2 ;;
      --allow-tofu-setup)
        setup_args+=(--allow-tofu-setup); shift ;;
      *) die "full-device-onboard: unknown option: $1" ;;
    esac
  done

  ensure_existing_demo_material
  cmd_setup_device "${setup_args[@]}"
}

cmd_make_offline_proof() {
  require_bin "$CLIENT_BIN"
  ensure_existing_client_material

  local output="$OFFLINE_PROOF_FILE"
  local audience="$DEFAULT_OFFLINE_AUDIENCE"
  local scope="$DEFAULT_OFFLINE_SCOPE"
  local expires_in="$DEFAULT_OFFLINE_EXPIRES_IN"
  local request_file=""
  local request_text=""
  local request_hash=""

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output)
        [[ $# -ge 2 ]] || die "--output requires a value"
        output="$2"; shift 2 ;;&
      --audience)
        [[ $# -ge 2 ]] || die "--audience requires a value"
        audience="$2"; shift 2 ;;&
      --scope)
        [[ $# -ge 2 ]] || die "--scope requires a value"
        scope="$2"; shift 2 ;;&
      --expires-in)
        [[ $# -ge 2 ]] || die "--expires-in requires a value"
        expires_in="$2"; shift 2 ;;&
      --request-file)
        [[ $# -ge 2 ]] || die "--request-file requires a value"
        request_file="$2"; shift 2 ;;&
      --request-text)
        [[ $# -ge 2 ]] || die "--request-text requires a value"
        request_text="$2"; shift 2 ;;&
      --request-hash)
        [[ $# -ge 2 ]] || die "--request-hash requires a value"
        request_hash="$2"; shift 2 ;;&
      *) die "make-offline-proof: unknown option: $1" ;;&
    esac
  done

  local req_args=()
  if [[ -n "$request_file" ]]; then
    [[ -f "$request_file" ]] || die "Request file not found: $request_file"
    req_args=(--request-file "$request_file")
  elif [[ -n "$request_text" ]]; then
    ensure_state_dirs
    printf '%s' "$request_text" > "$OFFLINE_REQUEST_FILE"
    chmod 600 "$OFFLINE_REQUEST_FILE" 2>/dev/null || true
    req_args=(--request-file "$OFFLINE_REQUEST_FILE")
  elif [[ -n "$request_hash" ]]; then
    validate_hex32 "$request_hash" "request_hash"
    req_args=(--request-hash "$request_hash")
  else
    ensure_state_dirs
    printf '%s' 'offline fallback request' > "$OFFLINE_REQUEST_FILE"
    chmod 600 "$OFFLINE_REQUEST_FILE" 2>/dev/null || true
    req_args=(--request-file "$OFFLINE_REQUEST_FILE")
  fi

  mkdir -p "$(dirname "$output")"

  log_header "Build offline proof artifact"
  log_info "Output: $output"
  log_info "Audience: $audience"
  log_info "Scope: $scope"
  log_info "Expires in: ${expires_in}s"

  sudo "$CLIENT_BIN" \
    --make-offline-proof "$output" \
    --audience "$audience" \
    --scope "$scope" \
    --offline-expires-in "$expires_in" \
    "${req_args[@]}"

  log_ok "Offline proof written: $output"
}

cmd_verify_offline_proof() {
  require_bin "$SERVER_BIN"
  ensure_existing_server_material

  local proof="$OFFLINE_PROOF_FILE"
  local audience="$DEFAULT_OFFLINE_AUDIENCE"
  local scopes=("$DEFAULT_OFFLINE_SCOPE")

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proof)
        [[ $# -ge 2 ]] || die "--proof requires a value"
        proof="$2"; shift 2 ;;&
      --audience)
        [[ $# -ge 2 ]] || die "--audience requires a value"
        audience="$2"; shift 2 ;;&
      --allow-scope|--allow-offline-scope)
        [[ $# -ge 2 ]] || die "$1 requires a value"
        scopes+=("$2"); shift 2 ;;&
      *) die "verify-offline-proof: unknown option: $1" ;;&
    esac
  done

  [[ -f "$proof" ]] || die "Offline proof file not found: $proof"

  local allow_args=()
  local uniq_scopes
  mapfile -t uniq_scopes < <(printf '%s\n' "${scopes[@]}" | awk 'NF && !seen[$0]++')
  for s in "${uniq_scopes[@]}"; do
    allow_args+=(--allow-offline-scope "$s")
  done

  log_header "Verify offline proof artifact"
  log_info "Proof: $proof"
  log_info "Audience: $audience"
  log_info "Allowed scopes: ${uniq_scopes[*]}"

  (cd "$SERVER_STATE_DIR" && sudo "$SERVER_BIN" --verify-offline-proof "$proof" --audience "$audience" "${allow_args[@]}")

  log_ok "Offline proof verification succeeded"
}

cmd_offline_local() {
  local mk_args=()
  local verify_args=()
  local output="$OFFLINE_PROOF_FILE"
  local audience="$DEFAULT_OFFLINE_AUDIENCE"
  local scope="$DEFAULT_OFFLINE_SCOPE"
  local expires_in="$DEFAULT_OFFLINE_EXPIRES_IN"
  local request_mode=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output) [[ $# -ge 2 ]] || die "--output requires a value"; output="$2"; shift 2 ;;&
      --audience) [[ $# -ge 2 ]] || die "--audience requires a value"; audience="$2"; shift 2 ;;&
      --scope) [[ $# -ge 2 ]] || die "--scope requires a value"; scope="$2"; shift 2 ;;&
      --expires-in) [[ $# -ge 2 ]] || die "--expires-in requires a value"; expires_in="$2"; shift 2 ;;&
      --request-file|--request-text|--request-hash)
        [[ $# -ge 2 ]] || die "$1 requires a value"
        request_mode=("$1" "$2"); shift 2 ;;&
      *) die "offline-local: unknown option: $1" ;;&
    esac
  done

  mk_args=(--output "$output" --audience "$audience" --scope "$scope" --expires-in "$expires_in")
  if [[ ${#request_mode[@]} -gt 0 ]]; then
    mk_args+=("${request_mode[@]}")
  fi
  verify_args=(--proof "$output" --audience "$audience" --allow-scope "$scope")

  log_header "Offline fallback local test"
  cmd_make_offline_proof "${mk_args[@]}"
  cmd_verify_offline_proof "${verify_args[@]}"
}

cmd_make_client_continuity_proof() {
  require_bin "$CLIENT_BIN"
  ensure_existing_client_material
  local output="$CLIENT_CONTINUITY_PROOF_FILE"
  local expires_in="$DEFAULT_CONTINUITY_EXPIRES_IN"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output) [[ $# -ge 2 ]] || die "--output requires a value"; output="$2"; shift 2 ;;
      --expires-in) [[ $# -ge 2 ]] || die "--expires-in requires a value"; expires_in="$2"; shift 2 ;;
      *) die "make-client-continuity-proof: unknown option: $1" ;;
    esac
  done
  mkdir -p "$(dirname "$output")"
  log_header "Build client continuity proof"
  log_info "Output: $output"
  log_info "Expires in: ${expires_in}s"
  sudo "$CLIENT_BIN" --make-client-continuity-proof "$output" --continuity-expires-in "$expires_in"
  log_ok "Client continuity proof written: $output"
}

cmd_verify_server_continuity_proof() {
  require_bin "$CLIENT_BIN"
  ensure_existing_client_material
  local proof="$SERVER_CONTINUITY_PROOF_FILE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proof) [[ $# -ge 2 ]] || die "--proof requires a value"; proof="$2"; shift 2 ;;
      *) die "verify-server-continuity-proof: unknown option: $1" ;;
    esac
  done
  [[ -f "$proof" ]] || die "Server continuity proof file not found: $proof"
  log_header "Verify server continuity proof"
  log_info "Proof: $proof"
  sudo "$CLIENT_BIN" --verify-server-continuity-proof "$proof"
  log_ok "Server continuity proof verification succeeded"
}

cmd_make_server_continuity_proof() {
  require_bin "$SERVER_BIN"
  ensure_existing_server_material
  local output="$SERVER_CONTINUITY_PROOF_FILE"
  local expires_in="$DEFAULT_CONTINUITY_EXPIRES_IN"
  local peer_id=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output) [[ $# -ge 2 ]] || die "--output requires a value"; output="$2"; shift 2 ;;
      --expires-in) [[ $# -ge 2 ]] || die "--expires-in requires a value"; expires_in="$2"; shift 2 ;;
      --peer-id) [[ $# -ge 2 ]] || die "--peer-id requires a value"; peer_id="$2"; shift 2 ;;
      *) die "make-server-continuity-proof: unknown option: $1" ;;
    esac
  done
  [[ -n "$peer_id" ]] || die "make-server-continuity-proof requires --peer-id <client_device_id_hex>"
  validate_hex32 "$peer_id" "peer-id"
  mkdir -p "$(dirname "$output")"
  log_header "Build server continuity proof"
  log_info "Output: $output"
  log_info "Peer id: $peer_id"
  log_info "Expires in: ${expires_in}s"
  (cd "$SERVER_STATE_DIR" && sudo "$SERVER_BIN" --make-server-continuity-proof "$output" --peer-id "$peer_id" --continuity-expires-in "$expires_in")
  log_ok "Server continuity proof written: $output"
}

cmd_verify_client_continuity_proof() {
  require_bin "$SERVER_BIN"
  ensure_existing_server_material
  local proof="$CLIENT_CONTINUITY_PROOF_FILE"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proof) [[ $# -ge 2 ]] || die "--proof requires a value"; proof="$2"; shift 2 ;;
      *) die "verify-client-continuity-proof: unknown option: $1" ;;
    esac
  done
  [[ -f "$proof" ]] || die "Client continuity proof file not found: $proof"
  log_header "Verify client continuity proof"
  log_info "Proof: $proof"
  (cd "$SERVER_STATE_DIR" && sudo "$SERVER_BIN" --verify-client-continuity-proof "$proof")
  log_ok "Client continuity proof verification succeeded"
}

cmd_continuity_local() {
  local expires_in="$DEFAULT_CONTINUITY_EXPIRES_IN"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --expires-in) [[ $# -ge 2 ]] || die "--expires-in requires a value"; expires_in="$2"; shift 2 ;;
      *) die "continuity-local: unknown option: $1" ;;
    esac
  done
  ensure_existing_demo_material
  local derived did
  derived="$(derive_client_identity_hex 2>/dev/null || true)"
  did="$(awk '{print $1}' <<<"$derived")"
  [[ -n "$did" ]] || die "Could not derive client device_id; make sure client state exists"

  log_header "Continuity local test"
  cmd_make_client_continuity_proof --output "$CLIENT_CONTINUITY_PROOF_FILE" --expires-in "$expires_in"
  cmd_verify_client_continuity_proof --proof "$CLIENT_CONTINUITY_PROOF_FILE"
  cmd_make_server_continuity_proof --output "$SERVER_CONTINUITY_PROOF_FILE" --peer-id "$did" --expires-in "$expires_in"
  cmd_verify_server_continuity_proof --proof "$SERVER_CONTINUITY_PROOF_FILE"
}

cmd_daemon_local() {
  [[ $# -ge 1 ]] || die "daemon-local requires <server_ip:port>"

  local bind_addr="$1"; shift
  local pairing_token=""
  local allow_tofu=0
  local interval_secs="$DEFAULT_DAEMON_INTERVAL_SECS"
  local runtime_secs="$DEFAULT_DAEMON_RUNTIME_SECS"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        pairing_token="$2"; shift 2 ;;
      --allow-tofu-setup)
        allow_tofu=1; shift ;;
      --interval-secs)
        [[ $# -ge 2 ]] || die "--interval-secs requires a value"
        interval_secs="$2"; shift 2 ;;
      --runtime-secs)
        [[ $# -ge 2 ]] || die "--runtime-secs requires a value"
        runtime_secs="$2"; shift 2 ;;
      *)
        die "daemon-local: unknown option: $1" ;;
    esac
  done

  ensure_existing_demo_material
  ensure_state_dirs
  mkdir -p "$GENERATED_DIR"

  local server_flags=(--bind "$bind_addr" --pairing)
  if [[ -n "$pairing_token" ]]; then
    server_flags+=(--pairing-token "$pairing_token")
  fi

  local setup_flags=(--server "$bind_addr" --setup)
  if [[ -n "$pairing_token" ]]; then
    setup_flags+=(--pairing-token "$pairing_token")
  fi
  if [[ "$allow_tofu" -eq 1 ]]; then
    setup_flags+=(--allow-tofu-setup)
  fi

  log_header "Automated daemon continuity test"
  log_info "Bind: $bind_addr"
  log_info "Daemon interval: ${interval_secs}s"
  log_info "Runtime after restart: ${runtime_secs}s"
  log_info "Client log: $CLIENT_DAEMON_LOG"

  rm -f "$CLIENT_DAEMON_LOG" "$SERVER_LOG_FILE" "$SERVER_RESTART_LOG_FILE" \
        "$SERVER_PID_FILE" "$CLIENT_DAEMON_PID_FILE"

  cleanup() {
    if [[ -f "$CLIENT_DAEMON_PID_FILE" ]]; then
      local cpid
      cpid="$(cat "$CLIENT_DAEMON_PID_FILE" 2>/dev/null || true)"
      [[ -n "$cpid" ]] && sudo kill "$cpid" 2>/dev/null || true
      rm -f "$CLIENT_DAEMON_PID_FILE"
    fi
    if [[ -f "$SERVER_PID_FILE" ]]; then
      local spid
      spid="$(cat "$SERVER_PID_FILE" 2>/dev/null || true)"
      [[ -n "$spid" ]] && sudo kill "$spid" 2>/dev/null || true
      rm -f "$SERVER_PID_FILE"
    fi
  }
  trap cleanup EXIT

  log_step "Starting server in background..."
  (
    cd "$SERVER_STATE_DIR"
    sudo "$SERVER_BIN" "${server_flags[@]}"
  ) > "$SERVER_LOG_FILE" 2>&1 &
  echo $! > "$SERVER_PID_FILE"
  sleep 2

  log_step "Onboarding client..."
  sudo "$CLIENT_BIN" "${setup_flags[@]}"
  log_ok "Client setup complete"

  log_step "Starting client daemon in background..."
  sudo "$CLIENT_BIN" \
    --server "$bind_addr" \
    --daemon \
    --daemon-interval-secs "$interval_secs" \
    > "$CLIENT_DAEMON_LOG" 2>&1 &
  echo $! > "$CLIENT_DAEMON_PID_FILE"
  sleep $(( interval_secs + 2 ))

  log_step "Stopping server to simulate outage..."
  sudo kill "$(cat "$SERVER_PID_FILE")"
  rm -f "$SERVER_PID_FILE"
  sleep $(( interval_secs * 2 + 2 ))

  log_step "Restarting server..."
  (
    cd "$SERVER_STATE_DIR"
    sudo "$SERVER_BIN" "${server_flags[@]}"
  ) > "$SERVER_RESTART_LOG_FILE" 2>&1 &
  echo $! > "$SERVER_PID_FILE"

  log_step "Waiting for client daemon to reconnect..."
  sleep "$runtime_secs"

  log_ok "Daemon test finished"
  log_val "Client daemon log:" "$CLIENT_DAEMON_LOG"
  log_val "Server initial log:" "$SERVER_LOG_FILE"
  log_val "Server restart log:" "$SERVER_RESTART_LOG_FILE"

  echo
  log_info "Last 40 lines of client daemon log:"
  tail -n 40 "$CLIENT_DAEMON_LOG" || true
}

cmd_reset_client() {
  log_warn "Resetting client state: $CLIENT_STATE_DIR"
  sudo rm -rf "$CLIENT_STATE_DIR"
  rm -f "$OFFLINE_PROOF_FILE" "$OFFLINE_REQUEST_FILE" "$CLIENT_CONTINUITY_PROOF_FILE" \
        "$SERVER_CONTINUITY_PROOF_FILE" "$CLIENT_DAEMON_LOG" "$CLIENT_DAEMON_PID_FILE"
  sudo mkdir -p "$CLIENT_STATE_DIR"
  sudo chmod 700 "$CLIENT_STATE_DIR"
  log_ok "Client state removed"
}

cmd_reset_server() {
  log_warn "Resetting server state in: $SERVER_STATE_DIR"
  sudo rm -f "$SERVER_REGISTRY" \
             "$SERVER_REGISTRY_BAK" \
             "$SERVER_REPLAY_CACHE" \
             "$SERVER_SK_FILE" \
             "${SERVER_STATE_DIR}/server_pub.bin" \
             "$SERVER_PUB_HEX_FILE" \
             "$SERVER_CERT" "$SERVER_CERT_KEY" \
             "$SERVER_CA_CERT" "$SERVER_CA_KEY" \
             "$SERVER_OFFLINE_COUNTERS" \
             "${SERVER_STATE_DIR}/ca_cert.srl"
  rm -f "$GEN_DEVICE_CERT" "$GEN_DEVICE_KEY" \
        "$SERVER_CSR" "$DEVICE_CSR" "$CA_SERIAL" "$OPENSSL_EXT" \
        "$OFFLINE_PROOF_FILE" "$OFFLINE_REQUEST_FILE" "$CLIENT_CONTINUITY_PROOF_FILE" \
        "$SERVER_CONTINUITY_PROOF_FILE" "$IDENT_HELPER_SRC" "$IDENT_HELPER_BIN" \
        "$SERVER_LOG_FILE" "$SERVER_RESTART_LOG_FILE" "$SERVER_PID_FILE"
  log_ok "Server state removed"
}

cmd_reset_all() {
  cmd_reset_server
  cmd_reset_client
  log_ok "All state removed"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  local cmd="$1"; shift
  case "$cmd" in
    build) cmd_build "$@" ;;
    make-certs) cmd_make_certs "$@" ;;
    install-client-certs) cmd_install_client_certs "$@" ;;
    check-server-certs) cmd_check_server_certs "$@" ;;
    check-client-certs) cmd_check_client_certs "$@" ;;
    export-ca-key) cmd_export_ca_key "$@" ;;
    start-server) cmd_start_server "$@" ;;
    server-local) cmd_server_local "$@" ;;
    pin-server) cmd_pin_server "$@" ;;
    setup-device) cmd_setup_device "$@" ;;
    auth-device) cmd_auth_device "$@" ;;
    auth-device-daemon) cmd_auth_device_daemon "$@" ;;
    make-offline-proof) cmd_make_offline_proof "$@" ;;
    verify-offline-proof) cmd_verify_offline_proof "$@" ;;
    offline-local) cmd_offline_local "$@" ;;
    make-client-continuity-proof) cmd_make_client_continuity_proof "$@" ;;
    verify-server-continuity-proof) cmd_verify_server_continuity_proof "$@" ;;
    make-server-continuity-proof) cmd_make_server_continuity_proof "$@" ;;
    verify-client-continuity-proof) cmd_verify_client_continuity_proof "$@" ;;
    continuity-local) cmd_continuity_local "$@" ;;
    show-pinned-key) cmd_show_pinned_key "$@" ;;
    status) cmd_status "$@" ;;
    client-local) cmd_client_local "$@" ;;
    client-daemon-local) cmd_client_daemon_local "$@" ;;
    daemon-local) cmd_daemon_local "$@" ;;
    full-device-onboard) cmd_full_device_onboard "$@" ;;
    reset-client) cmd_reset_client "$@" ;;
    reset-server) cmd_reset_server "$@" ;;
    reset-all) cmd_reset_all "$@" ;;
    -h|--help|help) usage ;;
    *) log_error "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"