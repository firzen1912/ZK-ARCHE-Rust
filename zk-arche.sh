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

SERVER_CERT="${SERVER_STATE_DIR}/server_cert.pem"
SERVER_CERT_KEY="${SERVER_STATE_DIR}/server_cert_key.pem"
SERVER_CA_CERT="${SERVER_STATE_DIR}/ca_cert.pem"
SERVER_CA_KEY="${SERVER_STATE_DIR}/ca_key.pem"

GEN_DEVICE_CERT="${GENERATED_DIR}/device_cert.pem"
GEN_DEVICE_KEY="${GENERATED_DIR}/device_key.pem"

SERVER_CSR="${GENERATED_DIR}/server.csr"
DEVICE_CSR="${GENERATED_DIR}/device.csr"
CA_SERIAL="${GENERATED_DIR}/ca_cert.srl"

IDENT_HELPER_SRC="${GENERATED_DIR}/.zk_arche_ident_helper.c"
IDENT_HELPER_BIN="${GENERATED_DIR}/.zk_arche_ident_helper"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
  _B='\033[0;34m' _C='\033[0;36m' _W='\033[1;37m' _N='\033[0m'
else
  _R='' _G='' _Y='' _B='' _C='' _W='' _N=''
fi

# Prints an informational log line.
log_info() { echo -e "${_B}[INFO]${_N}  $*"; }
# Prints a success log line.
log_ok() { echo -e "${_G}[OK]${_N}    $*"; }
# Prints a warning log line.
log_warn() { echo -e "${_Y}[WARN]${_N}  $*"; }
# Prints an error log line to stderr.
log_error() { echo -e "${_R}[ERROR]${_N} $*" >&2; }
# Prints a step-progress log line.
log_step() { echo -e "${_C}[STEP]${_N}  $*"; }
# Prints a section header.
log_header() { echo -e "\n${_W}==> $*${_N}"; }
# Prints a labeled value line.
log_val() { echo -e "    ${_Y}$1${_N}  $2"; }
# Prints an error and exits the script.
die() { log_error "$*"; exit 1; }

# Ensures the expected binary exists and is executable.
require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin
Build first with: ./zk-arche.sh build"
}

# Ensures the expected file exists.
require_file() {
  local f="$1"
  sudo test -f "$f" || die "Required file not found: $f"
}

# Ensures a required external command is available.
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

# Validates that a value is exactly 32 bytes encoded as hex.
validate_hex32() {
  local val="$1" label="$2"
  [[ "$val" =~ ^[0-9a-fA-F]{64}$ ]] || die "$label must be exactly 32 bytes (64 hex characters)"
}

# Installs a file to its destination with the requested mode using sudo.
sudo_write_file() {
  local src="$1" dst="$2" mode="$3"
  sudo install -m "$mode" "$src" "$dst"
}

# Securely overwrites a file before deleting it.
# Falls back to plain rm if shred is unavailable (macOS, etc.).
secure_delete() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  if command -v shred >/dev/null 2>&1; then
    shred -u "$path"
  else
    # On macOS / systems without shred, overwrite with random data then remove
    dd if=/dev/urandom of="$path" bs=1 count="$(wc -c < "$path")" conv=notrunc 2>/dev/null || true
    rm -f "$path"
  fi
}

# Creates the shared state directories with secure permissions.
ensure_state_dirs() {
  sudo mkdir -p "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR" "$GENERATED_DIR"
  sudo chmod 700 "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR" "$GENERATED_DIR"
}

# Ensures the client state directory tree exists.
ensure_client_state_dir() {
  ensure_state_dirs
}

# Ensures the server state directory tree exists.
ensure_server_state_dir() {
  ensure_state_dirs
}

# Creates the client device root secret when it is missing.
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

# Builds the helper program that derives the client identity from device_root.bin.
build_ident_helper() {
  require_cmd gcc
  cat > "$IDENT_HELPER_SRC" <<'EOF_HELPER'
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void bin2hex_lower(const uint8_t *in, size_t in_len, char *out, size_t out_len) {
    /* sodium_bin2hex already emits lowercase */
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

# Prints the client device_id and device_pub derived from the stored root.
derive_client_identity_hex() {
  ensure_client_root
  [[ -x "$IDENT_HELPER_BIN" ]] || build_ident_helper
  sudo "$IDENT_HELPER_BIN" "$CLIENT_DEVICE_ROOT"
}

# Prints the live server public key.
derive_server_pub_hex() {
  require_bin "$SERVER_BIN"
  ensure_server_state_dir
  (
    cd "$SERVER_STATE_DIR"
    sudo "$SERVER_BIN" --print-pubkey
  )
}

# Generates compact Ed25519 CA, server, and device certificates bound to the derived identities.
#
# SECURITY WARNING — CA KEY STORAGE:
#   This script writes ca_key.pem to SERVER_STATE_DIR for convenience.
#   In a production deployment the CA private key must be kept OFFLINE
#   (e.g. on an air-gapped machine or HSM).  A server compromise would
#   otherwise allow an attacker to sign arbitrary device certificates.
#   After running make-certs, consider running:
#       ./zk-arche.sh export-ca-key   # prints key, then removes it from disk
#   and storing the printed key securely offline.
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

  log_header "Generating CA, server cert, and device cert"
  log_val "device_id:" "$device_id"
  log_val "device_pub:" "$device_pub"
  log_val "server_pub:" "$server_pub"

  rm -f "$SERVER_CSR" "$DEVICE_CSR" "$CA_SERIAL" "$GEN_DEVICE_CERT" "$GEN_DEVICE_KEY"
  sudo rm -f "$SERVER_CA_KEY" "$SERVER_CA_CERT" "$SERVER_CERT" "$SERVER_CERT_KEY" \
             "$SERVER_PUB_HEX_FILE" "${SERVER_STATE_DIR}/ca_cert.srl"

  # Use Ed25519 for the CA and end-entity certificates to keep certs and
  # transcript signatures compact. OpenSSL handles the digest internally for
  # Ed25519, so do not pass -sha256 here.
  openssl genpkey -algorithm Ed25519 -out "$SERVER_CA_KEY.tmp" >/dev/null 2>&1

  openssl req -x509 -new -key "$SERVER_CA_KEY.tmp" \
    -out "$SERVER_CA_CERT.tmp" -days 3650 \
    -subj "/CN=ZK-ARCHE Demo CA" >/dev/null 2>&1

  openssl genpkey -algorithm Ed25519 -out "$SERVER_CERT_KEY.tmp" >/dev/null 2>&1

  openssl req -new -key "$SERVER_CERT_KEY.tmp" -out "$SERVER_CSR" \
    -subj "/CN=zk-arche-server/OU=${server_pub}" >/dev/null 2>&1

  openssl x509 -req -in "$SERVER_CSR" \
    -CA "$SERVER_CA_CERT.tmp" -CAkey "$SERVER_CA_KEY.tmp" -CAcreateserial \
    -out "$SERVER_CERT.tmp" -days 825 >/dev/null 2>&1

  if [[ -f "./ca_cert.srl" ]]; then
    mv -f "./ca_cert.srl" "$CA_SERIAL"
  fi

  openssl genpkey -algorithm Ed25519 -out "$GEN_DEVICE_KEY" >/dev/null 2>&1

  openssl req -new -key "$GEN_DEVICE_KEY" -out "$DEVICE_CSR" \
    -subj "/CN=${device_id}/OU=${device_pub}" >/dev/null 2>&1

  openssl x509 -req -in "$DEVICE_CSR" \
    -CA "$SERVER_CA_CERT.tmp" -CAkey "$SERVER_CA_KEY.tmp" -CAcreateserial \
    -out "$GEN_DEVICE_CERT" -days 825 >/dev/null 2>&1

  if [[ -f "./ca_cert.srl" ]]; then
    mv -f "./ca_cert.srl" "$CA_SERIAL"
  fi

  printf '%s\n' "$server_pub" > "$SERVER_PUB_HEX_FILE.tmp"

  sudo_write_file "$SERVER_CA_KEY.tmp" "$SERVER_CA_KEY" 600
  sudo_write_file "$SERVER_CA_CERT.tmp" "$SERVER_CA_CERT" 644
  sudo_write_file "$SERVER_CERT_KEY.tmp" "$SERVER_CERT_KEY" 600
  sudo_write_file "$SERVER_CERT.tmp" "$SERVER_CERT" 644
  sudo_write_file "$SERVER_PUB_HEX_FILE.tmp" "$SERVER_PUB_HEX_FILE" 644

  # Clean up plaintext temporaries immediately
  secure_delete "$SERVER_CA_KEY.tmp"
  rm -f "$SERVER_CA_CERT.tmp" "$SERVER_CERT_KEY.tmp" "$SERVER_CERT.tmp" "$SERVER_PUB_HEX_FILE.tmp"

  chmod 600 "$GEN_DEVICE_KEY" 2>/dev/null || true
  chmod 644 "$GEN_DEVICE_CERT" 2>/dev/null || true

  log_ok "Generated matching CA/server/device certs"
  log_val "CA cert:" "$SERVER_CA_CERT"
  log_val "Server cert:" "$SERVER_CERT"
  log_val "Server key:" "$SERVER_CERT_KEY"
  log_val "Device cert:" "$GEN_DEVICE_CERT"
  log_val "Device key:" "$GEN_DEVICE_KEY"
  log_warn "CA private key is on disk at: $SERVER_CA_KEY"
  log_warn "For production use, run './zk-arche.sh export-ca-key' to move it offline."
}

# Copies the generated client certificate material into the client state directory.
install_client_certs_from_generated() {
  require_file "$GEN_DEVICE_CERT"
  require_file "$GEN_DEVICE_KEY"
  require_file "$SERVER_CA_CERT"

  ensure_client_state_dir
  sudo install -m 644 "$GEN_DEVICE_CERT" "$CLIENT_DEVICE_CERT"
  sudo install -m 600 "$GEN_DEVICE_KEY" "$CLIENT_DEVICE_KEY"
  sudo install -m 644 "$SERVER_CA_CERT" "$CLIENT_CA_CERT"

  # FIX: securely delete the device private key from GENERATED_DIR after
  # installation.  Leaving it there creates a second unprotected copy.
  log_step "Securely removing device private key from generated dir..."
  secure_delete "$GEN_DEVICE_KEY"
  log_ok "Client cert material installed in $CLIENT_STATE_DIR"
  log_ok "Device private key removed from $GENERATED_DIR"
}

# Verifies that all required server certificate files already exist.
ensure_existing_server_material() {
  ensure_server_state_dir
  require_file "$SERVER_CA_CERT"
  require_file "$SERVER_CERT"
  require_file "$SERVER_CERT_KEY"
}

# Verifies that all required client files already exist.
ensure_existing_client_material() {
  ensure_client_state_dir
  require_file "$CLIENT_DEVICE_ROOT"
  require_file "$CLIENT_DEVICE_CERT"
  require_file "$CLIENT_DEVICE_KEY"
  require_file "$CLIENT_CA_CERT"
}

# Verifies that all binaries and demo certificate material are present.
ensure_existing_demo_material() {
  require_bin "$SERVER_BIN"
  require_bin "$CLIENT_BIN"
  ensure_existing_server_material
  ensure_existing_client_material
}

# Prints the client command-line usage help.
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
  export-ca-key            # print CA key then remove it from disk (production hardening)

${_C}SERVER COMMANDS${_N}
  start-server <bind_addr> [opts]
  server-local <bind_addr>
  reset-server

${_C}CLIENT COMMANDS${_N}
  setup-device <server_ip:port> [--pairing-token <token>]
  auth-device <server_ip:port>
  show-pinned-key
  pin-server <server_pub_hex>
  reset-client
  status

${_C}COMBINED FLOWS${_N}
  client-local <server_ip:port> [--pairing-token <token>]
  full-device-onboard <server_ip:port> [--pairing-token <token>]
  reset-all

${_C}RECOMMENDED LOCAL TEST FLOW${_N}
  ./zk-arche.sh build
  ./zk-arche.sh reset-all
  ./zk-arche.sh make-certs
  sudo ./zk-arche.sh server-local 127.0.0.1:4000
  sudo ./zk-arche.sh client-local 127.0.0.1:4000

EOF2
}

# Builds the server and client Rust binaries.
cmd_build() {
  require_cmd cargo
  log_header "Building Rust binaries"
  (cd "$PROJECT_ROOT" && cargo build --release)
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
}

# Generates demo certificates and installs the client certificate set.
cmd_make_certs() {
  require_bin "$SERVER_BIN"
  require_bin "$CLIENT_BIN"
  generate_bound_certs
  install_client_certs_from_generated
}

# Installs the previously generated client certificate files.
cmd_install_client_certs() {
  log_header "Installing client cert material from existing generated files"
  require_bin "$CLIENT_BIN"
  install_client_certs_from_generated
}

# Reports which expected server certificate files are present.
cmd_check_server_certs() {
  log_header "Server certificate files"
  _status_file "$SERVER_CA_CERT" "ca cert"
  _status_file "$SERVER_CA_KEY" "ca key"
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"
  _status_file "$SERVER_SK_FILE" "server static key"
  _status_file "$SERVER_REGISTRY" "device registry"
  _status_file "$SERVER_PUB_HEX_FILE" "server pub hex"
}

# Reports which expected client certificate files are present.
cmd_check_client_certs() {
  log_header "Client certificate files"
  _status_file "$CLIENT_DEVICE_ROOT" "device root"
  _status_file "$CLIENT_DEVICE_CERT" "device cert"
  _status_file "$CLIENT_DEVICE_KEY" "device key"
  _status_file "$CLIENT_CA_CERT" "ca cert"
  _status_file "$CLIENT_SERVER_PUB" "pinned server pub"
}

# Starts the server with the provided bind address and flags.
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

# Starts the server in local test mode with pairing enabled.
cmd_server_local() {
  require_bin "$SERVER_BIN"
  [[ $# -eq 1 ]] || die "server-local requires <bind_addr>"
  local bind_addr="$1"

  ensure_existing_demo_material

  log_header "Local test mode — server"
  log_info "Bind: $bind_addr"
  log_info "Pairing: enabled"
  echo
  log_info "In a second terminal run:"
  echo -e "    ${_Y}sudo ./zk-arche.sh client-local $bind_addr${_N}"
  echo

  cd "$SERVER_STATE_DIR"
  exec sudo "$SERVER_BIN" --bind "$bind_addr" --pairing
}

# Pins the supplied server public key for the client.
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

# Prints and then securely removes the CA private key from the server.
# Use this after make-certs to move the CA key offline for production hardening.
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

# Runs the client setup flow against the target server.
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

# Runs the client authentication flow against the target server.
cmd_auth_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"
  ensure_existing_client_material
  log_header "Device authentication"
  log_info "Server: $1"
  sudo "$CLIENT_BIN" --server "$1"
  log_ok "Authentication complete"
}

# Displays the currently pinned server public key.
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

# Prints whether a file exists and, when present, its size.
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

# Prints a summary of the current server, client, and generated state.
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
}

# Runs the recommended local client setup and authentication test flow.
cmd_client_local() {
  [[ $# -ge 1 ]] || die "client-local requires <server_ip:port>"
  local server_addr="$1"; shift
  local pairing_token_flags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        pairing_token_flags+=(--pairing-token "$2"); shift 2 ;;
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

# Runs the full certificate generation, install, setup, and auth onboarding sequence.
cmd_full_device_onboard() {
  [[ $# -ge 1 ]] || die "full-device-onboard requires <server_ip:port>"
  local server_addr="$1"; shift
  local setup_args=("$server_addr")

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        setup_args+=(--pairing-token "$2"); shift 2 ;;
      *) die "full-device-onboard: unknown option: $1" ;;
    esac
  done

  ensure_existing_demo_material
  cmd_setup_device "${setup_args[@]}"
}

# Removes client-side state files.
cmd_reset_client() {
  log_warn "Resetting client state: $CLIENT_STATE_DIR"
  sudo rm -rf "$CLIENT_STATE_DIR"
  sudo mkdir -p "$CLIENT_STATE_DIR"
  sudo chmod 700 "$CLIENT_STATE_DIR"
  log_ok "Client state removed"
}

# Removes server-side state files.
cmd_reset_server() {
  log_warn "Resetting server state in: $SERVER_STATE_DIR"
  sudo rm -f "$SERVER_REGISTRY" \
             "$SERVER_REGISTRY_BAK" \
             "$SERVER_SK_FILE" \
             "${SERVER_STATE_DIR}/server_pub.bin" \
             "$SERVER_PUB_HEX_FILE" \
             "$SERVER_CERT" "$SERVER_CERT_KEY" \
             "$SERVER_CA_CERT" "$SERVER_CA_KEY" \
             "${SERVER_STATE_DIR}/ca_cert.srl"
  rm -f "$GEN_DEVICE_CERT" "$GEN_DEVICE_KEY" \
        "$SERVER_CSR" "$DEVICE_CSR" "$CA_SERIAL" \
        "$IDENT_HELPER_SRC" "$IDENT_HELPER_BIN"
  log_ok "Server state removed"
}

# Removes both client-side and server-side state files.
cmd_reset_all() {
  cmd_reset_server
  cmd_reset_client
  log_ok "All state removed"
}

# Parses command-line arguments and dispatches the requested program action.
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
    show-pinned-key) cmd_show_pinned_key "$@" ;;
    status) cmd_status "$@" ;;
    client-local) cmd_client_local "$@" ;;
    full-device-onboard) cmd_full_device_onboard "$@" ;;
    reset-client) cmd_reset_client "$@" ;;
    reset-server) cmd_reset_server "$@" ;;
    reset-all) cmd_reset_all "$@" ;;
    -h|--help|help) usage ;;
    *) log_error "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
