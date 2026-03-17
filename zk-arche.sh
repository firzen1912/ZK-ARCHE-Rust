#!/usr/bin/env bash
# zk-arche.sh — ZK-ARCHE automation script
# Supports: build, mutual-certificate onboarding, auth, status, reset
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BIN="${PROJECT_ROOT}/target/release/server"
CLIENT_BIN="${PROJECT_ROOT}/target/release/client"
CLIENT_STATE_DIR="/var/lib/iot-auth"
CLIENT_SERVER_PUB="${CLIENT_STATE_DIR}/server_pub.bin"
CLIENT_DEVICE_ROOT="${CLIENT_STATE_DIR}/device_root.bin"
CLIENT_DEVICE_CERT="${CLIENT_STATE_DIR}/device_cert.pem"
CLIENT_DEVICE_KEY="${CLIENT_STATE_DIR}/device_key.pem"
CLIENT_CA_CERT="${CLIENT_STATE_DIR}/ca_cert.pem"
SERVER_PUB_HEX_FILE="${PROJECT_ROOT}/server_pub.hex"
SERVER_SK_FILE="${PROJECT_ROOT}/server_sk.bin"
SERVER_CERT="${PROJECT_ROOT}/server_cert.pem"
SERVER_CERT_KEY="${PROJECT_ROOT}/server_cert_key.pem"
SERVER_CA_CERT="${PROJECT_ROOT}/ca_cert.pem"
CERTS_WORK_DIR="${PROJECT_ROOT}/certs"
OPENSSL_CNF="${CERTS_WORK_DIR}/openssl.cnf"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  _R='\033[0;31m' _G='\033[0;32m' _Y='\033[0;33m'
  _B='\033[0;34m' _C='\033[0;36m' _W='\033[1;37m' _N='\033[0m'
else
  _R='' _G='' _Y='' _B='' _C='' _W='' _N=''
fi

log_info()    { echo -e "${_B}[INFO]${_N}  $*"; }
log_ok()      { echo -e "${_G}[OK]${_N}    $*"; }
log_warn()    { echo -e "${_Y}[WARN]${_N}  $*"; }
log_error()   { echo -e "${_R}[ERROR]${_N} $*" >&2; }
log_step()    { echo -e "${_C}[STEP]${_N}  $*"; }
log_header()  { echo -e "\n${_W}==> $*${_N}"; }
log_val()     { echo -e "    ${_Y}$1${_N}  $2"; }
die() { log_error "$*"; exit 1; }

require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin\nBuild first with: ./zk-arche.sh build"
}
require_file() {
  local f="$1"
  [[ -f "$f" ]] || die "Required file not found: $f"
}
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found in PATH: $1"
}
validate_hex32() {
  local val="$1" label="$2"
  [[ "$val" =~ ^[0-9a-fA-F]{64}$ ]] || die "$label must be exactly 32 bytes (64 hex characters)"
}
ensure_client_state_dir() {
  sudo mkdir -p "$CLIENT_STATE_DIR"
}
copy_with_sudo_if_needed() {
  local src="$1" dst="$2"
  ensure_client_state_dir
  if cp "$src" "$dst" 2>/dev/null; then
    :
  else
    sudo cp "$src" "$dst"
  fi
}

usage() {
  cat <<EOF

${_W}ZK-ARCHE automation script${_N}

${_C}USAGE${_N}
  ./zk-arche.sh <command> [options]

${_C}BUILD${_N}
  build                                   Compile release binaries

${_C}CERTIFICATE COMMANDS${_N}
  make-certs [device_id_hex]              Generate CA, server cert/key, and client cert/key
  check-server-certs                      Verify server-side cert/key files exist
  check-client-certs                      Verify client-side cert/key files exist
  install-client-certs                    Copy generated client cert material into /var/lib/iot-auth

${_C}SERVER COMMANDS${_N}
  start-server <bind_addr> [opts]         Start the server (passes extra flags through)
    Options:
      --pairing                           Enable pairing window
      --pairing-token <token>             Require this token during setup
      --pairing-seconds <n>               Close pairing window after N seconds
  server-local <bind_addr>                Start server in pairing mode for local testing
  reset-server                            Delete server state files

${_C}CLIENT COMMANDS${_N}
  setup-device <server_ip:port> [opts]    Enroll device using mutual certificate onboarding
    Options:
      --pairing-token <token>             Supply pairing token if server requires one
  auth-device <server_ip:port>            Authenticate an enrolled device
  show-pinned-key                         Print the server public key pinned for AUTH compatibility
  pin-server <server_pub_hex>             Manually pin a server public key for AUTH compatibility
  reset-client                            Delete all client state
  status                                  Show provisioning state of both client and server

${_C}COMBINED FLOWS${_N}
  client-local <server_ip:port> [opts]    Run local certificate-based setup
    Options:
      --pairing-token <token>             Supply pairing token to setup
  full-device-onboard <server_ip:port> [opts]
                                          Verify certs, optionally pin server key, then run setup.
                                          Options:
                                            --pairing-token <token>
                                            --server-pub <server_pub_hex>
  reset-all                               Reset both client and server state

${_C}TWO-MACHINE QUICKSTART${_N} (mutual certificate onboarding)

  ${_Y}Server machine:${_N}
    ./zk-arche.sh build
    ./zk-arche.sh make-certs
    ./zk-arche.sh start-server 0.0.0.0:4000 --pairing

  ${_Y}Client machine:${_N}
    ./zk-arche.sh build
    ./zk-arche.sh install-client-certs
    ./zk-arche.sh setup-device <server_ip:4000>
    ./zk-arche.sh auth-device <server_ip:4000>

${_C}SINGLE-MACHINE LOCAL TEST${_N}

  Terminal 1:  ./zk-arche.sh build
               ./zk-arche.sh make-certs
               ./zk-arche.sh server-local 127.0.0.1:4000
  Terminal 2:  ./zk-arche.sh client-local 127.0.0.1:4000

EOF
}

cmd_build() {
  log_header "Building release binaries"
  cargo build --release
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
}

write_openssl_cnf() {
  mkdir -p "$CERTS_WORK_DIR"
  cat > "$OPENSSL_CNF" <<'CNF'
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
CN = ZK-ARCHE Demo CA
O  = ZK-ARCHE

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_server ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth

[ v3_client ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = clientAuth
CNF
}

cmd_make_certs() {
  require_cmd openssl
  require_cmd python3
  require_file "$SERVER_SK_FILE"
  mkdir -p "$CERTS_WORK_DIR"
  ensure_client_state_dir
  write_openssl_cnf

  log_header "Generating CA, server cert, and client cert"

  local client_id_hex="${1:-}"
  if [[ -z "$client_id_hex" ]]; then
    if [[ -f "$CLIENT_DEVICE_ROOT" ]]; then
      client_id_hex="$(python3 - <<'PY' "$CLIENT_DEVICE_ROOT"
import sys, hashlib
from pathlib import Path
root = Path(sys.argv[1]).read_bytes()
if len(root) != 32:
    raise SystemExit('device_root.bin must be 32 bytes')
h = hashlib.sha256(); h.update(b'device-id'); h.update(root)
print(h.hexdigest())
PY
)"
      log_info "Derived device_id from existing client device_root.bin"
    else
      log_warn "No client device_root.bin found; generating a fresh one so cert CN matches the client"
      python3 - <<'PY' "$CLIENT_DEVICE_ROOT"
import os, sys
from pathlib import Path
p = Path(sys.argv[1])
p.parent.mkdir(parents=True, exist_ok=True)
if not p.exists():
    p.write_bytes(os.urandom(32))
PY
      client_id_hex="$(python3 - <<'PY' "$CLIENT_DEVICE_ROOT"
import sys, hashlib
from pathlib import Path
root = Path(sys.argv[1]).read_bytes()
h = hashlib.sha256(); h.update(b'device-id'); h.update(root)
print(h.hexdigest())
PY
)"
      log_info "Generated device_root.bin at $CLIENT_DEVICE_ROOT"
    fi
  else
    validate_hex32 "$client_id_hex" "device_id"
  fi

  log_val "Client device_id (CN):" "$client_id_hex"
  log_warn "This script generates the CA and X.509 shells and sets placeholder OU fields."
  log_warn "If your updated Rust verifier enforces exact OU == compressed Ristretto public key, reissue the certs with those exact values."

  log_step "Generating CA key and certificate..."
  openssl genrsa -out "${CERTS_WORK_DIR}/ca_key.pem" 2048 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key "${CERTS_WORK_DIR}/ca_key.pem" -sha256 -days 3650 -config "$OPENSSL_CNF" -out "$SERVER_CA_CERT" >/dev/null 2>&1

  log_step "Generating server certificate..."
  openssl genrsa -out "$SERVER_CERT_KEY" 2048 >/dev/null 2>&1
  openssl req -new -key "$SERVER_CERT_KEY" -subj "/CN=zk-arche-server/OU=UNBOUND_SERVER_STATIC_PUB/O=ZK-ARCHE" -out "${CERTS_WORK_DIR}/server.csr" >/dev/null 2>&1
  openssl x509 -req -in "${CERTS_WORK_DIR}/server.csr" -CA "$SERVER_CA_CERT" -CAkey "${CERTS_WORK_DIR}/ca_key.pem" -CAcreateserial -days 825 -sha256 -extfile "$OPENSSL_CNF" -extensions v3_server -out "$SERVER_CERT" >/dev/null 2>&1

  log_step "Generating client certificate..."
  openssl genrsa -out "${CERTS_WORK_DIR}/device_key.pem" 2048 >/dev/null 2>&1
  openssl req -new -key "${CERTS_WORK_DIR}/device_key.pem" -subj "/CN=${client_id_hex}/OU=UNBOUND_DEVICE_STATIC_PUB/O=ZK-ARCHE" -out "${CERTS_WORK_DIR}/device.csr" >/dev/null 2>&1
  openssl x509 -req -in "${CERTS_WORK_DIR}/device.csr" -CA "$SERVER_CA_CERT" -CAkey "${CERTS_WORK_DIR}/ca_key.pem" -CAcreateserial -days 825 -sha256 -extfile "$OPENSSL_CNF" -extensions v3_client -out "${CERTS_WORK_DIR}/device_cert.pem" >/dev/null 2>&1

  copy_with_sudo_if_needed "${CERTS_WORK_DIR}/device_cert.pem" "$CLIENT_DEVICE_CERT"
  copy_with_sudo_if_needed "${CERTS_WORK_DIR}/device_key.pem" "$CLIENT_DEVICE_KEY"
  copy_with_sudo_if_needed "$SERVER_CA_CERT" "$CLIENT_CA_CERT"

  log_ok "CA cert:        $SERVER_CA_CERT"
  log_ok "Server cert:    $SERVER_CERT"
  log_ok "Server key:     $SERVER_CERT_KEY"
  log_ok "Client cert:    $CLIENT_DEVICE_CERT"
  log_ok "Client key:     $CLIENT_DEVICE_KEY"
  log_ok "Client CA cert: $CLIENT_CA_CERT"
}

cmd_check_server_certs() {
  log_header "Checking server certificate files"
  _status_file "$SERVER_CA_CERT" "server CA cert"
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"
}

cmd_check_client_certs() {
  log_header "Checking client certificate files"
  _status_file "$CLIENT_CA_CERT" "client CA cert"
  _status_file "$CLIENT_DEVICE_CERT" "client device cert"
  _status_file "$CLIENT_DEVICE_KEY" "client device key"
  _status_file "$CLIENT_DEVICE_ROOT" "client device root"
}

cmd_install_client_certs() {
  log_header "Installing generated client certs into $CLIENT_STATE_DIR"
  require_file "${CERTS_WORK_DIR}/device_cert.pem"
  require_file "${CERTS_WORK_DIR}/device_key.pem"
  require_file "$SERVER_CA_CERT"
  copy_with_sudo_if_needed "${CERTS_WORK_DIR}/device_cert.pem" "$CLIENT_DEVICE_CERT"
  copy_with_sudo_if_needed "${CERTS_WORK_DIR}/device_key.pem" "$CLIENT_DEVICE_KEY"
  copy_with_sudo_if_needed "$SERVER_CA_CERT" "$CLIENT_CA_CERT"
  log_ok "Client certificate material installed"
}

cmd_start_server() {
  require_bin "$SERVER_BIN"
  require_file "$SERVER_CA_CERT"
  require_file "$SERVER_CERT"
  require_file "$SERVER_CERT_KEY"
  [[ $# -ge 1 ]] || die "start-server requires <bind_addr>"
  local bind_addr="$1"; shift
  log_header "Starting server"
  log_info "Bind:  $bind_addr"
  [[ $# -gt 0 ]] && log_info "Flags: $*"
  exec "$SERVER_BIN" --bind "$bind_addr" "$@"
}

cmd_server_local() {
  require_bin "$SERVER_BIN"
  [[ $# -eq 1 ]] || die "server-local requires <bind_addr>"
  local bind_addr="$1"
  log_header "Local test mode — server"
  log_info "Bind:    $bind_addr"
  log_info "Pairing: enabled (no token required)"
  echo
  log_info "Keep this terminal open."
  log_info "In a second terminal run:"
  echo -e "    ${_Y}./zk-arche.sh client-local $bind_addr${_N}"
  echo
  exec "$SERVER_BIN" --bind "$bind_addr" --pairing
}

cmd_pin_server() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "pin-server requires <server_pub_hex>"
  local server_pub="$1"
  validate_hex32 "$server_pub" "server_pub_hex"
  log_step "Pinning server public key..."
  "$CLIENT_BIN" --pin-server-pub "$server_pub"
  printf '%s\n' "$server_pub" > "$SERVER_PUB_HEX_FILE"
  log_ok "Server public key pinned"
  log_val "Fingerprint:" "$server_pub"
}

cmd_setup_device() {
  require_bin "$CLIENT_BIN"
  require_file "$CLIENT_DEVICE_CERT"
  require_file "$CLIENT_DEVICE_KEY"
  require_file "$CLIENT_CA_CERT"
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
  log_header "Device setup (mutual certificate onboarding)"
  log_info "Server: $server_addr"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  "$CLIENT_BIN" --server "$server_addr" --setup "${extra_flags[@]}"
  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local pinned_hex
    pinned_hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Device enrolled. AUTH compatibility pin present:"
    log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Device enrolled."
  fi
}

cmd_auth_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"
  log_header "Device authentication"
  log_info "Server: $1"
  "$CLIENT_BIN" --server "$1"
  log_ok "Authentication complete"
}

cmd_show_pinned_key() {
  if [[ ! -f "$CLIENT_SERVER_PUB" ]]; then
    log_warn "No pinned server key found at: $CLIENT_SERVER_PUB"
    log_info "Mutual cert onboarding does not require TOFU, but AUTH_V2 may still use a pinned compatibility key."
    return
  fi
  local hex
  hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB")"
  log_ok "Pinned server public key:"
  log_val "File:        " "$CLIENT_SERVER_PUB"
  log_val "Fingerprint: " "$hex"
}

cmd_status() {
  log_header "ZK-ARCHE status"
  echo -e "\n${_W}Binaries${_N}"
  if [[ -x "$SERVER_BIN" ]]; then log_ok "server binary:  $SERVER_BIN"; else log_warn "server binary:  not built ($SERVER_BIN)"; fi
  if [[ -x "$CLIENT_BIN" ]]; then log_ok "client binary:  $CLIENT_BIN"; else log_warn "client binary:  not built ($CLIENT_BIN)"; fi

  echo -e "\n${_W}Server state${_N}  ($PROJECT_ROOT)"
  _status_file "$SERVER_SK_FILE" "server secret key"
  _status_file "${PROJECT_ROOT}/registry.bin" "device registry"
  _status_file "$SERVER_CA_CERT" "server CA cert"
  _status_file "$SERVER_CERT" "server cert"
  _status_file "$SERVER_CERT_KEY" "server cert key"
  _status_file "$SERVER_PUB_HEX_FILE" "saved server pub hex"

  echo -e "\n${_W}Client state${_N}  ($CLIENT_STATE_DIR)"
  _status_file "$CLIENT_DEVICE_ROOT" "device root"
  _status_file "$CLIENT_CA_CERT" "client CA cert"
  _status_file "$CLIENT_DEVICE_CERT" "client device cert"
  _status_file "$CLIENT_DEVICE_KEY" "client device key"
  _status_file "$CLIENT_SERVER_PUB" "pinned server pub"
  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local hex
    hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_val "  pinned fingerprint:" "$hex"
  fi
  echo
}

_status_file() {
  local path="$1" label="$2"
  if [[ -f "$path" ]]; then
    local size
    size="$(wc -c < "$path" | tr -d ' ')"
    log_ok "$label: present (${size}B)"
  else
    log_warn "$label: absent"
  fi
}

cmd_client_local() {
  require_bin "$CLIENT_BIN"
  require_file "$CLIENT_DEVICE_CERT"
  require_file "$CLIENT_DEVICE_KEY"
  require_file "$CLIENT_CA_CERT"
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
  log_header "Local onboarding — client terminal"
  log_info "Server: $server_addr"
  "$CLIENT_BIN" --server "$server_addr" --setup "${pairing_token_flags[@]}"
  echo
  log_info "To authenticate later, run:"
  echo -e "    ${_Y}./zk-arche.sh auth-device $server_addr${_N}"
}

cmd_full_device_onboard() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "full-device-onboard requires <server_ip:port> [--pairing-token <token>] [--server-pub <hex>]"
  local server_addr="$1"; shift
  local setup_flags=()
  local server_pub=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        setup_flags+=(--pairing-token "$2"); shift 2 ;;
      --server-pub)
        [[ $# -ge 2 ]] || die "--server-pub requires a value"
        server_pub="$2"; shift 2 ;;
      *) die "full-device-onboard: unknown option: $1" ;;
    esac
  done
  log_header "Full device onboarding"
  log_info "Server: $server_addr"
  cmd_check_client_certs
  cmd_check_server_certs
  if [[ -n "$server_pub" ]]; then
    validate_hex32 "$server_pub" "server_pub_hex"
    log_step "Pinning server public key for AUTH compatibility..."
    "$CLIENT_BIN" --pin-server-pub "$server_pub"
    printf '%s\n' "$server_pub" > "$SERVER_PUB_HEX_FILE"
    log_ok "Server key pinned: $server_pub"
  fi
  log_step "Running device setup..."
  "$CLIENT_BIN" --server "$server_addr" --setup "${setup_flags[@]}"
  log_ok "Onboarding complete"
}

cmd_reset_client() {
  log_warn "Resetting client state: $CLIENT_STATE_DIR"
  sudo rm -rf "$CLIENT_STATE_DIR"
  log_ok "Client state removed"
}

cmd_reset_server() {
  log_warn "Resetting server state in: $PROJECT_ROOT"
  rm -f "${PROJECT_ROOT}/registry.bin" \
        "${PROJECT_ROOT}/registry.bak" \
        "$SERVER_SK_FILE" \
        "${PROJECT_ROOT}/server_pub.bin" \
        "$SERVER_PUB_HEX_FILE" \
        "$SERVER_CERT" \
        "$SERVER_CERT_KEY" \
        "$SERVER_CA_CERT"
  rm -rf "$CERTS_WORK_DIR"
  log_ok "Server state removed"
}

cmd_reset_all() {
  cmd_reset_server
  cmd_reset_client
  log_ok "All state removed"
}

main() {
  if [[ $# -lt 1 ]]; then usage; exit 1; fi
  local cmd="$1"; shift
  case "$cmd" in
    build)                cmd_build "$@" ;;
    make-certs)           cmd_make_certs "$@" ;;
    check-server-certs)   cmd_check_server_certs "$@" ;;
    check-client-certs)   cmd_check_client_certs "$@" ;;
    install-client-certs) cmd_install_client_certs "$@" ;;
    start-server)         cmd_start_server "$@" ;;
    server-local)         cmd_server_local "$@" ;;
    pin-server)           cmd_pin_server "$@" ;;
    setup-device)         cmd_setup_device "$@" ;;
    auth-device)          cmd_auth_device "$@" ;;
    show-pinned-key)      cmd_show_pinned_key "$@" ;;
    status)               cmd_status "$@" ;;
    client-local)         cmd_client_local "$@" ;;
    full-device-onboard)  cmd_full_device_onboard "$@" ;;
    reset-client)         cmd_reset_client "$@" ;;
    reset-server)         cmd_reset_server "$@" ;;
    reset-all)            cmd_reset_all "$@" ;;
    -h|--help|help)       usage ;;
    *) log_error "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
