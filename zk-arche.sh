#!/usr/bin/env bash
# zk-arche.sh — ZK-ARCHE automation script
# Supports: build, server management, TOFU device onboarding, auth, status, reset
set -euo pipefail

# ============================================================
# Paths
# ============================================================
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BIN="${PROJECT_ROOT}/target/release/server"
CLIENT_BIN="${PROJECT_ROOT}/target/release/client"
CLIENT_STATE_DIR="/var/lib/iot-auth"
CLIENT_SERVER_PUB="${CLIENT_STATE_DIR}/server_pub.bin"
SERVER_PUB_HEX_FILE="${PROJECT_ROOT}/server_pub.hex"
LAST_BOOTSTRAP_FILE="${PROJECT_ROOT}/last_bootstrap.env"

# ============================================================
# Logging helpers
# ============================================================
# Detect color support (disable if not a terminal or NO_COLOR is set)
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

# ============================================================
# Validation helpers
# ============================================================
require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin\nBuild first with: ./zk-arche.sh build"
}

require_file() {
  local f="$1"
  [[ -f "$f" ]] || die "Required file not found: $f"
}

validate_hex32() {
  local val="$1" label="$2"
  [[ "$val" =~ ^[0-9a-fA-F]{64}$ ]] || die "$label must be exactly 32 bytes (64 hex characters)"
}

# ============================================================
# Usage
# ============================================================
usage() {
  cat <<EOF

${_W}ZK-ARCHE automation script${_N}

${_C}USAGE${_N}
  ./zk-arche.sh <command> [options]

${_C}BUILD${_N}
  build                                   Compile release binaries

${_C}SERVER COMMANDS${_N}
  add-bootstrap [<id_hex> <secret_hex>]   Register a bootstrap credential (generates one if omitted)
  show-bootstrap                          Print the last generated bootstrap credential
  start-server <bind_addr> [opts]         Start the server (passes extra flags through)
    Options:
      --pairing                           Enable pairing window
      --pairing-token <token>             Require this token during setup
      --pairing-seconds <n>               Close pairing window after N seconds
  server-local <bind_addr>                Start server in pairing mode for local testing
  reset-server                            Delete all server state files

${_C}CLIENT COMMANDS${_N}
  provision-bootstrap <id_hex> <secret_hex>   Write bootstrap credentials to device
  setup-device <server_ip:port> [opts]        Enroll device (TOFU: server key auto-pinned)
    Options:
      --pairing-token <token>             Supply pairing token if server requires one
  auth-device <server_ip:port>            Authenticate an enrolled device
  show-pinned-key                         Print the server public key currently pinned on this client
  pin-server <server_pub_hex>             Manually pin a server public key (out-of-band)
  reset-client                            Delete all client state
  status                                  Show provisioning state of both client and server

${_C}COMBINED FLOWS${_N}
  client-local <server_ip:port> [opts]    Full local onboarding (reads last_bootstrap.env)
    Options:
      --pairing-token <token>             Supply pairing token to setup
  full-device-onboard <server_ip:port> <id_hex> <secret_hex> [<server_pub_hex>]
                                          Provision bootstrap + setup in one step.
                                          server_pub_hex is optional; omit to use TOFU.
  reset-all                               Reset both client and server state

${_C}TWO-MACHINE QUICKSTART${_N} (TOFU — no manual key exchange needed)

  ${_Y}Server machine:${_N}
    ./zk-arche.sh build
    ./zk-arche.sh add-bootstrap
    ./zk-arche.sh show-bootstrap          ← copy BOOTSTRAP_ID and BOOTSTRAP_SECRET
    ./zk-arche.sh start-server 0.0.0.0:4000 --pairing

  ${_Y}Client machine:${_N}
    ./zk-arche.sh build
    ./zk-arche.sh provision-bootstrap <id_hex> <secret_hex>
    ./zk-arche.sh setup-device <server_ip:4000>   ← server key is auto-pinned via TOFU
    ./zk-arche.sh auth-device <server_ip:4000>

${_C}SINGLE-MACHINE LOCAL TEST${_N}

  Terminal 1:  ./zk-arche.sh server-local 127.0.0.1:4000
  Terminal 2:  ./zk-arche.sh add-bootstrap
               ./zk-arche.sh client-local 127.0.0.1:4000

EOF
}

# ============================================================
# build
# ============================================================
cmd_build() {
  log_header "Building release binaries"
  cargo build --release
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
}

# ============================================================
# add-bootstrap
# ============================================================
cmd_add_bootstrap() {
  require_bin "$SERVER_BIN"

  local bootstrap_id bootstrap_secret

  if [[ $# -eq 0 ]]; then
    bootstrap_id="$(openssl rand -hex 32)"
    bootstrap_secret="$(openssl rand -hex 32)"
    log_info "Generated new bootstrap credential"
  elif [[ $# -eq 2 ]]; then
    bootstrap_id="$1"
    bootstrap_secret="$2"
    validate_hex32 "$bootstrap_id"     "bootstrap_id"
    validate_hex32 "$bootstrap_secret" "bootstrap_secret"
  else
    die "add-bootstrap expects 0 or 2 arguments"
  fi

  log_step "Registering bootstrap credential with server..."
  "$SERVER_BIN" --add-bootstrap "$bootstrap_id" "$bootstrap_secret"

  cat > "$LAST_BOOTSTRAP_FILE" <<ENV
BOOTSTRAP_ID=$bootstrap_id
BOOTSTRAP_SECRET=$bootstrap_secret
ENV

  log_ok "Bootstrap credential registered and saved to: $LAST_BOOTSTRAP_FILE"
  log_val "BOOTSTRAP_ID:    " "$bootstrap_id"
  log_val "BOOTSTRAP_SECRET:" "$bootstrap_secret"
}

# ============================================================
# show-bootstrap
# ============================================================
cmd_show_bootstrap() {
  require_file "$LAST_BOOTSTRAP_FILE"
  log_header "Last generated bootstrap values"
  # shellcheck disable=SC1090
  source "$LAST_BOOTSTRAP_FILE"
  log_val "BOOTSTRAP_ID:    " "${BOOTSTRAP_ID:?missing}"
  log_val "BOOTSTRAP_SECRET:" "${BOOTSTRAP_SECRET:?missing}"
}

# ============================================================
# start-server  (passes all extra flags straight through)
# ============================================================
cmd_start_server() {
  require_bin "$SERVER_BIN"
  [[ $# -ge 1 ]] || die "start-server requires <bind_addr>"
  local bind_addr="$1"; shift

  log_header "Starting server"
  log_info  "Bind:  $bind_addr"
  [[ $# -gt 0 ]] && log_info "Flags: $*"
  exec "$SERVER_BIN" --bind "$bind_addr" "$@"
}

# ============================================================
# server-local  (convenience wrapper for single-machine tests)
# ============================================================
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
  echo -e "    ${_Y}./zk-arche.sh add-bootstrap${_N}"
  echo -e "    ${_Y}./zk-arche.sh client-local $bind_addr${_N}"
  echo

  exec "$SERVER_BIN" --bind "$bind_addr" --pairing
}

# ============================================================
# pin-server  (manual out-of-band pinning — still supported)
# ============================================================
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

# ============================================================
# provision-bootstrap
# ============================================================
cmd_provision_bootstrap() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 2 ]] || die "provision-bootstrap requires <bootstrap_id_hex> <bootstrap_secret_hex>"
  validate_hex32 "$1" "bootstrap_id"
  validate_hex32 "$2" "bootstrap_secret"

  log_step "Writing bootstrap credentials to device..."
  "$CLIENT_BIN" --provision-bootstrap "$1" "$2"
  log_ok "Bootstrap credentials provisioned"
}

# ============================================================
# setup-device  [--pairing-token <token>]
# ============================================================
cmd_setup_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "setup-device requires <server_ip:port>"
  local server_addr="$1"; shift

  # Parse optional flags
  local extra_flags=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        extra_flags+=(--pairing-token "$2"); shift 2 ;;
      *) die "setup-device: unknown option: $1" ;;
    esac
  done

  log_header "Device setup (TOFU)"
  log_info "Server: $server_addr"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  log_info "The server's public key will be auto-pinned after successful enrollment."

  "$CLIENT_BIN" --server "$server_addr" --setup "${extra_flags[@]}"

  # Show what got pinned
  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local pinned_hex
    pinned_hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Device enrolled. Pinned server key:"
    log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Device enrolled."
  fi
}

# ============================================================
# auth-device
# ============================================================
cmd_auth_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"

  log_header "Device authentication"
  log_info "Server: $1"
  "$CLIENT_BIN" --server "$1"
  log_ok "Authentication complete"
}

# ============================================================
# show-pinned-key
# ============================================================
cmd_show_pinned_key() {
  if [[ ! -f "$CLIENT_SERVER_PUB" ]]; then
    log_warn "No pinned server key found at: $CLIENT_SERVER_PUB"
    log_info "Run setup-device to enroll (TOFU will pin the key automatically)."
    return
  fi
  local hex
  hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB")"
  log_ok "Pinned server public key:"
  log_val "File:        " "$CLIENT_SERVER_PUB"
  log_val "Fingerprint: " "$hex"
}

# ============================================================
# status  — inspect provisioning state of client and server
# ============================================================
cmd_status() {
  log_header "ZK-ARCHE status"

  # --- Binaries ---
  echo -e "\n${_W}Binaries${_N}"
  if [[ -x "$SERVER_BIN" ]]; then
    log_ok  "server binary:  $SERVER_BIN"
  else
    log_warn "server binary:  not built ($SERVER_BIN)"
  fi
  if [[ -x "$CLIENT_BIN" ]]; then
    log_ok  "client binary:  $CLIENT_BIN"
  else
    log_warn "client binary:  not built ($CLIENT_BIN)"
  fi

  # --- Server state ---
  echo -e "\n${_W}Server state${_N}  ($PROJECT_ROOT)"
  _status_file "${PROJECT_ROOT}/server_sk.bin"          "server secret key"
  _status_file "${PROJECT_ROOT}/registry.bin"           "device registry"
  _status_file "${PROJECT_ROOT}/bootstrap_registry.bin" "bootstrap registry"
  _status_file "$LAST_BOOTSTRAP_FILE"                   "last bootstrap env"

  if [[ -f "$LAST_BOOTSTRAP_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$LAST_BOOTSTRAP_FILE" 2>/dev/null || true
    [[ -n "${BOOTSTRAP_ID:-}"     ]] && log_val "  bootstrap_id:    " "${BOOTSTRAP_ID}"
    [[ -n "${BOOTSTRAP_SECRET:-}" ]] && log_val "  bootstrap_secret:" "${BOOTSTRAP_SECRET}"
  fi

  if [[ -f "${PROJECT_ROOT}/server_pub.hex" ]]; then
    log_val "  server_pub (hex):" "$(cat "${PROJECT_ROOT}/server_pub.hex")"
  fi

  # --- Client state ---
  echo -e "\n${_W}Client state${_N}  ($CLIENT_STATE_DIR)"
  _status_file "${CLIENT_STATE_DIR}/device_root.bin"    "device root"
  _status_file "${CLIENT_STATE_DIR}/bootstrap_id.bin"   "bootstrap id"
  _status_file "${CLIENT_STATE_DIR}/bootstrap_secret.bin" "bootstrap secret"
  _status_file "$CLIENT_SERVER_PUB"                     "pinned server pub"

  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local hex
    hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_val "  fingerprint:" "$hex"
  fi

  echo
}

# Helper: print file presence in a consistent style
_status_file() {
  local path="$1" label="$2"
  if [[ -f "$path" ]]; then
    local size
    size="$(wc -c < "$path" | tr -d ' ')"
    log_ok  "$label: present (${size}B)"
  else
    log_warn "$label: absent"
  fi
}

# ============================================================
# client-local  [--pairing-token <token>]
# Full local onboarding from last_bootstrap.env (no server_pub_hex needed — TOFU)
# ============================================================
cmd_client_local() {
  require_bin "$CLIENT_BIN"
  require_file "$LAST_BOOTSTRAP_FILE"
  [[ $# -ge 1 ]] || die "client-local requires <server_ip:port>"

  local server_addr="$1"; shift

  # Parse optional flags
  local pairing_token_flags=()
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        pairing_token_flags+=(--pairing-token "$2"); shift 2 ;;
      *) die "client-local: unknown option: $1" ;;
    esac
  done

  # shellcheck disable=SC1090
  source "$LAST_BOOTSTRAP_FILE"
  : "${BOOTSTRAP_ID:?missing BOOTSTRAP_ID in $LAST_BOOTSTRAP_FILE}"
  : "${BOOTSTRAP_SECRET:?missing BOOTSTRAP_SECRET in $LAST_BOOTSTRAP_FILE}"

  log_header "Local onboarding — client terminal"
  log_info "Server:     $server_addr"
  log_info "Bootstrap:  $LAST_BOOTSTRAP_FILE"
  log_info "Server key: will be auto-pinned via TOFU during setup"
  echo

  log_step "[1/2] Provisioning bootstrap credentials..."
  "$CLIENT_BIN" --provision-bootstrap "$BOOTSTRAP_ID" "$BOOTSTRAP_SECRET"
  log_ok "Bootstrap provisioned"

  log_step "[2/2] Running device setup (TOFU)..."
  "$CLIENT_BIN" --server "$server_addr" --setup "${pairing_token_flags[@]}"

  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local pinned_hex
    pinned_hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Setup complete. Pinned server key:"
    log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Setup complete"
  fi

  echo
  log_info "To authenticate later, run:"
  echo -e "    ${_Y}./zk-arche.sh auth-device $server_addr${_N}"
}

# ============================================================
# full-device-onboard  (server_pub_hex is optional — omit for TOFU)
# Usage: full-device-onboard <server_ip:port> <id_hex> <secret_hex> [<server_pub_hex>]
# ============================================================
cmd_full_device_onboard() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 3 ]] || die "full-device-onboard requires <server_ip:port> <id_hex> <secret_hex> [<server_pub_hex>]"

  local server_addr="$1"
  local bootstrap_id="$2"
  local bootstrap_secret="$3"
  local server_pub="${4:-}"

  validate_hex32 "$bootstrap_id"     "bootstrap_id"
  validate_hex32 "$bootstrap_secret" "bootstrap_secret"

  log_header "Full device onboarding"
  log_info "Server: $server_addr"

  log_step "[1/3] Provisioning bootstrap credentials..."
  "$CLIENT_BIN" --provision-bootstrap "$bootstrap_id" "$bootstrap_secret"
  log_ok "Bootstrap provisioned"

  if [[ -n "$server_pub" ]]; then
    validate_hex32 "$server_pub" "server_pub_hex"
    log_step "[2/3] Pinning server public key (out-of-band)..."
    "$CLIENT_BIN" --pin-server-pub "$server_pub"
    printf '%s\n' "$server_pub" > "$SERVER_PUB_HEX_FILE"
    log_ok "Server key pinned: $server_pub"
  else
    log_info "[2/3] No server_pub_hex supplied — TOFU will pin the key during setup"
  fi

  log_step "[3/3] Running device setup..."
  "$CLIENT_BIN" --server "$server_addr" --setup

  if [[ -f "$CLIENT_SERVER_PUB" ]]; then
    local pinned_hex
    pinned_hex="$(xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Onboarding complete. Pinned server key:"
    log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Onboarding complete"
  fi
}

# ============================================================
# reset-client / reset-server / reset-all
# ============================================================
cmd_reset_client() {
  log_warn "Resetting client state: $CLIENT_STATE_DIR"
  sudo rm -rf "$CLIENT_STATE_DIR"
  log_ok "Client state removed"
}

cmd_reset_server() {
  log_warn "Resetting server state in: $PROJECT_ROOT"
  rm -f "${PROJECT_ROOT}/registry.bin" \
        "${PROJECT_ROOT}/registry.bak" \
        "${PROJECT_ROOT}/bootstrap_registry.bin" \
        "${PROJECT_ROOT}/bootstrap_registry.bak" \
        "${PROJECT_ROOT}/server_sk.bin" \
        "${PROJECT_ROOT}/server_pub.bin" \
        "${PROJECT_ROOT}/server_pub.hex" \
        "${PROJECT_ROOT}/last_bootstrap.env"
  log_ok "Server state removed"
}

cmd_reset_all() {
  cmd_reset_server
  cmd_reset_client
  log_ok "All state removed"
}

# ============================================================
# Main dispatcher
# ============================================================
main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  local cmd="$1"; shift

  case "$cmd" in
    build)                cmd_build "$@" ;;
    add-bootstrap)        cmd_add_bootstrap "$@" ;;
    show-bootstrap)       cmd_show_bootstrap "$@" ;;
    start-server)         cmd_start_server "$@" ;;
    server-local)         cmd_server_local "$@" ;;
    pin-server)           cmd_pin_server "$@" ;;
    provision-bootstrap)  cmd_provision_bootstrap "$@" ;;
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