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
CLIENT_OFFLINE_COUNTER="${CLIENT_STATE_DIR}/offline_counter.bin"
CLIENT_CONTINUITY_FILE="${CLIENT_STATE_DIR}/continuity.bin"
CLIENT_SERVER_CONT_TRACK="${CLIENT_STATE_DIR}/server_continuity_track.bin"

SERVER_SK_FILE="${SERVER_STATE_DIR}/server_sk.bin"
SERVER_REGISTRY="${SERVER_STATE_DIR}/registry.bin"
SERVER_REGISTRY_BAK="${SERVER_STATE_DIR}/registry.bak"
SERVER_REPLAY_CACHE="${SERVER_STATE_DIR}/replay_cache.bin"
SERVER_OFFLINE_COUNTERS="${SERVER_STATE_DIR}/offline_counters.bin"
SERVER_CONTINUITY_FILE="${SERVER_STATE_DIR}/continuity.bin"
SERVER_CLIENT_CONT_TRACKS="${SERVER_STATE_DIR}/client_continuity_tracks.bin"
SERVER_PUB_HEX_FILE="${SERVER_STATE_DIR}/server_pub.hex"

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

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Required command not found: $1"
}

require_bin() {
  local bin="$1"
  [[ -x "$bin" ]] || die "Binary not found or not executable: $bin
Build first with: ./zk-arche.sh build"
}

require_file() {
  local f="$1"
  sudo test -f "$f" || die "Required file not found: $f"
}

validate_hex32() {
  local val="$1" label="$2"
  [[ "$val" =~ ^[0-9a-fA-F]{64}$ ]] || die "$label must be exactly 32 bytes (64 hex characters)"
}

sudo_write_file() {
  local src="$1" dst="$2" mode="$3"
  sudo install -m "$mode" "$src" "$dst"
}

ensure_state_dirs() {
  sudo mkdir -p "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR" "$GENERATED_DIR"
  sudo chmod 700 "$BASE_STATE_DIR" "$SERVER_STATE_DIR" "$CLIENT_STATE_DIR" "$GENERATED_DIR"
}

ensure_client_root() {
  ensure_state_dirs
  if ! sudo test -f "$CLIENT_DEVICE_ROOT"; then
    log_step "Creating client device root at $CLIENT_DEVICE_ROOT"
    local tmp
    tmp="$(mktemp)"
    openssl rand 32 > "$tmp"
    sudo_write_file "$tmp" "$CLIENT_DEVICE_ROOT" 600
    rm -f "$tmp"
    log_ok "Created client device root"
  fi
}

build_ident_helper() {
  require_cmd gcc
  cat > "$IDENT_HELPER_SRC" <<'EOF_HELPER'
#include <sodium.h>
#include <stdio.h>
#include <stdint.h>

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
  ensure_state_dirs
  (
    cd "$SERVER_STATE_DIR"
    sudo "$SERVER_BIN" --print-pubkey
  )
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

ensure_existing_server_material() {
  require_bin "$SERVER_BIN"
  ensure_state_dirs
}

ensure_existing_client_material() {
  require_bin "$CLIENT_BIN"
  ensure_client_root
}

usage() {
  cat <<EOF2

${_W}ZK-ARCHE automation script (raw public-key / one-ZKP AUTH)${_N}

${_C}USAGE${_N}
  ./zk-arche.sh <command> [options]

${_C}CORE COMMANDS${_N}
  build
  start-server <bind_addr> [server flags...]
  server-local <bind_addr> [--pairing-token <token>] [--pairing-seconds <n>]
  setup-device <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup]
  auth-device <server_ip:port>
  client-local <server_ip:port> [--pairing-token <token>] [--allow-tofu-setup]
  pin-server <server_pub_hex>
  show-pinned-key
  print-device-id
  print-server-pub
  status
  reset-client
  reset-server
  reset-all

${_C}OPTIONAL UTILITIES${_N}
  make-offline-proof <output_file> --audience <name> --scope <scope> [--offline-expires-in <secs>] [--request-hash <hex>|--request-file <path>]
  verify-offline-proof <proof_file> --audience <name> --allow-offline-scope <scope>...
  make-client-continuity-proof <output_file> [--continuity-expires-in <secs>]
  verify-server-continuity-proof <proof_file>
  make-server-continuity-proof <output_file> --peer-id <hex32> [--continuity-expires-in <secs>]
  verify-client-continuity-proof <proof_file>

${_C}RECOMMENDED LOCAL TEST FLOW${_N}
  ./zk-arche.sh build
  sudo ./zk-arche.sh reset-all
  sudo ./zk-arche.sh server-local 127.0.0.1:4000
  sudo ./zk-arche.sh client-local 127.0.0.1:4000

EOF2
}

cmd_build() {
  require_cmd cargo
  log_header "Building Rust binaries"
  (cd "$PROJECT_ROOT" && cargo build --release)
  log_ok "Server: $SERVER_BIN"
  log_ok "Client: $CLIENT_BIN"
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

  ensure_existing_server_material
  log_header "Local server"
  log_info "Bind: $bind_addr"
  log_info "Pairing: enabled"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  echo
  log_info "In a second terminal run:"
  echo -e "    ${_Y}sudo ./zk-arche.sh client-local $bind_addr${_N}"
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

cmd_print_device_id() {
  ensure_existing_client_material
  log_header "Client device identity"
  sudo "$CLIENT_BIN" --print-device-identity
}

cmd_print_server_pub() {
  ensure_existing_server_material
  log_header "Server public key"
  local spub
  spub="$(derive_server_pub_hex)"
  log_val "server_pub:" "$spub"
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
  log_header "Device setup"
  log_info "Server: $server_addr"
  [[ ${#extra_flags[@]} -gt 0 ]] && log_info "Extra flags: ${extra_flags[*]}"
  sudo "$CLIENT_BIN" --server "$server_addr" --setup "${extra_flags[@]}"

  if sudo test -f "$CLIENT_SERVER_PUB"; then
    local pinned_hex
    pinned_hex="$(sudo xxd -p -c 32 "$CLIENT_SERVER_PUB" 2>/dev/null || true)"
    log_ok "Device enrolled and server public key pinned"
    [[ -n "$pinned_hex" ]] && log_val "Fingerprint:" "$pinned_hex"
  else
    log_ok "Device enrolled"
  fi
}

cmd_auth_device() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "auth-device requires <server_ip:port>"
  ensure_existing_client_material
  require_file "$CLIENT_SERVER_PUB"
  log_header "Device authentication"
  log_info "Server: $1"
  sudo "$CLIENT_BIN" --server "$1"
  log_ok "Authentication complete"
}

cmd_client_local() {
  [[ $# -ge 1 ]] || die "client-local requires <server_ip:port>"
  local server_addr="$1"; shift
  local setup_flags=()

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --pairing-token)
        [[ $# -ge 2 ]] || die "--pairing-token requires a value"
        setup_flags+=(--pairing-token "$2"); shift 2 ;;
      --allow-tofu-setup)
        setup_flags+=(--allow-tofu-setup); shift ;;
      *) die "client-local: unknown option: $1" ;;
    esac
  done

  ensure_existing_client_material
  log_header "Local client"
  log_info "Server: $server_addr"
  log_step "Running setup..."
  sudo "$CLIENT_BIN" --server "$server_addr" --setup "${setup_flags[@]}"
  log_ok "Setup complete"
  log_step "Running AUTH..."
  sudo "$CLIENT_BIN" --server "$server_addr"
  log_ok "AUTH complete"
}

cmd_make_offline_proof() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "make-offline-proof requires <output_file> and flags"
  local out="$1"; shift
  ensure_existing_client_material
  sudo "$CLIENT_BIN" --make-offline-proof "$out" "$@"
}

cmd_verify_offline_proof() {
  require_bin "$SERVER_BIN"
  [[ $# -ge 1 ]] || die "verify-offline-proof requires <proof_file> and flags"
  local proof="$1"; shift
  ensure_existing_server_material
  cd "$SERVER_STATE_DIR"
  sudo "$SERVER_BIN" --verify-offline-proof "$proof" "$@"
}

cmd_make_client_continuity_proof() {
  require_bin "$CLIENT_BIN"
  [[ $# -ge 1 ]] || die "make-client-continuity-proof requires <output_file>"
  local out="$1"; shift
  ensure_existing_client_material
  sudo "$CLIENT_BIN" --make-client-continuity-proof "$out" "$@"
}

cmd_verify_server_continuity_proof() {
  require_bin "$CLIENT_BIN"
  [[ $# -eq 1 ]] || die "verify-server-continuity-proof requires <proof_file>"
  ensure_existing_client_material
  sudo "$CLIENT_BIN" --verify-server-continuity-proof "$1"
}

cmd_make_server_continuity_proof() {
  require_bin "$SERVER_BIN"
  [[ $# -ge 1 ]] || die "make-server-continuity-proof requires <output_file> and flags"
  local out="$1"; shift
  ensure_existing_server_material
  cd "$SERVER_STATE_DIR"
  sudo "$SERVER_BIN" --make-server-continuity-proof "$out" "$@"
}

cmd_verify_client_continuity_proof() {
  require_bin "$SERVER_BIN"
  [[ $# -eq 1 ]] || die "verify-client-continuity-proof requires <proof_file>"
  ensure_existing_server_material
  cd "$SERVER_STATE_DIR"
  sudo "$SERVER_BIN" --verify-client-continuity-proof "$1"
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

cmd_status() {
  log_header "ZK-ARCHE status (raw public-key flow)"

  echo -e "\n${_W}Binaries${_N}"
  [[ -x "$SERVER_BIN" ]] && log_ok "server binary: $SERVER_BIN" || log_warn "server binary: not built ($SERVER_BIN)"
  [[ -x "$CLIENT_BIN" ]] && log_ok "client binary: $CLIENT_BIN" || log_warn "client binary: not built ($CLIENT_BIN)"

  echo -e "\n${_W}State root${_N}"
  log_val "path:" "$BASE_STATE_DIR"

  echo -e "\n${_W}Server state${_N}  ($SERVER_STATE_DIR)"
  _status_file "$SERVER_SK_FILE" "server static key"
  _status_file "$SERVER_REGISTRY" "device registry"
  _status_file "$SERVER_REGISTRY_BAK" "device registry backup"
  _status_file "$SERVER_REPLAY_CACHE" "replay cache"
  _status_file "$SERVER_OFFLINE_COUNTERS" "offline counters"
  _status_file "$SERVER_CONTINUITY_FILE" "server continuity state"
  _status_file "$SERVER_CLIENT_CONT_TRACKS" "client continuity tracks"
  _status_file "$SERVER_PUB_HEX_FILE" "server pub hex cache"

  if [[ -x "$SERVER_BIN" ]]; then
    local spub
    spub="$(derive_server_pub_hex 2>/dev/null || true)"
    [[ -n "$spub" ]] && log_val "live server_pub:" "$spub"
  fi

  echo -e "\n${_W}Client state${_N}  ($CLIENT_STATE_DIR)"
  _status_file "$CLIENT_DEVICE_ROOT" "device root"
  _status_file "$CLIENT_SERVER_PUB" "pinned server pub"
  _status_file "$CLIENT_OFFLINE_COUNTER" "offline counter"
  _status_file "$CLIENT_CONTINUITY_FILE" "client continuity state"
  _status_file "$CLIENT_SERVER_CONT_TRACK" "server continuity track"

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

  echo -e "\n${_W}Generated helper files${_N}  ($GENERATED_DIR)"
  if [[ -x "$IDENT_HELPER_BIN" ]]; then
    _status_file "$IDENT_HELPER_BIN" "identity helper"
  else
    log_warn "identity helper: absent"
  fi
}

cmd_reset_client() {
  log_warn "Resetting client state: $CLIENT_STATE_DIR"
  sudo rm -rf "$CLIENT_STATE_DIR"
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
             "$SERVER_OFFLINE_COUNTERS" \
             "$SERVER_CONTINUITY_FILE" \
             "$SERVER_CLIENT_CONT_TRACKS" \
             "${SERVER_STATE_DIR}/server_pub.bin" \
             "$SERVER_PUB_HEX_FILE"
  rm -f "$IDENT_HELPER_SRC" "$IDENT_HELPER_BIN"
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
    start-server) cmd_start_server "$@" ;;
    server-local) cmd_server_local "$@" ;;
    setup-device) cmd_setup_device "$@" ;;
    auth-device) cmd_auth_device "$@" ;;
    client-local) cmd_client_local "$@" ;;
    pin-server) cmd_pin_server "$@" ;;
    show-pinned-key) cmd_show_pinned_key "$@" ;;
    print-device-id) cmd_print_device_id "$@" ;;
    print-server-pub) cmd_print_server_pub "$@" ;;
    make-offline-proof) cmd_make_offline_proof "$@" ;;
    verify-offline-proof) cmd_verify_offline_proof "$@" ;;
    make-client-continuity-proof) cmd_make_client_continuity_proof "$@" ;;
    verify-server-continuity-proof) cmd_verify_server_continuity_proof "$@" ;;
    make-server-continuity-proof) cmd_make_server_continuity_proof "$@" ;;
    verify-client-continuity-proof) cmd_verify_client_continuity_proof "$@" ;;
    status) cmd_status "$@" ;;
    reset-client) cmd_reset_client "$@" ;;
    reset-server) cmd_reset_server "$@" ;;
    reset-all) cmd_reset_all "$@" ;;
    -h|--help|help) usage ;;
    *) log_error "Unknown command: $cmd"; usage; exit 1 ;;
  esac
}

main "$@"
