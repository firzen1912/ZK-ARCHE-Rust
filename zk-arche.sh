#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_BIN="${PROJECT_ROOT}/target/release/server"
CLIENT_BIN="${PROJECT_ROOT}/target/release/client"
CLIENT_STATE_DIR="/var/lib/iot-auth"
SERVER_PUB_BIN="${PROJECT_ROOT}/server_pub.bin"
SERVER_PUB_HEX_FILE="${PROJECT_ROOT}/server_pub.hex"
LAST_BOOTSTRAP_FILE="${PROJECT_ROOT}/last_bootstrap.env"

usage() {
  cat <<'EOF'
ZK-ARCHE automation script

Usage:
  ./zk-arche.sh build
  ./zk-arche.sh add-bootstrap
  ./zk-arche.sh add-bootstrap <bootstrap_id_hex> <bootstrap_secret_hex>
  ./zk-arche.sh show-bootstrap
  ./zk-arche.sh start-server <bind_addr> [--pairing]
  ./zk-arche.sh server-local <bind_addr>
  ./zk-arche.sh pin-server <server_pub_hex>
  ./zk-arche.sh provision-bootstrap <bootstrap_id_hex> <bootstrap_secret_hex>
  ./zk-arche.sh setup-device <server_ip:port>
  ./zk-arche.sh auth-device <server_ip:port>
  ./zk-arche.sh client-local <server_ip:port> <server_pub_hex>
  ./zk-arche.sh reset-client
  ./zk-arche.sh reset-server
  ./zk-arche.sh full-device-onboard <server_ip:port> <bootstrap_id_hex> <bootstrap_secret_hex> <server_pub_hex>

Two-terminal local test:
  Terminal 1:
    ./zk-arche.sh server-local 127.0.0.1:4000

  Terminal 2:
    ./zk-arche.sh add-bootstrap
    ./zk-arche.sh show-bootstrap
    ./zk-arche.sh client-local 127.0.0.1:4000 <server_pub_hex>

Examples:
  ./zk-arche.sh build
  ./zk-arche.sh add-bootstrap
  ./zk-arche.sh show-bootstrap
  ./zk-arche.sh start-server 0.0.0.0:4000 --pairing
  ./zk-arche.sh server-local 127.0.0.1:4000
  ./zk-arche.sh client-local 127.0.0.1:4000 <server_pub_hex>
EOF
}

require_bin() {
  local bin="$1"
  if [[ ! -x "$bin" ]]; then
    echo "Error: binary not found or not executable: $bin" >&2
    echo "Build first with: cargo build --release" >&2
    exit 1
  fi
}
require_file() {
  local f="$1"
  if [[ ! -f "$f" ]]; then
    echo "Error: required file not found: $f" >&2
    exit 1
  fi
}

save_server_pub_from_hex() {
  local server_pub_hex="$1"

  if [[ ! "$server_pub_hex" =~ ^[0-9a-fA-F]{64}$ ]]; then
    echo "Error: server_pub_hex must be 32 bytes = 64 hex chars" >&2
    exit 1
  fi

  printf '%s' "$server_pub_hex" | xxd -r -p > "$SERVER_PUB_BIN"
  printf '%s\n' "$server_pub_hex" > "$SERVER_PUB_HEX_FILE"

  echo "[+] Saved server public key:"
  echo "    BIN: $SERVER_PUB_BIN"
  echo "    HEX: $SERVER_PUB_HEX_FILE"
}

build_release() {
  echo "[*] Building release binaries..."
  cargo build --release
  echo "[+] Build complete"
  echo "    Server: $SERVER_BIN"
  echo "    Client: $CLIENT_BIN"
}

add_bootstrap() {
  require_bin "$SERVER_BIN"

  local bootstrap_id bootstrap_secret

  if [[ $# -eq 0 ]]; then
    bootstrap_id="$(openssl rand -hex 32)"
    bootstrap_secret="$(openssl rand -hex 32)"
    echo "[*] Generated bootstrap credential"
  elif [[ $# -eq 2 ]]; then
    bootstrap_id="$1"
    bootstrap_secret="$2"
  else
    echo "Error: add-bootstrap expects 0 or 2 arguments" >&2
    exit 1
  fi

  echo "[*] Adding bootstrap credential to registry..."
  "$SERVER_BIN" --add-bootstrap "$bootstrap_id" "$bootstrap_secret"

  echo
  echo "[+] Bootstrap credential registered"
  echo "BOOTSTRAP_ID=$bootstrap_id"
  echo "BOOTSTRAP_SECRET=$bootstrap_secret"

  cat > "$LAST_BOOTSTRAP_FILE" <<EOF
BOOTSTRAP_ID=$bootstrap_id
BOOTSTRAP_SECRET=$bootstrap_secret
EOF
  echo "[+] Saved to $LAST_BOOTSTRAP_FILE"
}

show_bootstrap() {
  require_file "$LAST_BOOTSTRAP_FILE"
  echo "[*] Last generated bootstrap values:"
  cat "$LAST_BOOTSTRAP_FILE"
}

start_server() {
  require_bin "$SERVER_BIN"

  if [[ $# -lt 1 ]]; then
    echo "Error: start-server requires <bind_addr>" >&2
    exit 1
  fi

  local bind_addr="$1"
  shift || true

  echo "[*] Starting verifier on $bind_addr ..."
  exec "$SERVER_BIN" --bind "$bind_addr" "$@"
}

server_local() {
  require_bin "$SERVER_BIN"

  if [[ $# -ne 1 ]]; then
    echo "Error: server-local requires <bind_addr>" >&2
    exit 1
  fi

  local bind_addr="$1"

  echo "[*] Local test mode: server terminal"
  echo "[*] Bind: $bind_addr"
  echo "[*] Pairing mode enabled"
  echo
  echo "[*] Keep this terminal open."
  echo "[*] In Terminal 2, run:"
  echo "    ./zk-arche.sh add-bootstrap"
  echo "    ./zk-arche.sh show-bootstrap"
  echo "    ./zk-arche.sh client-local $bind_addr <server_pub_hex>"
  echo
  exec "$SERVER_BIN" --bind "$bind_addr" --pairing
}

pin_server() {
  require_bin "$CLIENT_BIN"

  if [[ $# -ne 1 ]]; then
    echo "Error: pin-server requires <server_pub_hex>" >&2
    exit 1
  fi

  local server_pub="$1"

  echo "[*] Saving server public key in project root..."
  save_server_pub_from_hex "$server_pub"

  echo "[*] Pinning server public key..."
  "$CLIENT_BIN" --pin-server-pub "$server_pub"
  echo "[+] Server public key pinned"
}

provision_bootstrap() {
  require_bin "$CLIENT_BIN"

  if [[ $# -ne 2 ]]; then
    echo "Error: provision-bootstrap requires <bootstrap_id_hex> <bootstrap_secret_hex>" >&2
    exit 1
  fi

  local bootstrap_id="$1"
  local bootstrap_secret="$2"

  echo "[*] Writing bootstrap credentials to device..."
  "$CLIENT_BIN" --provision-bootstrap "$bootstrap_id" "$bootstrap_secret"
  echo "[+] Bootstrap credentials provisioned"
}

setup_device() {
  require_bin "$CLIENT_BIN"

  if [[ $# -ne 1 ]]; then
    echo "Error: setup-device requires <server_ip:port>" >&2
    exit 1
  fi

  local server_addr="$1"

  echo "[*] Running zero-touch provisioning against $server_addr ..."
  "$CLIENT_BIN" --server "$server_addr" --setup
  echo "[+] Device setup complete"
}

auth_device() {
  require_bin "$CLIENT_BIN"

  if [[ $# -ne 1 ]]; then
    echo "Error: auth-device requires <server_ip:port>" >&2
    exit 1
  fi

  local server_addr="$1"

  echo "[*] Authenticating device against $server_addr ..."
  "$CLIENT_BIN" --server "$server_addr"
}

client_local() {
  require_bin "$CLIENT_BIN"
  require_file "$LAST_BOOTSTRAP_FILE"

  if [[ $# -ne 2 ]]; then
    echo "Error: client-local requires <server_ip:port> <server_pub_hex>" >&2
    exit 1
  fi

  local server_addr="$1"
  local server_pub="$2"

  # shellcheck disable=SC1090
  source "$LAST_BOOTSTRAP_FILE"

  : "${BOOTSTRAP_ID:?missing BOOTSTRAP_ID in $LAST_BOOTSTRAP_FILE}"
  : "${BOOTSTRAP_SECRET:?missing BOOTSTRAP_SECRET in $LAST_BOOTSTRAP_FILE}"

  echo "[*] Local test mode: client terminal"
  echo "[*] Server: $server_addr"
  echo "[*] Using bootstrap values from: $LAST_BOOTSTRAP_FILE"
  echo

  echo "[1/3] Provision bootstrap..."
  "$CLIENT_BIN" --provision-bootstrap "$BOOTSTRAP_ID" "$BOOTSTRAP_SECRET"

  echo "[2/3] Save and pin server public key..."
  save_server_pub_from_hex "$server_pub"
  "$CLIENT_BIN" --pin-server-pub "$server_pub"

  echo "[3/3] Run setup..."
  "$CLIENT_BIN" --server "$server_addr" --setup

  echo
  echo "[+] Local onboarding complete"
  echo "[*] To authenticate later, run:"
  echo "    ./zk-arche.sh auth-device $server_addr"
}

reset_client() {
  echo "[*] Resetting client state in $CLIENT_STATE_DIR ..."
  sudo rm -rf "$CLIENT_STATE_DIR"
  echo "[+] Client state removed"
}

reset_server() {
  echo "[*] Resetting server state..."
  rm -f "${PROJECT_ROOT}/registry.bin" \
        "${PROJECT_ROOT}/bootstrap_registry.bin" \
        "${PROJECT_ROOT}/server_sk.bin" \
        "${PROJECT_ROOT}/server_pub.bin" \
        "${PROJECT_ROOT}/server_pub.hex" \
        "${PROJECT_ROOT}/last_bootstrap.env"
  echo "[+] Server state removed"
}

full_device_onboard() {
  require_bin "$CLIENT_BIN"

  if [[ $# -ne 4 ]]; then
    echo "Error: full-device-onboard requires <server_ip:port> <bootstrap_id_hex> <bootstrap_secret_hex> <server_pub_hex>" >&2
    exit 1
  fi

  local server_addr="$1"
  local bootstrap_id="$2"
  local bootstrap_secret="$3"
  local server_pub="$4"

  echo "[*] Starting full device onboarding..."
  "$CLIENT_BIN" --provision-bootstrap "$bootstrap_id" "$bootstrap_secret"

  echo "[*] Saving server public key in project root..."
  save_server_pub_from_hex "$server_pub"

  "$CLIENT_BIN" --pin-server-pub "$server_pub"
  "$CLIENT_BIN" --server "$server_addr" --setup
  echo "[+] Full device onboarding complete"
}

main() {
  if [[ $# -lt 1 ]]; then
    usage
    exit 1
  fi

  local cmd="$1"
  shift || true

  case "$cmd" in
    build)
      build_release
      ;;
    add-bootstrap)
      add_bootstrap "$@"
      ;;
    show-bootstrap)
      show_bootstrap
      ;;
    start-server)
      start_server "$@"
      ;;
    server-local)
      server_local "$@"
      ;;
    pin-server)
      pin_server "$@"
      ;;
    provision-bootstrap)
      provision_bootstrap "$@"
      ;;
    setup-device)
      setup_device "$@"
      ;;
    auth-device)
      auth_device "$@"
      ;;
    client-local)
      client_local "$@"
      ;;
    reset-client)
      reset_client
      ;;
    reset-server)
      reset_server
      ;;
    full-device-onboard)
      full_device_onboard "$@"
      ;;
    -h|--help|help)
      usage
      ;;
    *)
      echo "Error: unknown command: $cmd" >&2
      usage
      exit 1
      ;;
  esac
}

main "$@"
