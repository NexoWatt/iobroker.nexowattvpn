#!/usr/bin/env bash
set -euo pipefail

# NexoWattVPN Host Auto-Installer (root)
# Purpose:
# - Install prerequisites (wireguard-tools, nftables) on Debian/Ubuntu/RPi OS
# - Enable nftables
# - Configure sudoers so ioBroker adapter can run the minimal root helper
# - Disable itself when done
#
# This script is intended to be triggered automatically by systemd (path/timer).
# It is safe to run multiple times (idempotent).

SERVICE_USER="${SERVICE_USER:-iobroker}"
HELPER_PATH="${HELPER_PATH:-/opt/iobroker/node_modules/iobroker.nexowattvpn/lib/root-helper.js}"
SUDOERS_FILE="${SUDOERS_FILE:-/etc/sudoers.d/nexowattvpn}"
DONE_FILE="${DONE_FILE:-/var/lib/nexowattvpn/autoinstall.done}"

log() {
  echo "[NexoWattVPN][autoinstall] $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_done() {
  [[ -f "$DONE_FILE" ]]
}

mark_done() {
  mkdir -p "$(dirname "$DONE_FILE")"
  date -Is >"$DONE_FILE"
}

detect_node_path() {
  local node_path=""
  if need_cmd su; then
    node_path="$(su -s /bin/bash -c 'node -p process.execPath' "$SERVICE_USER" 2>/dev/null || true)"
  fi

  if [[ -z "$node_path" ]]; then
    if [[ -x /opt/iobroker/nodejs/bin/node ]]; then
      node_path="/opt/iobroker/nodejs/bin/node"
    elif need_cmd node; then
      node_path="$(command -v node)"
    fi
  fi

  if [[ -z "$node_path" ]]; then
    log "ERROR: Could not detect node binary path."
    return 1
  fi

  echo "$node_path"
}

install_prereqs() {
  # Only install if required
  local missing=0
  need_cmd wg || missing=1
  need_cmd wg-quick || missing=1
  need_cmd nft || missing=1

  if [[ "$missing" -eq 0 ]]; then
    log "Prereqs already present (wg/wg-quick/nft)."
    return 0
  fi

  if ! need_cmd apt-get; then
    log "ERROR: apt-get not found. Cannot auto-install packages."
    return 1
  fi

  log "Installing prerequisites using apt-get (wireguard-tools, nftables)..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y wireguard-tools nftables
}

enable_nftables() {
  if need_cmd systemctl; then
    log "Enabling nftables service..."
    systemctl enable nftables >/dev/null 2>&1 || true
    systemctl start nftables >/dev/null 2>&1 || true
  fi
}

disable_ip_forwarding() {
  log "Ensuring IPv4 forwarding is disabled (host-only VPN target)..."
  sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1 || true
  mkdir -p /etc/sysctl.d
  cat >/etc/sysctl.d/99-nexowattvpn.conf <<EOF
net.ipv4.ip_forward=0
EOF
}

write_sudoers() {
  local node_path
  node_path="$(detect_node_path)"

  if [[ ! -f "$HELPER_PATH" ]]; then
    log "Helper not found at $HELPER_PATH yet. Will retry later."
    return 2
  fi

  local line="${SERVICE_USER} ALL=(root) NOPASSWD: ${node_path} ${HELPER_PATH} *"
  local tmp
  tmp="$(mktemp)"
  echo "$line" >"$tmp"
  chmod 440 "$tmp"

  if [[ -f "$SUDOERS_FILE" ]]; then
    if cmp -s "$tmp" "$SUDOERS_FILE"; then
      log "sudoers file already up-to-date: $SUDOERS_FILE"
      rm -f "$tmp"
      return 0
    fi
  fi

  log "Writing sudoers file: $SUDOERS_FILE"
  mv "$tmp" "$SUDOERS_FILE"
  chmod 440 "$SUDOERS_FILE"

  if need_cmd visudo; then
    visudo -cf "$SUDOERS_FILE" >/dev/null
  fi
}

try_disable_units() {
  if need_cmd systemctl; then
    systemctl disable --now nexowattvpn-autoinstall.path >/dev/null 2>&1 || true
    systemctl disable --now nexowattvpn-autoinstall.timer >/dev/null 2>&1 || true
  fi
}

main() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log "ERROR: must run as root."
    exit 1
  fi

  if is_done; then
    log "Already done ($DONE_FILE). Exiting."
    exit 0
  fi

  # Attempt full setup
  install_prereqs || log "WARNING: prereq install failed (network/offline?). Will retry via timer."

  enable_nftables
  disable_ip_forwarding

  set +e
  write_sudoers
  rc=$?
  set -e

  if [[ "$rc" -eq 2 ]]; then
    log "Helper not installed yet; waiting for adapter installation."
    exit 0
  elif [[ "$rc" -ne 0 ]]; then
    log "WARNING: sudoers setup failed; will retry."
    exit 1
  fi

  # Final verification
  if need_cmd wg && need_cmd wg-quick && need_cmd nft; then
    log "All prerequisites present and sudoers configured."
    mark_done
    try_disable_units
    log "Autoinstall finished."
    exit 0
  fi

  log "WARNING: Not all prerequisites are present yet; will retry."
  exit 1
}

main "$@"
