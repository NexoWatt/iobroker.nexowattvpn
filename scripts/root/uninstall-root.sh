#!/usr/bin/env bash
set -euo pipefail

HELPER_DST="/usr/local/sbin/nexowattvpn-helper"
SUDOERS_FILE="/etc/sudoers.d/nexowattvpn"
SYSTEMD_SERVICE="/etc/systemd/system/nexowattvpn-firewall.service"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run as root: sudo bash $0" >&2
    exit 1
  fi
}
need_root

echo "Stopping and disabling service..."
systemctl stop nexowattvpn-firewall.service >/dev/null 2>&1 || true
systemctl disable nexowattvpn-firewall.service >/dev/null 2>&1 || true

echo "Removing systemd unit..."
rm -f "${SYSTEMD_SERVICE}"
systemctl daemon-reload

echo "Removing sudoers rule..."
rm -f "${SUDOERS_FILE}"

echo "Removing helper..."
rm -f "${HELPER_DST}"

echo "Done. (Note: iptables rules may still be present; use adapter button 'Firewall entfernen' or run helper clear-firewall before uninstall.)"
