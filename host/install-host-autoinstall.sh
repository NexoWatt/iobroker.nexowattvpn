#!/usr/bin/env bash
set -euo pipefail

# Install the NexoWattVPN host auto-installer (systemd units + script)
# Run as root during manufacturing/provisioning on your devices.

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: run as root"
  exit 1
fi

install -m 0755 "$SRC_DIR/nexowattvpn-autoinstall.sh" /usr/local/sbin/nexowattvpn-autoinstall.sh
install -m 0644 "$SRC_DIR/nexowattvpn-autoinstall.service" /etc/systemd/system/nexowattvpn-autoinstall.service
install -m 0644 "$SRC_DIR/nexowattvpn-autoinstall.path" /etc/systemd/system/nexowattvpn-autoinstall.path
install -m 0644 "$SRC_DIR/nexowattvpn-autoinstall.timer" /etc/systemd/system/nexowattvpn-autoinstall.timer

systemctl daemon-reload
systemctl enable --now nexowattvpn-autoinstall.path
systemctl enable --now nexowattvpn-autoinstall.timer

echo "OK: NexoWattVPN autoinstall installed and enabled."
echo "It will run automatically when the adapter is installed (helper path exists) and retry until done."
