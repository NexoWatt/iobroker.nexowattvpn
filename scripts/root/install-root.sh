#!/usr/bin/env bash
set -euo pipefail

# Root setup for NexoWattVPN
# - installs /usr/local/sbin/nexowattvpn-helper
# - creates sudoers rule for user 'iobroker'
# - installs + enables systemd service to (re)apply wg firewall rules at boot

HELPER_SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HELPER_SRC_DIR}/../.." && pwd)"

HELPER_SRC="${REPO_ROOT}/scripts/root/nexowattvpn-helper"
HELPER_DST="/usr/local/sbin/nexowattvpn-helper"

SUDOERS_FILE="/etc/sudoers.d/nexowattvpn"
SYSTEMD_SERVICE="/etc/systemd/system/nexowattvpn-firewall.service"

IOBROKER_DATA_DIR="/opt/iobroker/iobroker-data/nexowattvpn"
FIREWALL_CFG="${IOBROKER_DATA_DIR}/firewall.json"
ROLES_CFG="${IOBROKER_DATA_DIR}/roles.json"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run as root: sudo bash $0" >&2
    exit 1
  fi
}

need_root

if [[ ! -f "${HELPER_SRC}" ]]; then
  echo "Helper source not found: ${HELPER_SRC}" >&2
  exit 1
fi

echo "Installing helper to ${HELPER_DST} ..."
install -m 0755 "${HELPER_SRC}" "${HELPER_DST}"

echo "Creating ioBroker data dir: ${IOBROKER_DATA_DIR} ..."
mkdir -p "${IOBROKER_DATA_DIR}"
# Do not fail if user/group doesn't exist yet; but typically it exists
chown iobroker:iobroker "${IOBROKER_DATA_DIR}" || true
chmod 0750 "${IOBROKER_DATA_DIR}"

if [[ ! -f "${ROLES_CFG}" ]]; then
  echo "Creating default roles.json ..."
  cat > "${ROLES_CFG}" <<EOF
{
  "version": 1,
  "peers": {}
}
EOF
  chown iobroker:iobroker "${ROLES_CFG}" || true
  chmod 0640 "${ROLES_CFG}"
fi

if [[ ! -f "${FIREWALL_CFG}" ]]; then
  echo "Creating default firewall.json ..."
  cat > "${FIREWALL_CFG}" <<EOF
{
  "version": 1,
  "rolesFile": "${ROLES_CFG}",
  "servicePortsTcp": "8081,8082",
  "customerPortsTcp": "8082",
  "blockForwarding": true,
  "allowPing": false
}
EOF
  chown iobroker:iobroker "${FIREWALL_CFG}" || true
  chmod 0640 "${FIREWALL_CFG}"
fi

echo "Writing sudoers rule ${SUDOERS_FILE} ..."
cat > "${SUDOERS_FILE}" <<EOF
# Allow ioBroker adapter to run ONLY the audited helper without password
iobroker ALL=(root) NOPASSWD: ${HELPER_DST} *
EOF
chmod 0440 "${SUDOERS_FILE}"

echo "Writing systemd service ${SYSTEMD_SERVICE} ..."
cat > "${SYSTEMD_SERVICE}" <<EOF
[Unit]
Description=NexoWattVPN - Apply firewall rules for PiVPN/WireGuard
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${HELPER_DST} apply-firewall --config ${FIREWALL_CFG} --json
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Enabling service..."
systemctl enable nexowattvpn-firewall.service

echo "Applying firewall rules now..."
systemctl start nexowattvpn-firewall.service || true

echo
echo "Root setup done."
echo "Next:"
echo "  1) Install/start the ioBroker adapter instance (nexowattvpn.0)"
echo "  2) Open adapter config in Admin and click: 'Status aktualisieren' + 'Konfiguration anwenden'"
