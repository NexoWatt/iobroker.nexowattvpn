#!/usr/bin/env bash
set -euo pipefail

# One-time bootstrap helper for ioBroker.nexowattvpn (NexoWattVPN)
# - installs required packages (wireguard-tools, nftables)
# - enables nftables (best-effort)
# - writes /etc/sudoers.d/nexowattvpn so the adapter can run root-helper via sudo -n
#
# Preferred method: copy the Bootstrap command shown in the Admin UI (Install tab).
# This script is a convenience fallback.

SERVICE_USER="${1:-iobroker}"

# Try to find the node binary used by ioBroker. Adjust if your installation differs.
NODE_BIN=""
if command -v node >/dev/null 2>&1; then
  NODE_BIN="$(command -v node)"
fi

# ioBroker often ships its own node; common location:
if [[ -z "$NODE_BIN" && -x /opt/iobroker/nodejs/bin/node ]]; then
  NODE_BIN="/opt/iobroker/nodejs/bin/node"
fi

if [[ -z "$NODE_BIN" ]]; then
  echo "ERROR: Could not find node binary. Provide PATH or edit this script." >&2
  exit 1
fi

HELPER="/opt/iobroker/node_modules/iobroker.nexowattvpn/lib/root-helper.js"
if [[ ! -f "$HELPER" ]]; then
  echo "ERROR: Helper not found at $HELPER. Install the adapter first." >&2
  exit 1
fi

PAYLOAD="$($NODE_BIN - <<NODE
const payload = {
  cfg: { serviceUser: process.argv[1] },
  serviceUser: process.argv[1],
  nodePath: process.argv[2],
  helperPath: process.argv[3],
};
process.stdout.write(Buffer.from(JSON.stringify(payload), 'utf8').toString('base64'));
NODE
"$SERVICE_USER" "$NODE_BIN" "$HELPER")"

echo "Running bootstrap as root ..."
sudo "$NODE_BIN" "$HELPER" bootstrap --json "$PAYLOAD"
