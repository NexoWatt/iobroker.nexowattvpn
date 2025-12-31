# Host Auto-Install (Factory/Provisioning)

This directory contains **systemd units and scripts** to make the NexoWattVPN setup **fully automatic**
on your own devices.

## What it does
- Installs prerequisites (`wireguard-tools`, `nftables`) on Debian/Ubuntu/Raspberry Pi OS (via `apt-get`)
- Enables `nftables`
- Ensures `net.ipv4.ip_forward=0` (host-only VPN policy)
- Writes `/etc/sudoers.d/nexowattvpn` so the adapter can run `lib/root-helper.js` via `sudo -n`
- Retries via timer until done, then disables itself

## Install (run once as root during provisioning)
```bash
sudo ./host/install-host-autoinstall.sh
```

After that, the customer can install the adapter in ioBroker, and the host setup will run automatically.
