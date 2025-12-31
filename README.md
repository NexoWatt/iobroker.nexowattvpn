# NexoWattVPN (ioBroker Adapter)

**Adapter name:** `nexowattvpn`  
**Repository/package name:** `iobroker.nexowattvpn`

This adapter manages a **WireGuard** VPN on the ioBroker host and enforces a **strict firewall policy on the WireGuard interface**:

- ✅ **Allowed over VPN**: **TCP** to the ioBroker host on **8081, 8082, 8188, 8086** (default)
- ❌ **Blocked over VPN**: everything else on the wg interface
- ❌ **Blocked**: forwarding from the wg interface (prevents pivoting into your LAN)

> Security goal: **VPN clients can reach only the ioBroker host services you allow**, not the rest of your network.

---

## 1. Requirements

### Host OS
- Linux host (Debian/Ubuntu/Raspberry Pi OS recommended)

### Packages
Install WireGuard tools and firewall utilities.

Option A (recommended): use the **Install** tab in the adapter (prereq check + one-time bootstrap command).

Option B (manual):

```bash
sudo apt update
sudo apt install -y wireguard-tools nftables
```

---

## 2. How it works

The adapter runs as the normal `iobroker` user and calls a **minimal root helper**:

- `lib/root-helper.js` (must run as root via `sudo`)
- Creates/updates: `/etc/wireguard/<iface>.conf`
- Starts/stops: `wg-quick up|down <iface>`
- Applies firewall: **nftables** (fixed backend)

---

## 3. One-time bootstrap (required)

The adapter needs permission to run `lib/root-helper.js` as root.

### 3.1 Preferred: bootstrap command from Admin UI

Open **Admin → Instances → NexoWattVPN → Install** and copy the generated **Bootstrap command**.
Run it once on the host in a terminal.

This will:
- install `wireguard-tools` + `nftables` (Debian/Ubuntu/Raspberry Pi OS)
- enable nftables (best-effort)
- create `/etc/sudoers.d/nexowattvpn`

### 3.2 Manual alternative: sudoers configuration

Create a sudo rule so the adapter can execute the helper **without password**.

### 3.2.1 Determine paths
- ioBroker node binary used by adapters: often `/usr/bin/node` or `/opt/iobroker/nodejs/bin/node`
- helper path after install:  
  `/opt/iobroker/node_modules/iobroker.nexowattvpn/lib/root-helper.js`

### 3.2.2 Create sudoers file
Open:

```bash
sudo visudo -f /etc/sudoers.d/nexowattvpn
```

Add (adjust node path if needed):

```text
iobroker ALL=(root) NOPASSWD: /usr/bin/node /opt/iobroker/node_modules/iobroker.nexowattvpn/lib/root-helper.js *
```

Notes:
- The adapter uses `sudo -n` (non-interactive). If sudo is not configured correctly, commands will fail.
- For higher security, you can restrict arguments more tightly (advanced sudoers usage).

---

## 4. Support access (opt-in)

This adapter includes an optional **Support** tab that can add a **dedicated support peer** to WireGuard.

Design goals:
- customer explicitly enables/disables support access
- no hidden permanent access
- support access can be time-limited (expiry)
- vendor uses their own key pair; the adapter never handles vendor private keys

When enabled, the adapter will output a **client config template** with a placeholder `PrivateKey = <FILL_IN_YOUR_PRIVATE_KEY>`.

---

## 5. Adapter configuration (Admin UI)

Go to **Admin → Instances → NexoWattVPN**:

### Server tab
- **WireGuard interface name**: `wg-nexowattvpn` (default)
- **Listen port**: `51820/udp` (default)
- **VPN network**: `10.80.80.0/24` (default)
- **Host VPN address**: `10.80.80.1/24` (default)
- **Endpoint hostname**: e.g. `myhome.dyndns.org` (needed for remote client configs)
- **Allowed TCP ports via VPN**: default `8081,8082,8188,8086`
- Buttons:
  - *Initialize/Update server config*
  - *Apply firewall rules*
  - *Start/Stop VPN*

### Profiles tab
- Enter a **profile name** (e.g. `phone-john`).
  - Allowed characters: `a-z A-Z 0-9 _ . -` (no spaces)
- Optional **password**:
  - If provided, a **PSK is derived** from it (adds an extra secret)
  - If empty, a **random PSK** is generated (recommended)
- Click **Create/Rotate profile + generate client config + QR**
- The adapter stores the **last generated output** in states and shows it in the Admin UI:
  - **Client config** (for manual copy/paste)
  - **QR code** (WireGuard apps can import via QR)
- Use **Clear last generated output** to remove the last config from ioBroker states.
- Revoke profiles:
  - Select a profile from the dropdown
  - Click **Revoke selected profile**

---

## 6. Networking notes (important)

### 6.1 This adapter does NOT automatically set up router port-forwarding
For remote access from the internet you typically need:
- Router forward UDP `listenPort` (default 51820) → ioBroker host.

### 6.2 Restriction to host only
The generated client config uses:

- `AllowedIPs = <hostVpnIp>/32`

This ensures the client routes **only the ioBroker host** through the VPN (no `0.0.0.0/0`, no LAN subnets).

### 6.3 Services must listen on the host address

The Admin UI includes a **Binding & exposure check** that inspects ioBroker instances (native.port/native.bind) for the allowed ports and shows whether services are bound to `0.0.0.0` (exposed) or to the WG host IP (VPN-only).
If your ioBroker Admin/Web/VIS are bound to `127.0.0.1` only, they will not be reachable via VPN.
Ensure they listen on `0.0.0.0` or on the wg address.

---

## 7. Files managed by this adapter

- WireGuard server config:
  - `/etc/wireguard/<iface>.conf`
- Firewall table:
  - nftables table: `inet nexowattvpn` (chains `input` + `forward`)

---

## 8. Disclaimer

This project is a **generated scaffold**. Review the root helper and firewall rules carefully before use in production.
You are responsible for your network security posture, updates, and hardening.

---

## License

MIT

---

## 3.3 Factory zero-touch setup (Model A, fully automatic on your devices)

> ✅ **Note (v0.0.7+):** The `host/` directory is now included in the npm package. In older versions the `host/` folder was missing after `npm install`, so the factory auto-installer scripts could not be executed from `node_modules`.

If you sell your own systems and want **zero manual steps for the end user**, install the **host auto-installer**
(systemd units + root script) once during manufacturing/provisioning:

```bash
sudo /opt/iobroker/node_modules/iobroker.nexowattvpn/host/install-host-autoinstall.sh
```

This will:
- enable a systemd **path trigger** and **retry timer**
- when the adapter is installed (helper file exists), it will automatically:
  - install `wireguard-tools` + `nftables` (Debian/Ubuntu/RPi OS)
  - enable `nftables`
  - write `/etc/sudoers.d/nexowattvpn` for the minimal root helper

After the first successful run it writes:

- `/var/lib/nexowattvpn/autoinstall.done`

…and disables itself.

> Note: Automatic package installation requires network connectivity / working apt repositories.
> If your devices are shipped offline, pre-install the packages in your base image and the auto-installer will
> only configure sudoers and sysctl.

