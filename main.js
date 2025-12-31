'use strict';

/**
 * ioBroker adapter: nexowattvpn
 * A local UI helper for PiVPN (WireGuard/OpenVPN).
 *
 * IMPORTANT:
 * - Most PiVPN operations require root. This adapter is designed to work with a minimal sudoers rule-set.
 * - See README.md for required system preparation.
 */

const utils = require('@iobroker/adapter-core');
const { execFile, spawn } = require('child_process');
const os = require('os');
const path = require('path');
const QRCode = require('qrcode');

class Nexowattvpn extends utils.Adapter {
  constructor(options = {}) {
    super({
      ...options,
      name: 'nexowattvpn',
    });

    this.protocol = null; // 'wireguard' | 'openvpn'
    this.setupVars = {};
    this.serverAddresses = { ipv4: null, ipv6: null }; // VPN interface addresses (wg0/tun0)
    this.statusTimer = null;

    this.on('ready', this.onReady.bind(this));
    this.on('message', this.onMessage.bind(this));
    this.on('unload', this.onUnload.bind(this));
  }

  /** @returns {boolean} */
  isRoot() {
    return typeof process.getuid === 'function' && process.getuid() === 0;
  }

  /** @returns {string} */
  get pivpnBin() {
    return (this.config && this.config.pivpnBinary) ? String(this.config.pivpnBinary) : '/usr/local/bin/pivpn';
  }

  /**
   * Execute a command.
   * @param {string} cmd
   * @param {string[]} args
   * @param {{sudo?: boolean, timeoutMs?: number}} [opts]
   * @returns {Promise<{stdout: string, stderr: string}>}
   */
  exec(cmd, args, opts = {}) {
    const timeoutMs = opts.timeoutMs || 120000;
    const useSudo = !!opts.sudo && !this.isRoot();

    let finalCmd = cmd;
    let finalArgs = args;

    if (useSudo) {
      finalCmd = 'sudo';
      finalArgs = ['-n', cmd, ...args];
    }

    return new Promise((resolve, reject) => {
      execFile(finalCmd, finalArgs, {
        timeout: timeoutMs,
        maxBuffer: 20 * 1024 * 1024,
        env: process.env,
      }, (error, stdout, stderr) => {
        const out = (stdout || '').toString();
        const err = (stderr || '').toString();

        if (error) {
          const e = new Error(`${finalCmd} ${finalArgs.join(' ')} failed: ${error.message}${err ? ` | ${err.trim()}` : ''}`);
          // Attach outputs for troubleshooting
          e.stdout = out;
          e.stderr = err;
          e.code = error.code;
          return reject(e);
        }

        resolve({ stdout: out, stderr: err });
      });
    });
  }

  /**
   * Read a file via cat, optionally using sudo.
   * @param {string} filePath
   * @param {boolean} [sudo]
   * @returns {Promise<string>}
   */
  async readFile(filePath, sudo = true) {
    const { stdout } = await this.exec('/bin/cat', [filePath], { sudo: sudo && this.config.useSudo !== false });
    return stdout;
  }

    /**
   * WireGuard: set AllowedIPs line inside a client config (in-place).
   * Uses sed -i to preserve file permissions and ownership.
   * @param {string} filePath
   * @param {string} allowedIps
   */
  async setWireguardAllowedIps(filePath, allowedIps) {
    const allowed = String(allowedIps || '').trim();
    if (!allowed) throw new Error('AllowedIPs must not be empty.');

    // Escape for sed replacement part:
    // - backslashes
    // - ampersand (sed replacement token)
    // - delimiter |
    const sedRepl = allowed
      .replace(/\\/g, '\\\\')
      .replace(/&/g, '\\&')
      .replace(/\|/g, '\\|')
      .replace(/"/g, '\\"');

    const script = [
      'set -euo pipefail',
      `FILE="${filePath.replace(/"/g, '\\"')}"`,
      'if [ ! -f "$FILE" ]; then echo "Missing file: $FILE" >&2; exit 2; fi',
      `sed -i -E "s|^[[:space:]]*AllowedIPs[[:space:]]*=[[:space:]]*.*$|AllowedIPs = ${sedRepl}|" "$FILE"`,
    ].join('\n');

    await this.exec('/bin/bash', ['-lc', script], { sudo: this.config.useSudo !== false, timeoutMs: 60000 });
  }

  /**
   * Parse setupVars.conf style content.
   * @param {string} content
   * @returns {Record<string, string>}
   */
  parseSetupVars(content) {
    /** @type {Record<string, string>} */
    const vars = {};
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const m = line.match(/^([A-Za-z0-9_]+)=(.*)$/);
      if (!m) continue;
      const key = m[1];
      let val = m[2].trim();
      // strip optional quotes
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      vars[key] = val;
    }
    return vars;
  }

  /**
   * Best-effort detection of PiVPN protocol.
   * @returns {Promise<'wireguard'|'openvpn'>}
   */
  async detectProtocol() {
    const protoOverride = (this.config.protocol || 'auto').toLowerCase();

    const candidates = [];
    if (protoOverride === 'wireguard' || protoOverride === 'openvpn') {
      candidates.push(protoOverride);
    } else {
      candidates.push('wireguard', 'openvpn');
    }

    // 1) Try /etc/pivpn/setupVars.conf (may contain VPN=wireguard/openvpn)
    try {
      const content = await this.readFile('/etc/pivpn/setupVars.conf', true);
      const vars = this.parseSetupVars(content);
      if (vars.VPN === 'wireguard' || vars.VPN === 'openvpn') {
        this.setupVars = vars;
        return vars.VPN;
      }
    } catch (e) {
      // ignore, fallback below
    }

    // 2) Try protocol-specific setupVars
    for (const proto of candidates) {
      const file = proto === 'wireguard'
        ? '/etc/pivpn/wireguard/setupVars.conf'
        : '/etc/pivpn/openvpn/setupVars.conf';
      try {
        const content = await this.readFile(file, true);
        this.setupVars = this.parseSetupVars(content);
        return proto;
      } catch (e) {
        // continue
      }
    }

    throw new Error('Could not detect PiVPN protocol. Is PiVPN installed and configured?');
  }

  /**
   * Determine VPN interface name used by PiVPN.
   * @returns {string}
   */
  getVpnInterface() {
    if (this.protocol === 'wireguard') return 'wg0';
    return 'tun0';
  }

  /**
   * Read server VPN addresses from wg0.conf (WireGuard).
   * @returns {Promise<{ipv4: string|null, ipv6: string|null}>}
   */
  async detectWireguardServerAddresses() {
    const wg0 = await this.readFile('/etc/wireguard/wg0.conf', true);
    const addrLine = wg0.split(/\r?\n/).find(l => /^\s*Address\s*=/.test(l));
    if (!addrLine) return { ipv4: null, ipv6: null };

    const value = addrLine.split('=')[1].trim();
    const parts = value.split(',').map(s => s.trim());
    let ipv4 = null;
    let ipv6 = null;

    for (const p of parts) {
      const ip = p.split('/')[0].trim();
      if (ip.includes(':')) ipv6 = ip;
      else ipv4 = ip;
    }
    return { ipv4, ipv6 };
  }

  /**
   * Read install_home.
   * @returns {string|null}
   */
  getInstallHome() {
    if (this.setupVars.install_home) return this.setupVars.install_home;
    if (this.setupVars.install_user) return `/home/${this.setupVars.install_user}`;
    return null;
  }

  /**
   * Get expected client config path for a given client name.
   * @param {string} clientName
   * @returns {string}
   */
  getClientConfigPath(clientName) {
    const home = this.getInstallHome();
    if (this.protocol === 'wireguard') {
      if (home) return path.posix.join(home, 'configs', `${clientName}.conf`);
      return `/etc/wireguard/configs/${clientName}.conf`;
    }
    // openvpn
    if (home) return path.posix.join(home, 'ovpns', `${clientName}.ovpn`);
    return `/etc/pivpn/${this.protocol}/ovpns/${clientName}.ovpn`;
  }

  /**
   * Parse ports CSV string.
   * @param {string} csv
   * @returns {number[]}
   */
  parsePorts(csv) {
    const ports = new Set();
    if (!csv) return [];
    for (const part of String(csv).split(',')) {
      const p = part.trim();
      if (!p) continue;
      const n = Number(p);
      if (Number.isInteger(n) && n > 0 && n <= 65535) ports.add(n);
    }
    return Array.from(ports).sort((a, b) => a - b);
  }

  /**
   * Best effort: detect ports from ioBroker instances.
   * We err on the side of including more ports to avoid breaking access.
   * @returns {Promise<number[]>}
   */
  async detectIoBrokerPorts() {
    const ports = new Set();

    try {
      const view = await this.getObjectViewAsync('system', 'instance', {
        startkey: 'system.adapter.',
        endkey: 'system.adapter.\u9999',
      });

      for (const row of (view && view.rows) ? view.rows : []) {
        const obj = row.value;
        if (!obj || typeof obj !== 'object') continue;
        const native = obj.native || {};
        for (const [k, v] of Object.entries(native)) {
          if (!/port/i.test(k)) continue;

          if (typeof v === 'number' && Number.isInteger(v) && v > 0 && v <= 65535) {
            ports.add(v);
            continue;
          }

          if (typeof v === 'string') {
            const n = Number.parseInt(v, 10);
            if (Number.isInteger(n) && n > 0 && n <= 65535) ports.add(n);
          }
        }
      }
    } catch (e) {
      this.log.warn(`Port auto-detection (instances) failed: ${e.message}`);
    }

    // Known defaults / common ioBroker ports (safe, even if unused)
    [8081, 8082, 8087].forEach(p => ports.add(p));

    // Always include "extraTcpPorts" configured in adapter
    for (const p of this.parsePorts(this.config.extraTcpPorts || '')) ports.add(p);

    return Array.from(ports).sort((a, b) => a - b);
  }

  /**
   * Validate client name for PiVPN.
   * @param {string} name
   */
  validateClientName(name) {
    const n = String(name || '').trim();
    if (!n) throw new Error('Client name must not be empty.');
    if (!/^[a-zA-Z0-9.@_-]+$/.test(n)) {
      throw new Error('Client name may only contain a-z, A-Z, 0-9 and . @ _ -');
    }
    if (n.startsWith('-') || n.startsWith('.')) throw new Error('Client name must not start with "-" or ".".');
    if (/^\d+$/.test(n)) throw new Error('Client name must not be an integer.');
    if (this.protocol === 'wireguard' && n.length > 15) {
      throw new Error('WireGuard client names must be <= 15 characters (PiVPN limitation).');
    }
    return n;
  }

  /**
   * WireGuard: derive AllowedIPs string for a profile scope.
   * @param {'hostOnly'|'fullTunnel'|'lan'} scope
   * @param {string|undefined} [customLanCidr]
   * @returns {string}
   */
  getAllowedIpsForScope(scope, customLanCidr) {
    if (scope === 'fullTunnel') {
      return '0.0.0.0/0, ::0/0';
    }

    if (scope === 'lan') {
      // Best-effort LAN CIDR from setup vars (IPv4addr=192.168.x.y/24).
      const lan = customLanCidr
        || this.setupVars.IPv4addr
        || this.setupVars.IPv4Addr
        || '';

      const m = String(lan).match(/(\d+\.\d+\.\d+\.\d+)\/(\d+)/);
      if (!m) {
        // fallback to hostOnly if unknown
        this.log.warn('LAN scope requested but LAN CIDR not detected; falling back to hostOnly.');
        return this.getAllowedIpsForScope('hostOnly');
      }

      const ip = m[1];
      const prefix = Number(m[2]);
      if (!(prefix >= 8 && prefix <= 30)) return this.getAllowedIpsForScope('hostOnly');

      // Convert IP/prefix to network
      const ipParts = ip.split('.').map(x => Number(x));
      const ipInt = ((ipParts[0] << 24) >>> 0) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
      const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      const netInt = (ipInt & mask) >>> 0;
      const net = [(netInt >>> 24) & 255, (netInt >>> 16) & 255, (netInt >>> 8) & 255, netInt & 255].join('.');

      // Include server VPN address as well (helpful for direct access)
      const parts = [`${net}/${prefix}`];
      if (this.serverAddresses.ipv4) parts.push(`${this.serverAddresses.ipv4}/32`);
      if (this.serverAddresses.ipv6) parts.push(`${this.serverAddresses.ipv6}/128`);
      return parts.join(', ');
    }

    // hostOnly
    const parts = [];
    if (this.serverAddresses.ipv4) parts.push(`${this.serverAddresses.ipv4}/32`);
    if (this.serverAddresses.ipv6) parts.push(`${this.serverAddresses.ipv6}/128`);
    if (parts.length === 0) {
      // fallback: safest default that still works for most setups
      return (this.setupVars.ALLOWED_IPS || '0.0.0.0/0, ::0/0');
    }
    return parts.join(', ');
  }

  /**
   * Read metadata mapping from state profiles.meta.
   * @returns {Promise<Record<string, any>>}
   */
  async readProfilesMeta() {
    try {
      const st = await this.getStateAsync('profiles.meta');
      if (!st || st.val == null) return {};
      const txt = String(st.val);
      return JSON.parse(txt);
    } catch (e) {
      return {};
    }
  }

  /**
   * Persist metadata mapping to state.
   * @param {Record<string, any>} meta
   */
  async writeProfilesMeta(meta) {
    await this.setStateAsync('profiles.meta', JSON.stringify(meta || {}), true);
  }

  /**
   * List clients.
   * @returns {Promise<Array<{name:string, created?:number|null, disabled?:boolean, type?:string, scope?:string}>>}
   */
  async listClients() {
    const meta = await this.readProfilesMeta();

    if (this.protocol === 'wireguard') {
      // clients.txt format: name pubkey unix_created ip_dec
      let txt = '';
      try {
        txt = await this.readFile('/etc/wireguard/configs/clients.txt', true);
      } catch (e) {
        return [];
      }

      let wg0 = '';
      try {
        wg0 = await this.readFile('/etc/wireguard/wg0.conf', true);
      } catch (e) {
        // ignore
      }

      const disabledSet = new Set();
      for (const line of wg0.split(/\r?\n/)) {
        const m = line.match(/^#\[disabled\]\s+###\s+begin\s+([A-Za-z0-9.@_-]+)\s+###/);
        if (m) disabledSet.add(m[1]);
      }

      const clients = [];
      for (const line of txt.split(/\r?\n/)) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 3) continue;
        const name = parts[0];
        const created = Number(parts[2]) || null;
        const metaEntry = meta[name] || {};
        clients.push({
          name,
          created,
          disabled: disabledSet.has(name),
          type: metaEntry.type || 'unknown',
          scope: metaEntry.scope || 'unknown',
        });
      }
      return clients.sort((a, b) => a.name.localeCompare(b.name));
    }

    // openvpn: parse index.txt for valid/revoked/expired
    let index = '';
    try {
      index = await this.readFile('/etc/openvpn/easy-rsa/pki/index.txt', true);
    } catch (e) {
      return [];
    }

    const clients = [];
    for (const line of index.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const status = line.split('\t')[0]?.trim();
      // CN appears at the end: /CN=name
      const cnMatch = line.match(/\/CN=([^\s/]+)\s*$/);
      if (!cnMatch) continue;
      const name = cnMatch[1];
      if (name === 'server') continue;

      const metaEntry = meta[name] || {};
      clients.push({
        name,
        created: null,
        disabled: status !== 'V',
        type: metaEntry.type || 'unknown',
        scope: metaEntry.scope || 'unknown',
        status: status,
      });
    }
    return clients.sort((a, b) => a.name.localeCompare(b.name));
  }

  /**
   * Create a client profile via PiVPN.
   * @param {{name:string, type:'service'|'customer', scope?:'hostOnly'|'fullTunnel'|'lan', password?:string, lanCidr?:string}} opts
   */
  async addClient(opts) {
    const type = opts.type === 'service' ? 'service' : 'customer';
    const scope = opts.scope || (type === 'service' ? (this.config.defaultServiceScope || 'fullTunnel') : (this.config.defaultCustomerScope || 'hostOnly'));
    const name = this.validateClientName(opts.name);

    if (this.protocol === 'wireguard') {
      // Non-interactive: -n NAME -ip auto
      await this.exec(this.pivpnBin, ['wg', 'add', '-n', name, '-ip', 'auto'], { sudo: this.config.useSudo !== false, timeoutMs: 180000 });

      // Harden/adjust AllowedIPs per profile (client-side routing)
      const cfgPath = this.getClientConfigPath(name);
      const allowed = this.getAllowedIpsForScope(scope, opts.lanCidr);

      // Replace line: AllowedIPs = ...
      // Use regex that matches the full line.
      await this.setWireguardAllowedIps(cfgPath, allowed);

      // Also adjust the copy in /etc/wireguard/configs if present (optional)
      try {
        await this.setWireguardAllowedIps(`/etc/wireguard/configs/${name}.conf`, allowed);
      } catch (e) {
        // ignore
      }
    } else {
      // openvpn: add -n NAME [nopass| -p PASSWORD]
      const args = ['ovpn', 'add', '-n', name];
      if (opts.password && String(opts.password).trim()) {
        args.push('-p', String(opts.password));
      } else {
        args.push('nopass');
      }
      await this.exec(this.pivpnBin, args, { sudo: this.config.useSudo !== false, timeoutMs: 180000 });
    }

    // Save metadata
    const meta = await this.readProfilesMeta();
    meta[name] = {
      type,
      scope,
      createdAt: Date.now(),
      hostOnly: (scope === 'hostOnly'),
    };
    await this.writeProfilesMeta(meta);

    return { ok: true, name, type, scope };
  }

  /**
   * Remove/revoke a client profile.
   * @param {{name:string}} opts
   */
  async removeClient(opts) {
    const name = this.validateClientName(opts.name);

    if (this.protocol === 'wireguard') {
      await this.exec(this.pivpnBin, ['wg', 'remove', '-y', name], { sudo: this.config.useSudo !== false, timeoutMs: 180000 });
    } else {
      await this.exec(this.pivpnBin, ['ovpn', 'revoke', '-y', name], { sudo: this.config.useSudo !== false, timeoutMs: 180000 });
    }

    const meta = await this.readProfilesMeta();
    if (meta[name]) {
      delete meta[name];
      await this.writeProfilesMeta(meta);
    }

    return { ok: true, name };
  }

  async disableClient(opts) {
    if (this.protocol !== 'wireguard') throw new Error('Disable is only supported for WireGuard.');
    const name = this.validateClientName(opts.name);
    await this.exec(this.pivpnBin, ['wg', 'off', '-y', name], { sudo: this.config.useSudo !== false, timeoutMs: 180000 });
    return { ok: true, name };
  }

  async enableClient(opts) {
    if (this.protocol !== 'wireguard') throw new Error('Enable is only supported for WireGuard.');
    const name = this.validateClientName(opts.name);
    await this.exec(this.pivpnBin, ['wg', 'on', '-y', name], { sudo: this.config.useSudo !== false, timeoutMs: 180000 });
    return { ok: true, name };
  }

  /**
   * Fetch client config content.
   * @param {{name:string}} opts
   * @returns {Promise<{name:string, path:string, content:string}>}
   */
  async getClientConfig(opts) {
    const name = this.validateClientName(opts.name);
    const cfgPath = this.getClientConfigPath(name);
    const content = await this.readFile(cfgPath, true);
    return { name, path: cfgPath, content };
  }

  /**
   * Generate a QR code as SVG based on the client config.
   * @param {{name:string}} opts
   * @returns {Promise<{name:string, svg:string}>}
   */
  async getClientQrSvg(opts) {
    if (this.protocol !== 'wireguard') {
      throw new Error('QR code export is currently implemented for WireGuard only.');
    }
    const { content } = await this.getClientConfig(opts);

    // QRCode to SVG string (small enough to embed in admin UI)
    const svg = await QRCode.toString(content, { type: 'svg' });
    return { name: opts.name, svg };
  }

  /**
   * Apply "host-only" firewall hardening for the VPN interface:
   * - Optional: block forwarding to LAN (FORWARD)
   * - Optional: restrict INPUT from VPN interface to a TCP/UDP allowlist.
   *
   * @param {{blockForwarding:boolean, restrictPorts:boolean, tcpPorts?:number[], udpPorts?:number[]}} opts
   */
  async applyFirewall(opts) {
    const iface = this.getVpnInterface();
    const blockForwarding = opts.blockForwarding !== false;
    const restrictPorts = !!opts.restrictPorts;

    const tcpPorts = (opts.tcpPorts && Array.isArray(opts.tcpPorts)) ? opts.tcpPorts : await this.detectIoBrokerPorts();
    const udpPorts = (opts.udpPorts && Array.isArray(opts.udpPorts)) ? opts.udpPorts : this.parsePorts(this.config.extraUdpPorts || '');

    // Persist to states for transparency
    await this.setStateAsync('firewall.allowedTcpPorts', tcpPorts.join(','), true);

    const chainIn = 'NEXOWATT_VPN_IN';
    const chainFwd = 'NEXOWATT_VPN_FWD';

    /** Build a bash script with idempotent iptables changes. */
    const bashLines = [
      'set -euo pipefail',
      'IPT="/usr/sbin/iptables"',
      'IPT6="/usr/sbin/ip6tables"',
      'IPTS="/usr/sbin/iptables-save"',
      'IPT6S="/usr/sbin/ip6tables-save"',
      `IFACE="${iface}"`,
      `CHAIN_IN="${chainIn}"`,
      `CHAIN_FWD="${chainFwd}"`,
      'if [ ! -x "$IPT" ]; then IPT="iptables"; fi',
      'if [ ! -x "$IPT6" ]; then IPT6="ip6tables"; fi',
      'if [ ! -x "$IPTS" ]; then IPTS="iptables-save"; fi',
      'if [ ! -x "$IPT6S" ]; then IPT6S="ip6tables-save"; fi',
      '',
      '# Ensure chains exist',
      '$IPT -N "$CHAIN_IN" 2>/dev/null || true',
      '$IPT -F "$CHAIN_IN"',
      '$IPT -N "$CHAIN_FWD" 2>/dev/null || true',
      '$IPT -F "$CHAIN_FWD"',
      '',
      '# Hook chains (insert at top if missing)',
      '$IPT -C INPUT -i "$IFACE" -j "$CHAIN_IN" 2>/dev/null || $IPT -I INPUT 1 -i "$IFACE" -j "$CHAIN_IN"',
      '$IPT -C FORWARD -i "$IFACE" -j "$CHAIN_FWD" 2>/dev/null || $IPT -I FORWARD 1 -i "$IFACE" -j "$CHAIN_FWD"',
      '',
      '# INPUT chain rules',
      '$IPT -A "$CHAIN_IN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
      '$IPT -A "$CHAIN_IN" -p icmp -j ACCEPT',
    ];

    if (restrictPorts) {
      if (tcpPorts.length > 0) {
        const list = tcpPorts.join(',');
        bashLines.push(`$IPT -A "$CHAIN_IN" -p tcp -m multiport --dports "${list}" -j ACCEPT`);
      }
      if (udpPorts.length > 0) {
        const list = udpPorts.join(',');
        bashLines.push(`$IPT -A "$CHAIN_IN" -p udp -m multiport --dports "${list}" -j ACCEPT`);
      }
      bashLines.push('$IPT -A "$CHAIN_IN" -j DROP');
    } else {
      // If not restricting ports, allow all INPUT from VPN interface (still host-only if forwarding blocked)
      bashLines.push('$IPT -A "$CHAIN_IN" -j ACCEPT');
    }

    // FORWARD chain rules
    if (blockForwarding) {
      bashLines.push('$IPT -A "$CHAIN_FWD" -j DROP');
    } else {
      // allow forwarding (do nothing special)
      bashLines.push('$IPT -A "$CHAIN_FWD" -j ACCEPT');
    }

    // Persist rules if iptables-persistent is used
    bashLines.push('');
    bashLines.push('if [ -d /etc/iptables ]; then');
    bashLines.push('  $IPTS > /etc/iptables/rules.v4 || true');
    bashLines.push('  if [ -f /etc/iptables/rules.v6 ]; then $IPT6S > /etc/iptables/rules.v6 || true; fi');
    bashLines.push('fi');
    bashLines.push('echo "OK"');

    const script = bashLines.join('\n');
    await this.exec('/bin/bash', ['-lc', script], { sudo: this.config.useSudo !== false, timeoutMs: 60000 });

    await this.setStateAsync('firewall.lastApplied', new Date().toISOString(), true);

    return { ok: true, iface, blockForwarding, restrictPorts, tcpPorts, udpPorts };
  }

  /**
   * Refresh status states.
   */
  async refreshStatus() {
    try {
      if (!this.protocol) return;
      if (this.protocol === 'wireguard') {
        // Service check: wg-quick@wg0 active OR wg show works
        let active = false;
        try {
          const { stdout } = await this.exec('/usr/bin/systemctl', ['is-active', `wg-quick@${this.getVpnInterface()}`], { sudo: this.config.useSudo !== false, timeoutMs: 10000 });
          active = stdout.trim() === 'active';
        } catch (e) {
          // fallback
          try {
            await this.exec('/usr/bin/wg', ['show'], { sudo: this.config.useSudo !== false, timeoutMs: 10000 });
            active = true;
          } catch (e2) {
            active = false;
          }
        }
        await this.setStateAsync('info.connection', active, true);
      } else {
        // openvpn: try common service names
        const candidates = ['openvpn', 'openvpn@server', 'openvpn-server@server'];
        let active = false;
        for (const svc of candidates) {
          try {
            const { stdout } = await this.exec('/usr/bin/systemctl', ['is-active', svc], { sudo: this.config.useSudo !== false, timeoutMs: 10000 });
            if (stdout.trim() === 'active') { active = true; break; }
          } catch (e) {
            // ignore
          }
        }
        await this.setStateAsync('info.connection', active, true);
      }
      await this.setStateAsync('info.lastError', '', true);
    } catch (e) {
      this.log.warn(`Status refresh failed: ${e.message}`);
      await this.setStateAsync('info.connection', false, true);
      await this.setStateAsync('info.lastError', String(e.message || e), true);
    }
  }

  async onReady() {
    try {
      // Ensure states exist
      await this.setStateAsync('info.connection', false, true);

      this.protocol = await this.detectProtocol();
      await this.setStateAsync('info.protocol', this.protocol, true);

      if (this.protocol === 'wireguard') {
        this.serverAddresses = await this.detectWireguardServerAddresses();
        this.log.info(`Detected WireGuard server addresses: ipv4=${this.serverAddresses.ipv4 || '-'}, ipv6=${this.serverAddresses.ipv6 || '-'}`);
      }

      // Optionally apply firewall on startup (only if configured)
      if (this.config && this.config.blockForwarding) {
        // Do not force restrictPorts on startup to avoid lockouts; only apply if explicitly enabled.
        if (this.config.restrictPorts) {
          try {
            await this.applyFirewall({
              blockForwarding: true,
              restrictPorts: true,
            });
            this.log.info('Firewall hardening applied (startup).');
          } catch (e) {
            this.log.warn(`Firewall hardening could not be applied: ${e.message}`);
          }
        }
      }

      await this.refreshStatus();

      this.statusTimer = setInterval(() => {
        this.refreshStatus().catch(e => this.log.warn(`Periodic status refresh failed: ${e.message}`));
      }, 60_000);

      this.log.info('nexowattvpn ready.');
    } catch (e) {
      this.log.error(`Startup failed: ${e.message}`);
      await this.setStateAsync('info.lastError', String(e.message || e), true);
    }
  }

  async onMessage(obj) {
    if (!obj || !obj.command) return;

    const respond = (response) => {
      if (obj.callback) {
        this.sendTo(obj.from, obj.command, response, obj.callback);
      }
    };

    try {
      switch (obj.command) {
        case 'getServerInfo': {
          respond({
            ok: true,
            protocol: this.protocol,
            setupVars: {
              VPN: this.setupVars.VPN,
              pivpnHOST: this.setupVars.pivpnHOST,
              pivpnPORT: this.setupVars.pivpnPORT,
              pivpnDNS1: this.setupVars.pivpnDNS1,
              pivpnDNS2: this.setupVars.pivpnDNS2,
              install_user: this.setupVars.install_user,
              install_home: this.setupVars.install_home,
              ALLOWED_IPS: this.setupVars.ALLOWED_IPS,
            },
            serverAddresses: this.serverAddresses,
          });
          break;
        }
        case 'listClients': {
          const clients = await this.listClients();
          respond({ ok: true, clients });
          break;
        }
        case 'addClient': {
          const res = await this.addClient(obj.message || {});
          respond(res);
          break;
        }
        case 'removeClient': {
          const res = await this.removeClient(obj.message || {});
          respond(res);
          break;
        }
        case 'disableClient': {
          const res = await this.disableClient(obj.message || {});
          respond(res);
          break;
        }
        case 'enableClient': {
          const res = await this.enableClient(obj.message || {});
          respond(res);
          break;
        }
        case 'getClientConfig': {
          const res = await this.getClientConfig(obj.message || {});
          respond({ ok: true, ...res });
          break;
        }
        case 'getClientQrSvg': {
          const res = await this.getClientQrSvg(obj.message || {});
          respond({ ok: true, ...res });
          break;
        }
        case 'applyFirewall': {
          const msg = obj.message || {};
          const tcpPorts = (msg.tcpPorts && Array.isArray(msg.tcpPorts)) ? msg.tcpPorts : null;
          const udpPorts = (msg.udpPorts && Array.isArray(msg.udpPorts)) ? msg.udpPorts : null;

          const res = await this.applyFirewall({
            blockForwarding: msg.blockForwarding !== false,
            restrictPorts: !!msg.restrictPorts,
            tcpPorts: tcpPorts || undefined,
            udpPorts: udpPorts || undefined,
          });
          respond(res);
          break;
        }
        case 'detectPorts': {
          const ports = await this.detectIoBrokerPorts();
          respond({ ok: true, tcpPorts: ports });
          break;
        }
        default:
          respond({ ok: false, error: `Unknown command: ${obj.command}` });
          break;
      }
    } catch (e) {
      this.log.warn(`Command ${obj.command} failed: ${e.message}`);
      respond({ ok: false, error: e.message });
    }
  }

  onUnload(callback) {
    try {
      if (this.statusTimer) {
        clearInterval(this.statusTimer);
        this.statusTimer = null;
      }
      callback();
    } catch (e) {
      callback();
    }
  }
}

if (module && module.parent) {
  module.exports = (options) => new Nexowattvpn(options);
} else {
  new Nexowattvpn();
}
