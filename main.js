'use strict';

/*
 * NexoWattVPN - ioBroker adapter to manage PiVPN/WireGuard via a minimal, audited root helper.
 *
 * IMPORTANT SECURITY NOTES
 * - This adapter never stores WireGuard client configs (PrivateKey) in ioBroker states.
 * - Client configs are retrieved on-demand via sendTo and returned to the admin UI only.
 * - Root actions are executed ONLY through /usr/local/sbin/nexowattvpn-helper with sudoers whitelisting.
 */

const path = require('path');
const fs = require('fs');
const fsp = require('fs/promises');
const { execFile } = require('child_process');

const utils = require('@iobroker/adapter-core');
const QRCode = require('qrcode');

const ROOT_HELPER = '/usr/local/sbin/nexowattvpn-helper';

class Nexowattvpn extends utils.Adapter {
  constructor(options = {}) {
    super({
      ...options,
      name: 'nexowattvpn',
    });

    this.on('ready', this.onReady.bind(this));
    this.on('message', this.onMessage.bind(this));
    this.on('unload', this.onUnload.bind(this));

    /** @type {NodeJS.Timeout | null} */
    this._statusTimer = null;
  }

  /**
   * Try to determine a persistent data directory for this adapter instance.
   * Falls back to /opt/iobroker/iobroker-data if adapter-core helpers are unavailable.
   * @returns {string}
   */
  getDataDir() {
    // We intentionally use a fixed directory so the root helper + systemd service can rely on it.
    // If your ioBroker installation uses a different base path, adjust here AND in scripts/root/install-root.sh.
    return '/opt/iobroker/iobroker-data/nexowattvpn';
  }
    } catch {
      // ignore
    }
    // Fallback (common on ioBroker installations)
    return `/opt/iobroker/iobroker-data/${this.name}`;
  }

  /**
   * @returns {string}
   */
  getRolesFilePath() {
    return path.join(this.getDataDir(), 'roles.json');
  }

  /**
   * @returns {string}
   */
  getFirewallConfigPath() {
    return path.join(this.getDataDir(), 'firewall.json');
  }

  async onReady() {
    // Reset known states
    await this.setStateAsync('info.connection', false, true);
    await this.setStateAsync('info.lastError', '', true);

    // Ensure policy files exist (roles + firewall config)
    await this.ensurePolicyFiles();

    // Initial status refresh
    await this.refreshStatus().catch((e) => this.logError(e, 'refreshStatus'));

    // Poll status periodically
    this._statusTimer = setInterval(() => {
      this.refreshStatus().catch((e) => this.logError(e, 'refreshStatus'));
    }, 60_000);

    this.log.info('NexoWattVPN adapter started.');
  }

  async onUnload(callback) {
    try {
      if (this._statusTimer) {
        clearInterval(this._statusTimer);
        this._statusTimer = null;
      }
      callback();
    } catch {
      callback();
    }
  }

  /**
   * Log and publish a concise error.
   * @param {unknown} err
   * @param {string} context
   */
  logError(err, context) {
    const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    this.log.error(`[${context}] ${msg}`);
    this.setState('info.lastError', msg, true);
  }

  /**
   * Ensure roles.json and firewall.json exist in the adapter data dir.
   */
  async ensurePolicyFiles() {
    const dataDir = this.getDataDir();
    await fsp.mkdir(dataDir, { recursive: true });

    const rolesPath = this.getRolesFilePath();
    if (!fs.existsSync(rolesPath)) {
      await fsp.writeFile(
        rolesPath,
        JSON.stringify({ version: 1, peers: {} }, null, 2),
        { encoding: 'utf-8', mode: 0o640 }
      );
    }

    // Always (re)write firewall config from adapter configuration to keep it current
    await this.writeFirewallConfigFromAdapterConfig();
  }

  /**
   * Write firewall.json based on current adapter configuration.
   */
  async writeFirewallConfigFromAdapterConfig() {
    const firewallPath = this.getFirewallConfigPath();
    const cfg = {
      version: 1,
      rolesFile: this.getRolesFilePath(),
      // Ports are strings in adapter config; helper parses and validates them.
      servicePortsTcp: this.config.servicePortsTcp || '8081,8082',
      customerPortsTcp: this.config.customerPortsTcp || '8082',
      blockForwarding: true,
      allowPing: false,
    };
    await fsp.writeFile(firewallPath, JSON.stringify(cfg, null, 2), { encoding: 'utf-8', mode: 0o640 });
  }

  /**
   * Run the audited root helper with sudo.
   * @param {string[]} args
   * @returns {Promise<{stdout: string, stderr: string}>}
   */
  callRootHelper(args) {
    return new Promise((resolve, reject) => {
      // Prefer sudo if not running as root (default in ioBroker)
      const cmd = 'sudo';
      const cmdArgs = [ROOT_HELPER, ...args];

      execFile(cmd, cmdArgs, { timeout: 300_000, maxBuffer: 10 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          const wrapped = new Error(`Root helper failed: ${error.message}${stderr ? ` | stderr: ${stderr}` : ''}`);
          wrapped.cause = error;
          return reject(wrapped);
        }
        resolve({ stdout: String(stdout || ''), stderr: String(stderr || '') });
      });
    });
  }

  /**
   * Refresh core status states from PiVPN/WireGuard.
   */
  async refreshStatus() {
    const helperInstalled = fs.existsSync(ROOT_HELPER);
    await this.setStateAsync('info.helperInstalled', helperInstalled, true);

    if (!helperInstalled) {
      await this.setStateAsync('info.connection', false, true);
      await this.setStateAsync('info.pivpnInstalled', false, true);
      await this.setStateAsync('info.wireguardConfigured', false, true);
      return;
    }

    const { stdout } = await this.callRootHelper(['status', '--json']);
    const status = JSON.parse(stdout);

    await this.setStateAsync('info.pivpnInstalled', !!status.pivpnInstalled, true);
    await this.setStateAsync('info.wireguardConfigured', !!status.wireguardConfigured, true);
    await this.setStateAsync('info.wgInterface', status.wgInterface || '', true);
    await this.setStateAsync('info.serverIp', status.serverIp || '', true);
    await this.setStateAsync('info.endpointHost', status.pivpnHOST || '', true);
    await this.setStateAsync('info.port', Number(status.pivpnPORT || 0), true);
    await this.setStateAsync('info.allowedIps', status.ALLOWED_IPS || '', true);

    // "connection" => adapter ready and PiVPN config readable
    await this.setStateAsync('info.connection', !!status.pivpnInstalled && !!status.wireguardConfigured, true);

    return status;
  }

  /**
   * Read roles.json, merge role information into peer list.
   * @param {{peers: Array<{name: string}>}} peerList
   */
  async mergeRoles(peerList) {
    const rolesPath = this.getRolesFilePath();
    let roles = { peers: {} };
    try {
      roles = JSON.parse(await fsp.readFile(rolesPath, 'utf-8'));
    } catch {
      // ignore (will just not show roles)
    }

    const rolesMap = roles?.peers || {};
    for (const p of peerList.peers || []) {
      p.role = rolesMap?.[p.name]?.role || 'customer';
    }
    return peerList;
  }

  /**
   * Update role for a peer in roles.json.
   * @param {string} name
   * @param {'service'|'customer'} role
   */
  async setPeerRole(name, role) {
    const rolesPath = this.getRolesFilePath();
    const content = JSON.parse(await fsp.readFile(rolesPath, 'utf-8'));
    content.peers = content.peers || {};
    content.peers[name] = { role };
    await fsp.writeFile(rolesPath, JSON.stringify(content, null, 2), 'utf-8');
  }

  /**
   * Remove peer from roles.json.
   * @param {string} name
   */
  async removePeerRole(name) {
    const rolesPath = this.getRolesFilePath();
    const content = JSON.parse(await fsp.readFile(rolesPath, 'utf-8'));
    if (content?.peers?.[name]) {
      delete content.peers[name];
      await fsp.writeFile(rolesPath, JSON.stringify(content, null, 2), 'utf-8');
    }
  }

  /**
   * Handle admin UI messages (sendTo).
   * @param {ioBroker.Message} obj
   */
  async onMessage(obj) {
    if (!obj || !obj.command) return;

    const reply = (payload) => {
      if (obj.callback) {
        this.sendTo(obj.from, obj.command, payload, obj.callback);
      }
    };

    try {
      switch (obj.command) {
        case 'status': {
          const status = await this.refreshStatus();
          reply({ ok: true, status });
          break;
        }

        case 'applyConfig': {
          // message may contain partial overrides; fallback to adapter config
          const msg = obj.message || {};
          const endpointHost = (msg.endpointHost ?? this.config.endpointHost ?? '').toString().trim();
          const port = Number(msg.port ?? this.config.port ?? 51820);
          const dns1 = (msg.dns1 ?? this.config.dns1 ?? '').toString().trim();
          const dns2 = (msg.dns2 ?? this.config.dns2 ?? '').toString().trim();

          const allowedIpsMode = (msg.allowedIpsMode ?? this.config.allowedIpsMode ?? 'hostOnly').toString();
          const allowedIpsCustom = (msg.allowedIpsCustom ?? this.config.allowedIpsCustom ?? '').toString().trim();

          // Keep firewall.json aligned with adapter config
          await this.writeFirewallConfigFromAdapterConfig();

          const args = ['configure'];
          if (endpointHost) args.push('--endpoint-host', endpointHost);
          if (Number.isFinite(port) && port > 0) args.push('--port', String(port));
          if (dns1) args.push('--dns1', dns1);
          if (dns2) args.push('--dns2', dns2);

          if (allowedIpsMode === 'custom') {
            if (!allowedIpsCustom) {
              throw new Error('allowedIpsCustom is empty but allowedIpsMode=custom');
            }
            args.push('--allowed-ips', allowedIpsCustom);
          } else {
            // default: hostOnly
            args.push('--allowed-ips', 'HOST_ONLY');
          }

          const { stdout } = await this.callRootHelper([...args, '--json']);
          const applied = JSON.parse(stdout);

          // Apply firewall (optional)
          if (this.config.autoApplyFirewall) {
            await this.callRootHelper(['apply-firewall', '--config', this.getFirewallConfigPath(), '--json']);
          }

          const status = await this.refreshStatus();
          reply({ ok: true, applied, status });
          break;
        }

        case 'listPeers': {
          const { stdout } = await this.callRootHelper(['list-peers', '--json']);
          const peers = await this.mergeRoles(JSON.parse(stdout));
          reply({ ok: true, peers });
          break;
        }

        case 'addPeer': {
          const msg = obj.message || {};
          const name = (msg.name || '').toString().trim();
          const role = (msg.role || 'customer').toString() === 'service' ? 'service' : 'customer';
          if (!name) throw new Error('Missing peer name');

          await this.callRootHelper(['add-peer', '--name', name, '--ip', 'auto', '--json']);

          await this.setPeerRole(name, role);

          // Apply firewall after change
          if (this.config.autoApplyFirewall) {
            await this.writeFirewallConfigFromAdapterConfig();
            await this.callRootHelper(['apply-firewall', '--config', this.getFirewallConfigPath(), '--json']);
          }

          reply({ ok: true });
          break;
        }

        case 'removePeer': {
          const msg = obj.message || {};
          const name = (msg.name || '').toString().trim();
          if (!name) throw new Error('Missing peer name');
          await this.callRootHelper(['remove-peer', '--name', name, '--yes', '--json']);
          await this.removePeerRole(name);

          if (this.config.autoApplyFirewall) {
            await this.writeFirewallConfigFromAdapterConfig();
            await this.callRootHelper(['apply-firewall', '--config', this.getFirewallConfigPath(), '--json']);
          }

          reply({ ok: true });
          break;
        }

        case 'disablePeer': {
          const msg = obj.message || {};
          const name = (msg.name || '').toString().trim();
          if (!name) throw new Error('Missing peer name');
          await this.callRootHelper(['disable-peer', '--name', name, '--yes', '--json']);
          reply({ ok: true });
          break;
        }

        case 'enablePeer': {
          const msg = obj.message || {};
          const name = (msg.name || '').toString().trim();
          if (!name) throw new Error('Missing peer name');
          await this.callRootHelper(['enable-peer', '--name', name, '--yes', '--json']);
          reply({ ok: true });
          break;
        }

        case 'getPeerConfig': {
          const msg = obj.message || {};
          const name = (msg.name || '').toString().trim();
          if (!name) throw new Error('Missing peer name');
          const { stdout } = await this.callRootHelper(['get-peer-conf', '--name', name]);
          // Do NOT store in states; return to UI only
          reply({ ok: true, name, config: stdout });
          break;
        }

        case 'getPeerQr': {
          const msg = obj.message || {};
          const name = (msg.name || '').toString().trim();
          if (!name) throw new Error('Missing peer name');
          const { stdout } = await this.callRootHelper(['get-peer-conf', '--name', name]);
          const dataUrl = await QRCode.toDataURL(stdout, { errorCorrectionLevel: 'M' });
          reply({ ok: true, name, dataUrl });
          break;
        }

        case 'applyFirewall': {
          await this.writeFirewallConfigFromAdapterConfig();
          const { stdout } = await this.callRootHelper(['apply-firewall', '--config', this.getFirewallConfigPath(), '--json']);
          reply({ ok: true, result: JSON.parse(stdout) });
          break;
        }

        case 'clearFirewall': {
          const { stdout } = await this.callRootHelper(['clear-firewall', '--json']);
          reply({ ok: true, result: JSON.parse(stdout) });
          break;
        }

        default:
          reply({ ok: false, error: `Unknown command: ${obj.command}` });
          break;
      }
    } catch (e) {
      this.logError(e, `onMessage:${obj.command}`);
      reply({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  }
}

if (module.parent) {
  module.exports = (options) => new Nexowattvpn(options);
} else {
  // @ts-ignore
  new Nexowattvpn();
}
