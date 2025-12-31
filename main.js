/*
 * ioBroker Adapter: NexoWattVPN (nexowattvpn)
 * Purpose: Manage a WireGuard VPN with strict host-only access (ports allowed via wg interface)
 *
 * Security model:
 * - Adapter runs unprivileged (iobroker user).
 * - Root operations are executed by lib/root-helper.js via sudo (NOPASSWD).
 *
 * NOTE:
 * - This is a scaffold intended to be adapted to your environment.
 */

"use strict";

const utils = require("@iobroker/adapter-core");
const { execFile } = require("child_process");
const path = require("path");
const QRCode = require("qrcode");

function escapeHtml(input) {
  return String(input ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


class NexoWattVPN extends utils.Adapter {
  constructor(options = {}) {
    super({
      ...options,
      name: "nexowattvpn",
    });

    this._pollTimer = null;

    this.on("ready", this.onReady.bind(this));
    this.on("message", this.onMessage.bind(this));
    this.on("unload", this.onUnload.bind(this));
  }

  async onReady() {
    // Reset connection state on start
    await this.setStateAsync("info.connection", { val: false, ack: true }).catch(() => {});
    await this._ensureObjects();

    // Basic validation / normalization
    const cfg = this._getEffectiveConfig();

    this.log.info(`Configured interface=${cfg.ifaceName}, listenPort=${cfg.listenPort}, allowedPorts=${cfg.allowedPorts.join(",")}`);

    if (cfg.enabled) {
      // Best-effort: ensure prerequisites, server config, firewall and tunnel
      try {
        await this._callHelper("fullSetup", { cfg });
      } catch (e) {
        this._setLastError(e);
        this.log.error(`Startup failed: ${e && e.message ? e.message : e}`);
      }
    }

    // Support-access expiry check
    await this._checkSupportExpiry().catch(() => {});

    // Poll status periodically
    this._pollTimer = this.setInterval(async () => {
      await this._pollStatus().catch(() => {});
      await this._checkSupportExpiry().catch(() => {});
    }, 30_000);
    await this._pollStatus().catch(() => {});
  }

  async onUnload(callback) {
    try {
      if (this._pollTimer) {
        this.clearInterval(this._pollTimer);
        this._pollTimer = null;
      }
      callback();
    } catch (e) {
      callback();
    }
  }

  async onMessage(obj) {
    if (!obj || !obj.command) return;

    const cfg = this._getEffectiveConfig();

    const reply = (data) => {
      if (obj.callback) this.sendTo(obj.from, obj.command, data, obj.callback);
    };

    try {
      switch (obj.command) {
        case "sudoCheck": {
          const ok = await this._sudoCheck();
          reply({ text: ok ? "OK: sudo ohne Passwort (NOPASSWD) ist verfügbar" : "FEHLER: sudo -n ist nicht erlaubt (Bootstrap/sudoers fehlt)", icon: ok ? "info" : "error" });
          break;
        }
        case "prereqCheck": {
          const res = await this._callHelper("prereqCheck", { cfg });
          reply({ text: JSON.stringify(res.result, null, 2), icon: "info" });
          break;
        }
        case "healthOverview": {
          // Übersicht / Ampel als HTML
          const sudoOk = await this._sudoCheck();
          let prereqs = null;
          let prereqOk = false;
          let health = null;
          let firewall = null;

          if (sudoOk) {
            try {
              const r1 = await this._callHelper("prereqCheck", { cfg });
              prereqs = r1.result || null;
              prereqOk = !!(prereqs?.commands?.wg && prereqs?.commands?.wgQuick && prereqs?.commands?.nft);
            } catch (e) {
              prereqs = null;
              prereqOk = false;
            }

            try {
              const r2 = await this._callHelper("health", { cfg });
              health = r2.result || null;
              firewall = health?.firewall || null;
            } catch (e) {
              health = null;
              firewall = null;
            }
          }

          const lamp = (state) => {
            if (state === true) return "🟢";
            if (state === "warn") return "🟡";
            return "🔴";
          };

          const endpointSet = !!String(cfg.endpointHost || "").trim();
          const ifaceUp = !!health?.interfaceUp;
          const confExists = !!health?.confExists;
          const firewallOk = !!firewall?.tableExists;

          const nextSteps = [];
          if (!sudoOk) nextSteps.push("1) Tab „Installieren“ → Bootstrap‑Befehl 1× als root ausführen");
          if (sudoOk && !prereqOk) nextSteps.push("Voraussetzungen installieren (wireguard-tools + nftables)");
          if (sudoOk && prereqOk && !confExists) nextSteps.push("Server‑Konfiguration erstellen/aktualisieren");
          if (sudoOk && prereqOk && confExists && !firewallOk) nextSteps.push("Firewall‑Regeln anwenden");
          if (sudoOk && prereqOk && confExists && firewallOk && !ifaceUp) nextSteps.push("VPN starten (wg‑quick up)");
          if (sudoOk && prereqOk && confExists && firewallOk && ifaceUp) nextSteps.push("Als Nächstes: Profile erstellen (Tab „Profile“) und mit WireGuard‑App verbinden");

          const html = [
            '<div style="display:flex;flex-direction:column;gap:10px;">',
            '<div style="font-weight:700;font-size:14px;">System‑Status</div>',
            '<table style="border-collapse:collapse;width:100%;">',
            '<tbody>',
            `<tr><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${lamp(sudoOk)} sudo‑Freigabe (sudo -n)</td><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${sudoOk ? "OK" : "FEHLT"}</td></tr>`,
            `<tr><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${lamp(prereqOk)} Voraussetzungen (wg/wg‑quick/nft)</td><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${sudoOk ? (prereqOk ? "OK" : "FEHLT") : "–"}</td></tr>`,
            `<tr><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${lamp(endpointSet ? true : "warn")} Endpoint (öffentlich)</td><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${endpointSet ? escapeHtml(cfg.endpointHost) : "(leer – für Client‑Configs empfohlen)"}</td></tr>`,
            `<tr><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${lamp(confExists)} Server‑Konfiguration</td><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${sudoOk ? (confExists ? escapeHtml(health?.confPath || "") : "nicht vorhanden") : "–"}</td></tr>`,
            `<tr><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${lamp(firewallOk ? true : "warn")} Firewall (nft)</td><td style="padding:4px 8px;border-bottom:1px solid rgba(0,0,0,0.12);">${sudoOk ? (firewallOk ? "aktiv" : "nicht aktiv") : "–"}</td></tr>`,
            `<tr><td style="padding:4px 8px;">${lamp(ifaceUp ? true : "warn")} VPN (wg‑Interface)</td><td style="padding:4px 8px;">${sudoOk ? (ifaceUp ? "läuft" : "gestoppt") : "–"}</td></tr>`,
            '</tbody>',
            '</table>',
            '<div style="opacity:0.9;">',
            '<b>Empfohlener nächster Schritt:</b><br/>',
            nextSteps.length ? nextSteps.map((s) => `• ${escapeHtml(s)}`).join("<br/>") : "–",
            '</div>',
            '<div style="opacity:0.85;">',
            '<b>Wichtig:</b> Direkter Internet‑Zugriff auf einen VPN‑Server hinter NAT benötigt i. d. R. eine UDP‑Portweiterleitung am Router. Ohne Router‑Änderung ist ein externer Hub/VPS (Reverse‑VPN) die robuste Lösung.',
            '</div>',
            '</div>'
          ].join("");

          reply(html);
          break;
        }

        case "installPrereqs": {
          const res = await this._callHelper("installPrereqs", { cfg });
          reply({ text: `OK: Voraussetzungen installiert/überprüft.\n${JSON.stringify(res.result, null, 2)}`, icon: "install" });
          break;
        }

        case "fullSetup": {
          const res = await this._callHelper("fullSetup", { cfg });
          await this._pollStatus().catch(() => {});
          reply({ text: `OK: Full‑Setup abgeschlossen.\n${JSON.stringify(res.result, null, 2)}`, icon: "connection" });
          break;
        }
        case "bootstrapCommand": {
          // This command cannot be executed by the adapter itself until sudoers exists.
          // We return a one-liner the user can run once as root.
          const helperPath = path.join(__dirname, "lib", "root-helper.js");
          const payload = {
            cfg: { serviceUser: cfg.serviceUser },
            serviceUser: cfg.serviceUser,
            nodePath: process.execPath,
            helperPath,
          };
          const b64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
          const cmd = `sudo ${process.execPath} ${helperPath} bootstrap --json ${b64}`;
          reply({ text: cmd, icon: "terminal" });
          break;
        }
        case "ensureServer": {
          const res = await this._callHelper("ensureServer", { cfg });
          await this._pollStatus().catch(() => {});
          reply({ text: `OK: Server‑Konfiguration erstellt/aktualisiert. ServerPublicKey=${res?.result?.serverPublicKey || ""}`, icon: "connection" });
          break;
        }
        case "up": {
          await this._callHelper("up", { cfg });
          await this._pollStatus().catch(() => {});
          reply({ text: "OK: VPN gestartet", icon: "play" });
          break;
        }
        case "down": {
          await this._callHelper("down", { cfg });
          await this._pollStatus().catch(() => {});
          reply({ text: "OK: VPN gestoppt", icon: "stop" });
          break;
        }
        case "applyFirewall": {
          await this._callHelper("applyFirewall", { cfg });
          reply({ text: `OK: Firewall angewendet (WG: erlaube TCP ${cfg.allowedPorts.join(",")})`, icon: "socket" });
          break;
        }
        case "removeFirewall": {
          await this._callHelper("removeFirewall", { cfg });
          reply({ text: "OK: Firewall‑Regeln entfernt", icon: "delete" });
          break;
        }
        case "listProfiles": {
          const res = await this._callHelper("listProfiles", { cfg });
          const text = JSON.stringify(res.result, null, 2);
          reply({ text, icon: "list" });
          break;
        }
        case "status": {
          const res = await this._callHelper("status", { cfg });
          // For textSendTo we return text or {text, style, ...}
          const text = JSON.stringify(res.result, null, 2);
          reply({ text, icon: res.result?.interfaceUp ? "connection" : "no-connection" });
          break;
        }
        case "firewallStatus": {
          const res = await this._callHelper("firewallStatus", { cfg });
          const txt = JSON.stringify(res.result, null, 2);
          reply({ text: txt, icon: res.result?.tableExists ? "info" : "error" });
          break;
        }

        case "createProfile": {
          const profileName = (obj.message && (obj.message.profileName || obj.message.name)) || "";
          const password = (obj.message && (obj.message.password || "")) || "";

          if (!String(profileName).trim()) {
            reply({ text: "FEHLER: Profilname ist leer", style: { color: "red" }, icon: "error" });
            break;
          }

          const res = await this._callHelper("createProfile", { cfg, profileName, password });
          const clientConfig = res?.result?.clientConfig || "";

          // Generate a QR code (WireGuard apps can import via QR)
          const qrDataUrl = await QRCode.toDataURL(clientConfig, {
            errorCorrectionLevel: "H",
            margin: 1,
            scale: 6,
          });

          const html = [
            '<div style="display:flex;flex-direction:column;gap:12px;">',
            `<div><b>Profil:</b> ${escapeHtml(res?.result?.profileName || profileName)}</div>`,
            `<div><b>Peer‑IP:</b> ${escapeHtml(res?.result?.peerIp || "")}</div>`,
            '<div><b>Client‑Konfiguration</b></div>',
            `<pre style="white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;border:1px solid rgba(0,0,0,0.2);padding:8px;border-radius:4px;">${escapeHtml(clientConfig)}</pre>`,
            '<div><b>QR‑Code</b> (Import in WireGuard‑App)</div>',
            `<img alt="WireGuard QR" src="${qrDataUrl}" style="max-width:320px;max-height:320px;"/>`,
            '</div>',
          ].join('');

          // Store last output in states (so it can be displayed by jsonConfig state control)
          await this.setStateAsync("profiles.lastGeneratedHtml", { val: html, ack: true }).catch(() => {});
          await this.setStateAsync("profiles.lastGeneratedName", { val: res?.result?.profileName || String(profileName), ack: true }).catch(() => {});
          await this.setStateAsync("profiles.lastGeneratedPeerIp", { val: res?.result?.peerIp || "", ack: true }).catch(() => {});
          await this.setStateAsync("profiles.lastGeneratedAt", { val: Date.now(), ack: true }).catch(() => {});

          await this._pollStatus().catch(() => {});

          reply({ text: `OK: Profil '${res?.result?.profileName || profileName}' erstellt/rotiert. Ausgabe unten aktualisiert.`, icon: "qrcode" });
          break;
        }
        case "revokeProfile": {
          const profileName = (obj.message && (obj.message.profileName || obj.message.name)) || "";

          // Prevent accidental removal of the dedicated Support profile via the generic flow.
          if (String(profileName) === String(cfg.supportPeerName)) {
            reply({ text: `FEHLER: '${cfg.supportPeerName}' ist das Support‑Profil. Bitte im Tab „Support“ deaktivieren.`, style: { color: "red" }, icon: "error" });
            break;
          }

          const res = await this._callHelper("revokeProfile", { cfg, profileName });
          reply({ text: `OK: ${res.result?.revoked ? "widerrufen" : "nicht gefunden"} (${profileName})`, icon: "delete" });
          break;
        }

        case "enableSupportProfile": {
          const password = (obj.message && (obj.message.password || "")) || "";
          const expiresMinutesRaw = (obj.message && (obj.message.expiresMinutes || obj.message.expires || "")) || "";
          const expiresMinutes = Number(expiresMinutesRaw || cfg.supportExpiryMinutes || 0);

          if (!String(cfg.supportPeerPublicKey || "").trim()) {
            reply({ text: "FEHLER: Public Key (Support/Vendor) ist leer. Bitte zuerst eintragen.", style: { color: "red" }, icon: "error" });
            break;
          }

          const res = await this._callHelper("enableSupportProfile", {
            cfg,
            supportPeerName: cfg.supportPeerName,
            supportPeerPublicKey: cfg.supportPeerPublicKey,
            password,
          });

          const r = res.result || {};
          const expiresAt = Number.isFinite(expiresMinutes) && expiresMinutes > 0 ? Date.now() + expiresMinutes * 60_000 : 0;

          const html = [
            '<div style="display:flex;flex-direction:column;gap:12px;">',
            `<div><b>Support‑Profil aktiviert:</b> ${escapeHtml(r.profileName || cfg.supportPeerName)}</div>`,
            `<div><b>Peer‑IP:</b> ${escapeHtml(r.peerIp || "")}</div>`,
            `<div><b>Endpoint:</b> ${escapeHtml(r.endpoint || "(Endpoint im Tab „Server“ setzen)")}</div>`,
            `<div><b>AllowedIPs (Client):</b> ${escapeHtml(r.allowedIpsClient || "")}</div>`,
            expiresAt ? `<div><b>Expires:</b> ${new Date(expiresAt).toISOString()}</div>` : `<div><b>Ablauf:</b> (keine Ablaufzeit konfiguriert)</div>`,
            '<div style="opacity:0.9;">Der Support trägt seinen PrivateKey selbst in das Template unten ein.</div>',
            '<div><b>Support‑Client‑Konfiguration (Template)</b></div>',
            `<pre style="white-space:pre-wrap;word-break:break-word;max-height:320px;overflow:auto;border:1px solid rgba(0,0,0,0.2);padding:8px;border-radius:4px;">${escapeHtml(r.clientConfigTemplate || "")}</pre>`,
            r.presharedKey ? `<div><b>PSK:</b> <code>${escapeHtml(r.presharedKey)}</code></div>` : "",
            '</div>',
          ].join("");

          await this.setStateAsync("support.active", { val: true, ack: true }).catch(() => {});
          await this.setStateAsync("support.peerName", { val: String(r.profileName || cfg.supportPeerName), ack: true }).catch(() => {});
          await this.setStateAsync("support.peerIp", { val: String(r.peerIp || ""), ack: true }).catch(() => {});
          await this.setStateAsync("support.expiresAt", { val: expiresAt, ack: true }).catch(() => {});
          await this.setStateAsync("support.lastOutputHtml", { val: html, ack: true }).catch(() => {});

          reply({ text: "OK: Support‑Zugang aktiviert.", icon: "connection" });
          break;
        }

        case "disableSupportProfile": {
          const res = await this._callHelper("disableSupportProfile", { cfg, supportPeerName: cfg.supportPeerName });
          await this.setStateAsync("support.active", { val: false, ack: true }).catch(() => {});
          await this.setStateAsync("support.peerIp", { val: "", ack: true }).catch(() => {});
          await this.setStateAsync("support.expiresAt", { val: 0, ack: true }).catch(() => {});
          await this.setStateAsync("support.lastOutputHtml", { val: "", ack: true }).catch(() => {});
          reply({ text: `OK: Support‑Zugang ${res.result?.revoked ? "deaktiviert" : "nicht gefunden"}`, icon: "delete" });
          break;
        }

        case "supportStatus": {
          try {
            const res = await this._callHelper("listProfiles", { cfg });
            const peers = res?.result?.peers || [];
            const s = peers.find((p) => String(p.name) === String(cfg.supportPeerName));
            reply({ text: JSON.stringify({ exists: !!s, peer: s || null }, null, 2), icon: s ? "connection" : "no-connection" });
          } catch (e) {
            reply({ text: `FEHLER: ${e && e.message ? e.message : e}`, style: { color: "red" }, icon: "error" });
          }
          break;
        }
        case "getServerPublicKey": {
          const res = await this._callHelper("getServerPublicKey", { cfg });
          reply({ text: res.result.serverPublicKey || "", icon: "visible" });
          break;
        }
        case "profileOptions": {
          // Used by jsonConfig selectSendTo. Must return an array like [{label,value}, ...]
          try {
            const res = await this._callHelper("listProfiles", { cfg });
            const peers = res?.result?.peers || [];
            const supportName = String(cfg.supportPeerName || "");
            const options = peers
              .filter((p) => String(p.name) !== supportName && String(p.kind || "") !== "support")
              .map((p) => ({ label: String(p.name), value: String(p.name) }))
              .sort((a, b) => a.label.localeCompare(b.label));
            reply(options);
          } catch (e) {
            reply([]);
          }
          break;
        }

        case "clearLastOutput": {
          await this.setStateAsync("profiles.lastGeneratedHtml", { val: "", ack: true }).catch(() => {});
          await this.setStateAsync("profiles.lastGeneratedName", { val: "", ack: true }).catch(() => {});
          await this.setStateAsync("profiles.lastGeneratedPeerIp", { val: "", ack: true }).catch(() => {});
          await this.setStateAsync("profiles.lastGeneratedAt", { val: 0, ack: true }).catch(() => {});
          reply({ text: "OK: Letzte Ausgabe gelöscht", icon: "delete" });
          break;
        }

        case "bindingCheck": {
          const wgHostIp = String(cfg.hostVpnIp || "").split("/")[0].trim();
          const allowedPorts = (cfg.allowedPorts || []).map((n) => Number(n)).filter((n) => Number.isFinite(n));

          const instances = [];
          try {
            const view = await this.getObjectViewAsync("system", "instance", {
              startkey: "system.adapter.",
              endkey: "system.adapter.香",
            });
            for (const row of view?.rows || []) {
              const obj = row?.value || row?.doc || null;
              if (!obj || !obj.native || !obj.common) continue;
              const portRaw = obj.native.port;
              const port = portRaw === undefined || portRaw === null ? null : Number(portRaw);
              if (port !== null && Number.isFinite(port)) {
                instances.push({
                  id: row.id || obj._id || "",
                  enabled: obj.common.enabled !== false,
                  port,
                  bind: obj.native.bind || obj.native.bindIp || obj.native.bindIP || "",
                  secure: obj.native.secure,
                  name: obj.common.name,
                });
              }
            }
          } catch (e) {
            // ignore
          }

          const byPort = new Map();
          for (const p of allowedPorts) byPort.set(p, []);
          for (const inst of instances) {
            if (byPort.has(inst.port)) byPort.get(inst.port).push(inst);
          }

          const exposure = (bind) => {
            const b = String(bind || "").trim();
            if (!b || b === "0.0.0.0" || b === "::" || b === "::0") return "Auf allen Interfaces erreichbar";
            if (b === wgHostIp) return "Nur VPN (an WireGuard‑IP gebunden)";
            if (b === "127.0.0.1" || b === "::1") return "Nur Localhost (über VPN nicht erreichbar)";
            return `Gebunden an ${escapeHtml(b)}`;
          };

          const rowsHtml = allowedPorts
            .map((p) => {
              const list = byPort.get(p) || [];
              if (!list.length) {
                return `<tr><td>${p}</td><td colspan="3"><i>Keine ioBroker‑Instanz mit native.port=${p} gefunden</i></td></tr>`;
              }
              return list
                .map((inst, idx) => {
                  const bind = String(inst.bind || "");
                  return `<tr>
  <td>${idx === 0 ? p : ""}</td>
  <td>${escapeHtml(inst.id)}</td>
  <td>${escapeHtml(bind || "(not set)")}</td>
  <td>${escapeHtml(exposure(bind))}${inst.secure ? " (secure=true)" : ""}${inst.enabled ? "" : " (disabled)"}</td>
</tr>`;
                })
                .join("");
            })
            .join("");

          const html = [
            '<div style="display:flex;flex-direction:column;gap:10px;">',
            `<div><b>WireGuard‑Host‑IP:</b> ${escapeHtml(wgHostIp)}</div>`,
            `<div><b>Erlaubte Ports (VPN → Host):</b> ${escapeHtml(allowedPorts.join(", "))}</div>`,
            '<div style="opacity:0.9;">Tipp: Damit Dienste NUR über VPN erreichbar sind, binde sie an die WireGuard‑Host‑IP (oben) statt an 0.0.0.0.</div>',
            '<table style="border-collapse:collapse;width:100%;">',
            '<thead><tr><th style="text-align:left;border-bottom:1px solid rgba(0,0,0,0.2);padding:4px;">Port</th><th style="text-align:left;border-bottom:1px solid rgba(0,0,0,0.2);padding:4px;">Instanz</th><th style="text-align:left;border-bottom:1px solid rgba(0,0,0,0.2);padding:4px;">Bind</th><th style="text-align:left;border-bottom:1px solid rgba(0,0,0,0.2);padding:4px;">Erreichbarkeit</th></tr></thead>',
            `<tbody>${rowsHtml}</tbody>`,
            '</table>',
            '</div>',
          ].join('');

          reply(html);
          break;
        }
        default:
          reply({ text: `Unbekannter Befehl: ${obj.command}`, icon: "no-connection" });
          break;
      }
    } catch (e) {
      const msg = e && e.message ? e.message : String(e);
      this._setLastError(e);
      this.log.error(`Command ${obj.command} failed: ${msg}`);
      reply({ text: `FEHLER: ${msg}`, style: { color: "red" }, icon: "no-connection" });
    }
  }

  async _ensureObjects() {
    const objects = [
      {
        id: "info.connection",
        common: { name: "Connection", type: "boolean", role: "indicator.connected", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "info.interfaceUp",
        common: { name: "WireGuard interface up", type: "boolean", role: "indicator.state", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "info.serverPublicKey",
        common: { name: "Server public key", type: "string", role: "text", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "info.lastError",
        common: { name: "Last error", type: "string", role: "text", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "info.peerCount",
        common: { name: "Peer count", type: "number", role: "value", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "info.lastStatus",
        common: { name: "Last status (json)", type: "string", role: "json", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "profiles.lastGeneratedHtml",
        common: { name: "Last generated output (HTML)", type: "string", role: "html", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "profiles.lastGeneratedName",
        common: { name: "Last generated profile name", type: "string", role: "text", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "profiles.lastGeneratedPeerIp",
        common: { name: "Last generated peer IP", type: "string", role: "text", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "profiles.lastGeneratedAt",
        common: { name: "Last generated timestamp", type: "number", role: "value.time", read: true, write: false },
        native: {},
        type: "state",
      },

      {
        id: "support.active",
        common: { name: "Support access active", type: "boolean", role: "indicator.maintenance", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "support.peerName",
        common: { name: "Support peer name", type: "string", role: "text", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "support.peerIp",
        common: { name: "Support peer IP", type: "string", role: "text", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "support.expiresAt",
        common: { name: "Support access expires at", type: "number", role: "value.time", read: true, write: false },
        native: {},
        type: "state",
      },
      {
        id: "support.lastOutputHtml",
        common: { name: "Support output (HTML)", type: "string", role: "html", read: true, write: false },
        native: {},
        type: "state",
      },
    ];

    for (const o of objects) {
      await this.setObjectNotExistsAsync(o.id, o).catch(() => {});
    }
  }

  _getEffectiveConfig() {
    const allowedPorts = String(this.config.allowedPorts || "8081,8082")
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean)
      .map((p) => Number(p))
      .filter((n) => Number.isFinite(n) && n > 0 && n <= 65535);

    return {
      enabled: !!this.config.enabled,
      ifaceName: String(this.config.ifaceName || "wg-nexowattvpn").trim(),
      listenPort: Number(this.config.listenPort || 51820),
      vpnCidr: String(this.config.vpnCidr || "10.80.80.0/24").trim(),
      hostVpnIp: String(this.config.hostVpnIp || "10.80.80.1/24").trim(),
      endpointHost: String(this.config.endpointHost || "").trim(),
      dns: String(this.config.dns || "").trim(),
      persistentKeepalive: Number(this.config.persistentKeepalive || 25),
      allowedPorts,
      firewallBackend: "nft",
      openListenPort: !!this.config.openListenPort,
      usePsk: this.config.usePsk !== false,

      // Installer / sudoers bootstrap
      serviceUser: String(this.config.serviceUser || "iobroker").trim(),

      // Support access (opt-in)
      supportPeerName: String(this.config.supportPeerName || "nexowatt-support").trim(),
      supportPeerPublicKey: String(this.config.supportPeerPublicKey || "").trim(),
      supportExpiryMinutes: Number(this.config.supportExpiryMinutes || 60),
    };
  }

  async _checkSupportExpiry() {
    // If support is time-limited, revoke automatically.
    const expires = await this.getStateAsync("support.expiresAt").catch(() => null);
    const active = await this.getStateAsync("support.active").catch(() => null);
    const expiresAt = Number(expires?.val || 0);
    const isActive = !!active?.val;
    if (!isActive || !expiresAt || !Number.isFinite(expiresAt)) return;
    if (Date.now() < expiresAt) return;

    const cfg = this._getEffectiveConfig();
    this.log.warn(`Support access expired (${new Date(expiresAt).toISOString()}). Disabling support profile '${cfg.supportPeerName}'.`);
    try {
      await this._callHelper("disableSupportProfile", { cfg, supportPeerName: cfg.supportPeerName });
    } catch (e) {
      // Still mark as expired locally; user can re-run disable later if needed
      this._setLastError(e);
    }
    await this.setStateAsync("support.active", { val: false, ack: true }).catch(() => {});
    await this.setStateAsync("support.peerIp", { val: "", ack: true }).catch(() => {});
    await this.setStateAsync("support.expiresAt", { val: 0, ack: true }).catch(() => {});
    await this.setStateAsync("support.lastOutputHtml", { val: "", ack: true }).catch(() => {});
  }

  async _pollStatus() {
    try {
      const cfg = this._getEffectiveConfig();
      const res = await this._callHelper("status", { cfg });
      const status = res.result || {};
      await this.setStateAsync("info.interfaceUp", { val: !!status.interfaceUp, ack: true });
      await this.setStateAsync("info.connection", { val: !!status.interfaceUp, ack: true });
      await this.setStateAsync("info.serverPublicKey", { val: status.serverPublicKey || "", ack: true });
      await this.setStateAsync("info.peerCount", { val: Number(status.peerCount || 0), ack: true });
      await this.setStateAsync("info.lastStatus", { val: JSON.stringify(status), ack: true });
      await this.setStateAsync("info.lastError", { val: "", ack: true });
    } catch (e) {
      this._setLastError(e);
      await this.setStateAsync("info.connection", { val: false, ack: true }).catch(() => {});
    }
  }

  _setLastError(e) {
    const msg = e && e.message ? e.message : String(e);
    this.setState("info.lastError", { val: msg, ack: true }).catch(() => {});
  }

  _sudoCheck() {
    const runAsRoot = typeof process.getuid === "function" ? process.getuid() === 0 : false;
    if (runAsRoot) return Promise.resolve(true);
    return new Promise((resolve) => {
      execFile("sudo", ["-n", "true"], { timeout: 10_000 }, (err) => {
        resolve(!err);
      });
    });
  }

  _callHelper(command, payload) {
    const helperPath = path.join(__dirname, "lib", "root-helper.js");

    const json = Buffer.from(JSON.stringify(payload || {}), "utf8").toString("base64");
    const args = [process.execPath, helperPath, command, "--json", json];

    const runAsRoot = typeof process.getuid === "function" ? process.getuid() === 0 : false;
    const cmd = runAsRoot ? process.execPath : "sudo";
    const cmdArgs = runAsRoot ? args.slice(1) : ["-n", ...args];

    return new Promise((resolve, reject) => {
      // Installer actions can take several minutes (apt). Keep a generous timeout.
      execFile(cmd, cmdArgs, { timeout: 20 * 60_000, maxBuffer: 20 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          const msg = (stderr || stdout || error.message || String(error)).toString().trim();
          return reject(new Error(msg || "Helper failed"));
        }
        const out = (stdout || "").toString().trim();
        if (!out) return reject(new Error("Helper returned empty output"));
        let parsed;
        try {
          parsed = JSON.parse(out);
        } catch (e) {
          return reject(new Error(`Invalid helper JSON: ${out.slice(0, 400)}`));
        }
        if (!parsed.ok) return reject(new Error(parsed.error || "Unknown helper error"));
        resolve(parsed);
      });
    });
  }
}

if (module && module.parent) {
  module.exports = (options) => new NexoWattVPN(options);
} else {
  new NexoWattVPN();
}
