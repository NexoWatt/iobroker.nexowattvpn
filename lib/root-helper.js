#!/usr/bin/env node
"use strict";

/**
 * Root helper for ioBroker.nexowattvpn
 * This script MUST be executed as root (via sudo) to:
 * - create/update /etc/wireguard/<iface>.conf
 * - start/stop WireGuard interface via wg-quick
 * - add/remove peers (also live via wg set if interface is up)
 * - apply/remove a strict firewall policy on the wg interface:
 *     allow TCP ports (default: 8081,8082,8188,8086) to the host only; drop everything else
 *     drop forwarding from wg interface to prevent LAN access/pivoting
 *
 * The helper prints a single JSON object to stdout:
 *   { ok: true, result: ... }   or   { ok: false, error: "..." }
 *
 * Added installer/support commands:
 * - prereqCheck: detect OS + presence of wg/wg-quick/nft/systemctl
 * - installPrereqs: install required packages on Debian/Ubuntu via apt and enable nftables
 * - bootstrap: install prereqs AND write sudoers rule so the adapter can run this helper non-interactively
 * - enableSupportProfile/disableSupportProfile: opt-in, time-limited support access (public-key peer)
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const { spawnSync } = require("child_process");

function out(obj) {
  process.stdout.write(JSON.stringify(obj));
}

function ok(result) {
  out({ ok: true, result });
  process.exit(0);
}

function fail(error, code = 1) {
  out({ ok: false, error: String(error || "unknown error") });
  process.exit(code);
}

function getArgValue(flag) {
  const idx = process.argv.indexOf(flag);
  if (idx === -1) return null;
  return process.argv[idx + 1] ?? null;
}

function assertRoot() {
  if (typeof process.getuid === "function" && process.getuid() !== 0) {
    fail("root-helper must run as root (use sudo).");
  }
}

function cmdExists(cmd, args = ["--version"]) {
  const r = spawnSync(cmd, args, { stdio: "ignore" });
  return r && r.status === 0;
}

function run(cmd, args, options = {}) {
  const r = spawnSync(cmd, args, {
    encoding: "utf8",
    input: options.input,
    env: options.env,
    timeout: options.timeout,
    stdio: options.stdio || ["pipe", "pipe", "pipe"],
  });

  const stdout = (r.stdout || "").toString();
  const stderr = (r.stderr || "").toString();
  if (r.error) {
    const msg = r.error.message || String(r.error);
    throw new Error(`${cmd} failed: ${msg}`);
  }
  if (r.status !== 0) {
    const msg = (stderr || stdout || "").trim();
    throw new Error(`${cmd} ${args.join(" ")} failed: ${msg || "exit " + r.status}`);
  }
  return { stdout, stderr, status: r.status };
}

function readOsRelease() {
  const p = "/etc/os-release";
  const txt = readFileIfExists(p);
  const out = {};
  for (const line of txt.split(/\r?\n/)) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (!m) continue;
    let v = m[2];
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    out[m[1]] = v;
  }
  return out;
}

function isDebianLike(osr) {
  const id = String(osr.ID || "").toLowerCase();
  const like = String(osr.ID_LIKE || "").toLowerCase();
  return [id, like].some((s) => s.includes("debian") || s.includes("ubuntu") || s.includes("raspbian"));
}

function prereqCheck() {
  const osr = readOsRelease();
  const debianLike = isDebianLike(osr);
  return {
    os: {
      id: osr.ID || "",
      id_like: osr.ID_LIKE || "",
      name: osr.NAME || "",
      version: osr.VERSION || "",
      pretty_name: osr.PRETTY_NAME || "",
      debianLike,
    },
    commands: {
      wg: cmdExists("wg", ["--version"]),
      wgQuick: cmdExists("wg-quick", ["--help"]),
      nft: cmdExists("nft", ["--version"]),
      systemctl: cmdExists("systemctl", ["--version"]),
      aptGet: cmdExists("apt-get", ["--version"]),
      visudo: cmdExists("visudo", ["-V"]),
    },
    paths: {
      etcWireguardExists: fs.existsSync("/etc/wireguard"),
    },
  };
}

function installPrereqs() {
  const checkBefore = prereqCheck();
  if (!checkBefore.os.debianLike) {
    throw new Error(`Unsupported OS for auto-install (only Debian/Ubuntu/Raspberry Pi OS). Detected: ${checkBefore.os.pretty_name || checkBefore.os.id || "unknown"}`);
  }

  const missing = !checkBefore.commands.wg || !checkBefore.commands.wgQuick || !checkBefore.commands.nft;

  // Only run apt if something is missing
  if (missing) {
    if (!checkBefore.commands.aptGet) {
      throw new Error("apt-get not found; cannot auto-install prereqs.");
    }

    const env = { ...process.env, DEBIAN_FRONTEND: "noninteractive" };
    // Keep timeouts generous; package mirrors can be slow.
    run("apt-get", ["update"], { env, timeout: 10 * 60_000 });
    run("apt-get", ["install", "-y", "wireguard-tools", "nftables"], { env, timeout: 15 * 60_000 });
  }

  // Enable nftables service if systemd is present (best-effort)
  if (checkBefore.commands.systemctl) {
    try {
      run("systemctl", ["enable", "--now", "nftables"], { timeout: 60_000 });
    } catch (e) {
      // Some minimal distros do not ship the nftables unit - ignore.
    }
  }

  // Hardening: ensure forwarding is disabled (host-only access target)
  try {
    const sysctlFile = "/etc/sysctl.d/99-nexowattvpn.conf";
    const sysctlContent = [
      "# Managed by ioBroker.nexowattvpn (NexoWattVPN)",
      "net.ipv4.ip_forward=0",
      "net.ipv6.conf.all.forwarding=0",
      "",
    ].join("\n");
    fs.writeFileSync(sysctlFile, sysctlContent, { encoding: "utf8", mode: 0o644 });
    try { fs.chownSync(sysctlFile, 0, 0); } catch (e) {}
    if (cmdExists("sysctl", ["--version"])) {
      try { run("sysctl", ["--system"], { timeout: 60_000 }); } catch (e) {}
    }
  } catch (e) {
    // ignore
  }

  ensureDir("/etc/wireguard");
  try { fs.chmodSync("/etc/wireguard", 0o700); } catch (e) {}
  try { fs.chownSync("/etc/wireguard", 0, 0); } catch (e) {}

  return prereqCheck();
}

function validateServiceUser(user) {
  const u = String(user || "").trim();
  if (!u) throw new Error("serviceUser is empty");
  if (!/^[a-z_][a-z0-9_-]*$/.test(u)) throw new Error("serviceUser invalid");
  return u;
}

function validateAbsoluteExistingPath(p, label) {
  const s = String(p || "").trim();
  if (!s || !path.isAbsolute(s)) throw new Error(`${label} must be an absolute path`);
  if (!fs.existsSync(s)) throw new Error(`${label} does not exist: ${s}`);
  return s;
}

function writeSudoersRule({ serviceUser, nodePath, helperPath }) {
  const u = validateServiceUser(serviceUser);
  const node = validateAbsoluteExistingPath(nodePath, "nodePath");
  const helper = validateAbsoluteExistingPath(helperPath, "helperPath");

  const sudoersPath = "/etc/sudoers.d/nexowattvpn";
  const line = `${u} ALL=(root) NOPASSWD: ${node} ${helper} *`;
  const content = [
    "# Managed by ioBroker.nexowattvpn (NexoWattVPN)",
    "# Allows the adapter (service user) to run the minimal root-helper without a password.",
    line,
    "",
  ].join("\n");

  fs.writeFileSync(sudoersPath, content, { encoding: "utf8", mode: 0o440 });
  try { fs.chownSync(sudoersPath, 0, 0); } catch (e) {}
  fs.chmodSync(sudoersPath, 0o440);

  // Validate sudoers syntax if visudo exists
  if (cmdExists("visudo", ["-V"])) {
    try {
      run("visudo", ["-cf", sudoersPath], { timeout: 20_000 });
    } catch (e) {
      throw new Error(`sudoers validation failed: ${e.message || e}`);
    }
  }

  return { sudoersPath, line };
}

function normalizeIfaceName(name) {
  name = String(name || "").trim();
  if (!name) throw new Error("ifaceName is empty");
  name = name.replace(/\.conf$/i, "");
  // Linux interface naming rules are broad; we keep it strict
  if (!/^[a-zA-Z0-9_.-]{1,15}$/.test(name)) {
    throw new Error("ifaceName contains invalid characters (allowed: a-zA-Z0-9_.-; length <= 15)");
  }
  return name;
}

function parsePorts(ports) {
  if (!Array.isArray(ports)) ports = String(ports || "").split(",").map((p) => p.trim()).filter(Boolean);
  const out = [];
  for (const p of ports) {
    const n = Number(p);
    if (!Number.isFinite(n) || n < 1 || n > 65535) continue;
    out.push(n);
  }
  // de-dup + stable sort
  return Array.from(new Set(out)).sort((a, b) => a - b);
}

function ipv4ToInt(ip) {
  const parts = String(ip).trim().split(".");
  if (parts.length !== 4) throw new Error(`Invalid IPv4: ${ip}`);
  let n = 0;
  for (const part of parts) {
    const v = Number(part);
    if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error(`Invalid IPv4: ${ip}`);
    n = (n << 8) + v;
  }
  // ensure unsigned
  return n >>> 0;
}

function intToIpv4(n) {
  n = n >>> 0;
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function parseCidr(cidr) {
  const s = String(cidr || "").trim();
  const m = s.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d{1,2})$/);
  if (!m) throw new Error(`Invalid CIDR: ${cidr}`);
  const ip = m[1];
  const prefix = Number(m[2]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) throw new Error(`Invalid CIDR prefix: ${cidr}`);
  const ipInt = ipv4ToInt(ip);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = ipInt & mask;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  return { ip, prefix, ipInt, mask, network, broadcast };
}

function getHostIpFromCidr(ipWithPrefix) {
  const s = String(ipWithPrefix || "").trim();
  const m = s.match(/^(\d+\.\d+\.\d+\.\d+)(?:\/\d{1,2})?$/);
  if (!m) throw new Error(`Invalid IP: ${ipWithPrefix}`);
  return m[1];
}

function safeProfileName(name) {
  name = String(name || "").trim();
  if (!name) throw new Error("profileName is empty");
  // avoid tricky characters/newlines
  if (!/^[a-zA-Z0-9_.-]{1,64}$/.test(name)) {
    throw new Error("profileName invalid (allowed: a-zA-Z0-9 _ . - ; no spaces; length <= 64)");
  }
  return name;
}

function wireguardConfPath(ifaceName) {
  return path.join("/etc/wireguard", `${ifaceName}.conf`);
}

function ensureDir(p) {
  fs.mkdirSync(p, { recursive: true });
}

function readFileIfExists(p) {
  try {
    return fs.readFileSync(p, "utf8");
  } catch (e) {
    return "";
  }
}

function writeFile600(p, content) {
  fs.writeFileSync(p, content, { encoding: "utf8", mode: 0o600 });
  try {
    fs.chownSync(p, 0, 0);
  } catch (e) {
    // ignore if not supported
  }
  fs.chmodSync(p, 0o600);
}

function wgGenKey() {
  if (!cmdExists("wg", ["--version"])) {
    throw new Error("wg (wireguard-tools) not found. Install wireguard-tools.");
  }
  return run("wg", ["genkey"]).stdout.trim();
}

function wgPubKey(privateKey) {
  return run("wg", ["pubkey"], { input: privateKey }).stdout.trim();
}

function wgGenPsk() {
  if (!cmdExists("wg", ["--version"])) {
    throw new Error("wg (wireguard-tools) not found. Install wireguard-tools.");
  }
  return run("wg", ["genpsk"]).stdout.trim();
}

function isInterfaceUp(ifaceName) {
  if (!cmdExists("wg", ["--version"])) return false;
  const r = spawnSync("wg", ["show", ifaceName], { stdio: "ignore" });
  return r && r.status === 0;
}

function parseServerPrivateKey(confText) {
  const m = confText.match(/^\s*PrivateKey\s*=\s*([A-Za-z0-9+/=]+)\s*$/m);
  return m ? m[1].trim() : null;
}

function parseListenPort(confText) {
  const m = confText.match(/^\s*ListenPort\s*=\s*(\d+)\s*$/m);
  return m ? Number(m[1]) : null;
}

function findPeersSectionStart(confText) {
  const m = confText.match(/^\[Peer\]\s*$/m);
  if (!m) return -1;
  return m.index ?? -1;
}

function ensureServerConfig(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const confPath = wireguardConfPath(ifaceName);
  ensureDir(path.dirname(confPath));

  const old = readFileIfExists(confPath);
  let serverPrivateKey = parseServerPrivateKey(old);
  if (!serverPrivateKey) serverPrivateKey = wgGenKey();
  const serverPublicKey = wgPubKey(serverPrivateKey);

  const peersStart = findPeersSectionStart(old);
  const peersPart = peersStart >= 0 ? old.slice(peersStart).trimStart() : "";

  const hostVpnIp = String(cfg.hostVpnIp || "").trim();
  if (!/^\d+\.\d+\.\d+\.\d+\/\d{1,2}$/.test(hostVpnIp)) {
    throw new Error(`hostVpnIp must be IPv4 with prefix (e.g. 10.80.80.1/24). Got: ${hostVpnIp}`);
  }
  const listenPort = Number(cfg.listenPort || 51820);
  if (!Number.isInteger(listenPort) || listenPort < 1 || listenPort > 65535) {
    throw new Error(`listenPort invalid: ${cfg.listenPort}`);
  }

  const header = [
    "# Managed by ioBroker.nexowattvpn (NexoWattVPN)",
    "# DO NOT edit manually unless you know what you are doing.",
    "",
    "[Interface]",
    `Address = ${hostVpnIp}`,
    `ListenPort = ${listenPort}`,
    `PrivateKey = ${serverPrivateKey}`,
    "",
  ].join("\n");

  const content = peersPart ? `${header}\n${peersPart.trim()}\n` : `${header}\n`;
  writeFile600(confPath, content);

  return { confPath, ifaceName, serverPublicKey, listenPort };
}

function ensureNft() {
  if (!cmdExists("nft", ["--version"])) {
    throw new Error("nft not found. Please install nftables (nft command).");
  }
  return "nft";
}

/**
 * Apply strict policy:
 * - On wg interface INPUT: allow established/related, allow tcp dports allowedPorts, drop rest
 * - On FORWARD: drop any packets entering from wg interface (prevents LAN routing)
 *
 * Implemented as a dedicated nftables inet table/chain (fixed backend: nft only).
 */
function applyFirewall(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const allowedPorts = parsePorts(cfg.allowedPorts);
  if (!allowedPorts.length) throw new Error("allowedPorts empty");

  // Fixed backend: nftables
  ensureNft();

  // nftables backend (inet table)
  const table = "nexowattvpn";
  const family = "inet";
  const chainIn = "input";
  const chainFwd = "forward";
  const portTokens = allowedPorts.map((p, i) => (i === allowedPorts.length - 1 ? String(p) : `${p},`));

  // Create table if missing
  try { run("nft", ["add", "table", family, table]); } catch (e) {}

  // Create chains with hooks if missing (explicit policy accept)
  try {
    run("nft", ["add", "chain", family, table, chainIn, "{", "type", "filter", "hook", "input", "priority", "-150", ";", "policy", "accept", ";", "}"]);
  } catch (e) {}
  try {
    run("nft", ["add", "chain", family, table, chainFwd, "{", "type", "filter", "hook", "forward", "priority", "-150", ";", "policy", "accept", ";", "}"]);
  } catch (e) {}

  // Flush chains
  run("nft", ["flush", "chain", family, table, chainIn]);
  run("nft", ["flush", "chain", family, table, chainFwd]);

  // Rules: allow established/related on iface; allow tcp ports; drop rest on iface
  run("nft", ["add", "rule", family, table, chainIn, "iifname", ifaceName, "ct", "state", "{", "established", ",", "related", "}", "accept"]);
  run("nft", ["add", "rule", family, table, chainIn, "iifname", ifaceName, "tcp", "dport", "{", ...portTokens, "}", "accept"]);
  run("nft", ["add", "rule", family, table, chainIn, "iifname", ifaceName, "drop"]);

  // Forward: drop anything entering from iface
  run("nft", ["add", "rule", family, table, chainFwd, "iifname", ifaceName, "drop"]);

  return { backend: "nft", ifaceName, allowedPorts };
}


function removeFirewall(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);

  // Fixed backend: nftables
  ensureNft();

  // nft: remove whole table
  const family = "inet";
  const table = "nexowattvpn";
  try { run("nft", ["delete", "table", family, table]); } catch (e) {}
  return { backend: "nft", ifaceName };
}


function wgQuickUp(ifaceName) {
  if (!cmdExists("wg-quick", ["--help"])) {
    throw new Error("wg-quick not found. Install wireguard-tools.");
  }
  // Make this idempotent: if the interface is already up, do not fail.
  if (cmdExists("wg", ["show", ifaceName])) {
    return;
  }
  run("wg-quick", ["up", ifaceName]);
}

function wgQuickDown(ifaceName) {
  if (!cmdExists("wg-quick", ["--help"])) {
    throw new Error("wg-quick not found. Install wireguard-tools.");
  }
  // Make this idempotent: if the interface is not up, do not fail.
  if (!cmdExists("wg", ["show", ifaceName])) {
    return;
  }
  run("wg-quick", ["down", ifaceName]);
}

function getUsedPeerIpsFromConf(confText) {
  const ips = new Set();
  const re = /^\s*AllowedIPs\s*=\s*([0-9.]+)\/32\s*$/gm;
  let m;
  while ((m = re.exec(confText))) {
    ips.add(m[1]);
  }
  return ips;
}

function allocatePeerIp(cfg, confText) {
  const vpn = parseCidr(String(cfg.vpnCidr || "").trim());
  const hostIp = getHostIpFromCidr(cfg.hostVpnIp);

  const used = getUsedPeerIpsFromConf(confText);
  used.add(hostIp);

  // Avoid network and broadcast
  const start = vpn.network + 1;
  const end = vpn.broadcast - 1;

  // Start from +2 to keep .1 for host (common convention)
  for (let ipInt = vpn.network + 2; ipInt <= end; ipInt++) {
    const ip = intToIpv4(ipInt);
    if (!used.has(ip)) return ip;
  }
  // fallback: try from +1
  for (let ipInt = start; ipInt <= end; ipInt++) {
    const ip = intToIpv4(ipInt);
    if (!used.has(ip)) return ip;
  }
  throw new Error("No free peer IPs left in vpnCidr");
}

function appendPeerToConf(confText, peer) {
  const marker = `# NEXOWATTVPN_PEER name=${peer.name} publicKey=${peer.publicKey} ip=${peer.ip}`;
  const lines = [
    "",
    marker,
    "[Peer]",
    `PublicKey = ${peer.publicKey}`,
  ];
  if (peer.presharedKey) lines.push(`PresharedKey = ${peer.presharedKey}`);
  lines.push(`AllowedIPs = ${peer.ip}/32`);
  lines.push("");

  return (confText || "").trimEnd() + lines.join("\n") + "\n";
}

function removePeerByNameFromConf(confText, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Remove block from marker line until next marker or end
  const re = new RegExp(
    `^#\\s*NEXOWATTVPN_PEER\\s+name=${escaped}\\b[\\s\\S]*?(?=^#\\s*NEXOWATTVPN_PEER\\s+name=|\\Z)`,
    "m"
  );
  const m = confText.match(re);
  if (!m) return { updated: confText, removed: null };
  const removedBlock = m[0];
  const updated = confText.replace(re, "").replace(/\n{3,}/g, "\n\n");
  // Parse publicKey from removed block
  const pk = (removedBlock.match(/publicKey=([A-Za-z0-9+/=]+)/) || [])[1] || null;
  const ip = (removedBlock.match(/ip=([0-9.]+)/) || [])[1] || null;
  return { updated, removed: { publicKey: pk, ip } };
}

function derivePskFromPassword(password, salt) {
  // salt: stable per peer (use publicKey)
  const key = crypto.scryptSync(String(password), String(salt), 32);
  return key.toString("base64");
}

function validateWireGuardPublicKey(publicKey) {
  const pk = String(publicKey || "").trim();
  // WireGuard public keys are base64 encoded 32 bytes (usually 44 chars with '=' padding)
  if (!/^[A-Za-z0-9+/=]{40,60}$/.test(pk)) {
    throw new Error("peerPublicKey invalid (expected WireGuard base64 public key)");
  }
  return pk;
}

function createPeerFromPublicKey(cfg, profileName, peerPublicKey, password, kind) {
  const name = safeProfileName(profileName);
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const ensured = ensureServerConfig(cfg);
  const confPath = ensured.confPath;
  let confText = readFileIfExists(confPath);

  const publicKey = validateWireGuardPublicKey(peerPublicKey);

  // If an old peer with this name exists, remove it first (rotate)
  const removed = removePeerByNameFromConf(confText, name);
  if (removed.removed && removed.removed.publicKey && isInterfaceUp(ifaceName)) {
    try { run("wg", ["set", ifaceName, "peer", removed.removed.publicKey, "remove"]); } catch (e) {}
  }
  confText = removed.updated;

  // Reuse IP if the previous peer existed, else allocate new
  const peerIp = removed.removed?.ip || allocatePeerIp(cfg, confText);

  // PSK (optional)
  let psk = null;
  if (cfg.usePsk !== false) {
    if (password && String(password).trim()) {
      psk = derivePskFromPassword(String(password).trim(), publicKey);
    } else {
      psk = wgGenPsk();
    }
  }

  // Append peer to server config
  const markerKind = kind ? String(kind).trim() : "";
  const peerBlock = { name, publicKey, presharedKey: psk, ip: peerIp };
  let updatedConf = appendPeerToConf(confText, peerBlock);
  if (markerKind) {
    // Insert kind token into the marker line for easier auditing.
    updatedConf = updatedConf.replace(
      new RegExp(`^#\\s*NEXOWATTVPN_PEER\\s+name=${name}\\s+publicKey=${publicKey}\\s+ip=${peerIp}\\s*$`, "m"),
      `# NEXOWATTVPN_PEER name=${name} publicKey=${publicKey} ip=${peerIp} kind=${markerKind}`
    );
  }
  writeFile600(confPath, updatedConf);

  // If interface is up, add peer live
  if (isInterfaceUp(ifaceName)) {
    const args = ["set", ifaceName, "peer", publicKey, "allowed-ips", `${peerIp}/32`];
    let tmpFile = null;
    try {
      if (psk) {
        tmpFile = path.join(os.tmpdir(), `nexowattvpn-psk-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
        fs.writeFileSync(tmpFile, psk + "\n", { encoding: "utf8", mode: 0o600 });
        args.push("preshared-key", tmpFile);
      }
      run("wg", args);
    } finally {
      if (tmpFile) {
        try { fs.unlinkSync(tmpFile); } catch (e) {}
      }
    }
  }

  const hostOnly = `${getHostIpFromCidr(cfg.hostVpnIp)}/32`;
  const endpointHost = String(cfg.endpointHost || "").trim();
  const listenPort = Number(cfg.listenPort || 51820);
  const keepalive = Number(cfg.persistentKeepalive || 25);

  const clientTemplateLines = [
    "[Interface]",
    "PrivateKey = <FILL_IN_YOUR_PRIVATE_KEY>",
    `Address = ${peerIp}/32`,
    "",
    "[Peer]",
    `PublicKey = ${ensured.serverPublicKey}`,
  ];
  if (psk) clientTemplateLines.push(`PresharedKey = ${psk}`);
  if (endpointHost) clientTemplateLines.push(`Endpoint = ${endpointHost}:${listenPort}`);
  clientTemplateLines.push(`AllowedIPs = ${hostOnly}`);
  if (Number.isFinite(keepalive) && keepalive > 0) clientTemplateLines.push(`PersistentKeepalive = ${keepalive}`);
  clientTemplateLines.push("");

  return {
    profileName: name,
    kind: markerKind || "",
    peerIp,
    peerPublicKey: publicKey,
    serverPublicKey: ensured.serverPublicKey,
    presharedKey: psk || "",
    allowedIpsClient: hostOnly,
    endpoint: endpointHost ? `${endpointHost}:${listenPort}` : "",
    clientConfigTemplate: clientTemplateLines.join("\n"),
    note: endpointHost ? "" : "endpointHost is empty; set it in adapter config for remote use.",
  };
}

function enableSupportProfile(cfg, payload) {
  const name = safeProfileName(payload.supportPeerName || payload.profileName || "");
  const pk = validateWireGuardPublicKey(payload.supportPeerPublicKey || payload.peerPublicKey || "");
  const password = String(payload.password || "");
  return createPeerFromPublicKey(cfg, name, pk, password, "support");
}

function disableSupportProfile(cfg, payload) {
  const name = safeProfileName(payload.supportPeerName || payload.profileName || "");
  return revokeProfile(cfg, name);
}

function createProfile(cfg, profileName, password) {
  const name = safeProfileName(profileName);
  const ifaceName = normalizeIfaceName(cfg.ifaceName);

  // Ensure server config exists and read it
  const ensured = ensureServerConfig(cfg);
  const confPath = ensured.confPath;
  const confText = readFileIfExists(confPath);

  // Generate client keypair
  const clientPrivateKey = wgGenKey();
  const clientPublicKey = wgPubKey(clientPrivateKey);

  // Allocate peer IP
  const peerIp = allocatePeerIp(cfg, confText);

  // PSK (optional)
  let psk = null;
  if (cfg.usePsk !== false) {
    if (password && String(password).trim()) {
      psk = derivePskFromPassword(String(password).trim(), clientPublicKey);
    } else {
      // random, as strong as it gets
      psk = wgGenPsk();
    }
  }

  // Append peer to server config
  const updatedConf = appendPeerToConf(confText, { name, publicKey: clientPublicKey, presharedKey: psk, ip: peerIp });
  writeFile600(confPath, updatedConf);

  // If interface is up, add peer live
  if (isInterfaceUp(ifaceName)) {
    const args = ["set", ifaceName, "peer", clientPublicKey, "allowed-ips", `${peerIp}/32`];
    let tmpFile = null;
    try {
      if (psk) {
        tmpFile = path.join(os.tmpdir(), `nexowattvpn-psk-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
        fs.writeFileSync(tmpFile, psk + "\n", { encoding: "utf8", mode: 0o600 });
        args.push("preshared-key", tmpFile);
      }
      run("wg", args);
    } finally {
      if (tmpFile) {
        try { fs.unlinkSync(tmpFile); } catch (e) {}
      }
    }
  }

  // Build client configuration:
  // AllowedIPs: host only (no LAN, no 0.0.0.0/0)
  const hostOnly = `${getHostIpFromCidr(cfg.hostVpnIp)}/32`;
  const endpointHost = String(cfg.endpointHost || "").trim();
  const listenPort = Number(cfg.listenPort || 51820);
  const dns = String(cfg.dns || "").trim();
  const keepalive = Number(cfg.persistentKeepalive || 25);

  if (!endpointHost) {
    // Still return config but warn
  }

  const clientLines = [
    "[Interface]",
    `PrivateKey = ${clientPrivateKey}`,
    `Address = ${peerIp}/32`,
  ];
  if (dns) clientLines.push(`DNS = ${dns}`);
  clientLines.push("");
  clientLines.push("[Peer]");
  clientLines.push(`PublicKey = ${ensured.serverPublicKey}`);
  if (psk) clientLines.push(`PresharedKey = ${psk}`);
  if (endpointHost) clientLines.push(`Endpoint = ${endpointHost}:${listenPort}`);
  clientLines.push(`AllowedIPs = ${hostOnly}`);
  if (Number.isFinite(keepalive) && keepalive > 0) clientLines.push(`PersistentKeepalive = ${keepalive}`);
  clientLines.push("");

  return {
    profileName: name,
    peerIp,
    peerPublicKey: clientPublicKey,
    serverPublicKey: ensured.serverPublicKey,
    clientConfig: clientLines.join("\n"),
    note: endpointHost ? "" : "endpointHost is empty; set it in adapter config to use the config remotely.",
  };
}

function revokeProfile(cfg, profileName) {
  const name = safeProfileName(profileName);
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const confPath = wireguardConfPath(ifaceName);

  const confText = readFileIfExists(confPath);
  if (!confText) return { revoked: false, reason: "config file not found" };

  const { updated, removed } = removePeerByNameFromConf(confText, name);
  if (!removed) return { revoked: false, reason: "profile not found" };

  writeFile600(confPath, updated);

  // If interface is up, remove peer live
  if (removed.publicKey && isInterfaceUp(ifaceName)) {
    try {
      run("wg", ["set", ifaceName, "peer", removed.publicKey, "remove"]);
    } catch (e) {
      // ignore live removal errors, config file is authoritative
    }
  }

  return { revoked: true, removed };
}

function listProfiles(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const confPath = `/etc/wireguard/${ifaceName}.conf`;
  if (!fs.existsSync(confPath)) throw new Error(`WireGuard config not found: ${confPath}`);

  const confText = fs.readFileSync(confPath, "utf8");
  const lines = confText.split(/\r?\n/);

  const peers = [];
  const markerRe = /^\s*#\s*NEXOWATTVPN_PEER\s+name=([^\s]+)\s+publicKey=([^\s]+)\s+ip=([0-9.]+)(?:\s+kind=([^\s]+))?\s*$/;

  for (let i = 0; i < lines.length; i++) {
    const m = markerRe.exec(lines[i]);
    if (!m) continue;

    const name = m[1];
    const publicKey = m[2];
    const ip = m[3];
    const kind = m[4] || "";

    let hasPresharedKey = false;
    let allowedIps = null;

    for (let j = i + 1; j < lines.length; j++) {
      const nextMarker = markerRe.test(lines[j]);
      if (nextMarker) break;

      if (/^\s*PresharedKey\s*=/.test(lines[j])) hasPresharedKey = true;
      const am = /^\s*AllowedIPs\s*=\s*([0-9.]+\/32)\s*$/.exec(lines[j]);
      if (am) allowedIps = am[1];
    }

    peers.push({ name, publicKey, ip, allowedIps, hasPresharedKey, kind });
  }

  return { ifaceName, confPath, peers, count: peers.length };
}

function getServerPublicKey(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const confPath = wireguardConfPath(ifaceName);
  const confText = readFileIfExists(confPath);
  if (!confText) {
    // ensure creates it
    return ensureServerConfig(cfg).serverPublicKey;
  }
  const priv = parseServerPrivateKey(confText);
  if (!priv) return ensureServerConfig(cfg).serverPublicKey;
  return wgPubKey(priv);
}


function firewallStatus(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const ports = parsePorts(cfg.allowedPorts || []);
  let tableExists = false;
  let inputChain = "";
  let forwardChain = "";
  try {
    // If table does not exist this throws
    run("nft", ["list", "table", "inet", "nexowattvpn"]);
    tableExists = true;
  } catch (e) {
    tableExists = false;
  }

  if (tableExists) {
    try {
      inputChain = run("nft", ["list", "chain", "inet", "nexowattvpn", "input"]).stdout || "";
    } catch (e) {
      inputChain = "";
    }
    try {
      forwardChain = run("nft", ["list", "chain", "inet", "nexowattvpn", "forward"]).stdout || "";
    } catch (e) {
      forwardChain = "";
    }
  }

  const ifaceMatch = inputChain.includes(`iifname "${ifaceName}"`);
  // Very simple check: all configured ports appear in the input chain output.
  const portsMatch = ports.length ? ports.every((p) => inputChain.includes(String(p))) : true;

  const forwardBlocked = forwardChain.includes(`iifname "${ifaceName}"`) && forwardChain.toLowerCase().includes("drop");

  return {
    tableExists,
    ifaceName,
    ports,
    ifaceMatch,
    portsMatch,
    forwardBlocked,
  };
}

function health(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const confPath = wireguardConfPath(ifaceName);
  const confExists = fs.existsSync(confPath);
  const confText = confExists ? readFileIfExists(confPath) : "";

  // Do NOT auto-create config here; purely reporting.
  let serverPublicKey = "";
  try {
    const priv = parseServerPrivateKey(confText);
    if (priv) serverPublicKey = wgPubKey(priv);
  } catch (e) {
    serverPublicKey = "";
  }

  const interfaceUp = isInterfaceUp(ifaceName);

  const peerCountFromConf = (confText.match(/^#\s*NEXOWATTVPN_PEER\s+/gm) || []).length;

  return {
    ifaceName,
    confPath,
    confExists,
    interfaceUp,
    listenPort: parseListenPort(confText) || Number(cfg.listenPort || 0),
    serverPublicKey,
    peerCount: peerCountFromConf,
    firewall: firewallStatus(cfg),
  };
}

function status(cfg) {
  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  const confPath = wireguardConfPath(ifaceName);
  const confText = readFileIfExists(confPath);

  const serverPublicKey = (() => {
    try {
      const priv = parseServerPrivateKey(confText);
      if (priv) return wgPubKey(priv);
      return ensureServerConfig(cfg).serverPublicKey;
    } catch (e) {
      return "";
    }
  })();

  const up = isInterfaceUp(ifaceName);

  const peers = [];
  if (up) {
    try {
      const dump = run("wg", ["show", ifaceName, "dump"]).stdout.trim();
      const lines = dump.split("\n").filter(Boolean);
      // First line is interface
      for (let i = 1; i < lines.length; i++) {
        const parts = lines[i].split("\t");
        // peerPublicKey, presharedKey, endpoint, allowedIps, latestHandshake, rx, tx, keepalive
        const peerPublicKey = parts[0] || "";
        const endpoint = parts[2] || "";
        const allowedIps = parts[3] || "";
        const latestHandshake = Number(parts[4] || 0);
        const rx = Number(parts[5] || 0);
        const tx = Number(parts[6] || 0);
        peers.push({ peerPublicKey, endpoint, allowedIps, latestHandshake, rx, tx });
      }
    } catch (e) {
      // ignore
    }
  }

  // Count peers from config markers
  const peerCountFromConf = (confText.match(/^#\s*NEXOWATTVPN_PEER\s+/gm) || []).length;

  return {
    ifaceName,
    interfaceUp: up,
    serverPublicKey,
    confPath,
    listenPort: parseListenPort(confText) || Number(cfg.listenPort || 0),
    peerCount: up ? peers.length : peerCountFromConf,
    peers,
  };
}

function fullSetup(cfg) {
  // All-in-one convenience command for vendor devices / one-click setup.
  // Performs:
  //  - install/verify prerequisites (WireGuard tools + nftables)
  //  - ensure server config
  //  - apply firewall rules
  //  - bring interface up
  const prereqs = installPrereqs();
  const server = ensureServerConfig(cfg);
  const firewall = applyFirewall(cfg);

  const ifaceName = normalizeIfaceName(cfg.ifaceName);
  wgQuickUp(ifaceName);
  const st = status(cfg);

  return { prereqs, server, firewall, status: st };
}

function main() {
  assertRoot();

  const command = process.argv[2];
  if (!command) fail("No command provided");

  const jsonB64 = getArgValue("--json");
  if (!jsonB64) fail("Missing --json argument");

  let payload;
  try {
    payload = JSON.parse(Buffer.from(jsonB64, "base64").toString("utf8"));
  } catch (e) {
    fail("Invalid --json payload");
  }

  const cfg = payload.cfg || {};
  try {
    switch (command) {
      case "ensureServer": {
        const res = ensureServerConfig(cfg);
        ok({ ...res });
        break;
      }
      case "up": {
        const ifaceName = normalizeIfaceName(cfg.ifaceName);
        // Ensure config exists first
        ensureServerConfig(cfg);
        wgQuickUp(ifaceName);
        ok({ ifaceName, interfaceUp: true });
        break;
      }
      case "down": {
        const ifaceName = normalizeIfaceName(cfg.ifaceName);
        wgQuickDown(ifaceName);
        ok({ ifaceName, interfaceUp: false });
        break;
      }
      case "applyFirewall": {
        const res = applyFirewall(cfg);
        ok(res);
        break;
      }
      case "removeFirewall": {
        const res = removeFirewall(cfg);
        ok(res);
        break;
      }
      case "createProfile": {
        const profileName = payload.profileName || "";
        const password = payload.password || "";
        const res = createProfile(cfg, profileName, password);
        ok(res);
        break;
      }
      case "revokeProfile": {
        const profileName = payload.profileName || "";
        const res = revokeProfile(cfg, profileName);
        ok(res);
        break;
      }

      case "listProfiles": {
        ok(listProfiles(cfg));
        break;
      }
      case "status": {
        ok(status(cfg));
        break;
      }
      case "firewallStatus": {
        ok(firewallStatus(cfg));
        break;
      }
      case "health": {
        ok(health(cfg));
        break;
      }
      case "getServerPublicKey": {
        ok({ serverPublicKey: getServerPublicKey(cfg) });
        break;
      }

      case "prereqCheck": {
        ok(prereqCheck());
        break;
      }
      case "installPrereqs": {
        ok(installPrereqs());
        break;
      }

      case "fullSetup": {
        ok(fullSetup(cfg));
        break;
      }
      case "bootstrap": {
        // Intended to be run once manually as root (copy/paste command from Admin UI).
        const serviceUser = payload.serviceUser || cfg.serviceUser || "iobroker";
        const nodePath = payload.nodePath || process.execPath;
        const helperPath = payload.helperPath || process.argv[1] || __filename;

        const afterInstall = installPrereqs();
        const sudoers = writeSudoersRule({ serviceUser, nodePath, helperPath });
        ok({ prereqs: afterInstall, sudoers });
        break;
      }

      case "enableSupportProfile": {
        ok(enableSupportProfile(cfg, payload));
        break;
      }
      case "disableSupportProfile": {
        ok(disableSupportProfile(cfg, payload));
        break;
      }
      default:
        fail(`Unknown command: ${command}`);
    }
  } catch (e) {
    fail(e && e.message ? e.message : String(e));
  }
}

main();
