# NexoWattVPN (ioBroker Adapter) – PiVPN/WireGuard Manager

Dieses Repository enthält einen **ioBroker Adapter** (`nexowattvpn`), der **PiVPN (WireGuard)** auf einem Raspberry Pi / Debian Host **verwaltet**:

- PiVPN/WireGuard **Konfigurationswerte** setzen (Endpoint/Port/DNS/AllowedIPs)
- **Peers/Profile** anlegen, deaktivieren, aktivieren, entfernen
- **Peer-Konfiguration** ausgeben und **QR-Code** erzeugen (für WireGuard App Import)
- Optional: **Firewall/Port-Lockdown** auf dem WireGuard-Interface (`wg0`), so dass VPN-Clients **nur auf definierte ioBroker-Ports** zugreifen können und **nicht** ins restliche Kundennetz routen.

> Wichtiger Architekturpunkt: WireGuard läuft als System-Komponente. Der Adapter ist nur das Management.

---

## Voraussetzungen

1. **PiVPN ist installiert** und nutzt **WireGuard**.
2. PiVPN ist **mindestens einmal initial konfiguriert**, so dass diese Datei existiert:
   - `/etc/pivpn/wireguard/setupVars.conf`
3. systemd ist aktiv (Raspberry Pi OS / Debian Standard).
4. Der ioBroker Host hat den Benutzer `iobroker` (Standardinstallation unter `/opt/iobroker`).

---

## Sicherheitsmodell (wichtig)

Damit der Adapter PiVPN/WireGuard verwalten darf, braucht er Root-Rechte.  
Das wird **nicht** über beliebige `sudo`-Kommandos gelöst, sondern über **einen auditierten Root-Helper**:

- `/usr/local/sbin/nexowattvpn-helper`

Der Adapter ruft ausschließlich diesen Helper auf.  
Das ist deutlich sicherer als `sudo` für `iptables`, `pivpn`, `sed` etc. direkt freizugeben.

---

## Installation (lokal)

### 1) Repository auf den ioBroker Host kopieren

Beispiel:

```bash
cd /opt/iobroker
git clone https://github.com/yourname/iobroker.nexowattvpn.git
cd iobroker.nexowattvpn
npm install
```

### 2) Root-Setup ausführen (einmalig)

```bash
sudo bash scripts/root/install-root.sh
```

Das installiert:
- Root Helper nach `/usr/local/sbin/nexowattvpn-helper`
- sudoers Regel `/etc/sudoers.d/nexowattvpn`
- systemd Service `nexowattvpn-firewall.service` (damit Firewall-Regeln nach Boot wieder gesetzt werden)

### 3) Adapter in ioBroker installieren

Je nach Setup z. B.:

```bash
# Variante A: aus lokalem Verzeichnis installieren
iobroker add ./iobroker.nexowattvpn
# oder (je nach ioBroker Version/Setup):
iobroker install ./iobroker.nexowattvpn
```

Alternativ: im Admin über "Adapter" → "Benutzerdefiniert" / GitHub-URL, wenn du das Repo veröffentlichst.

### 4) Im Admin konfigurieren

- Adapter-Instanz starten (`nexowattvpn.0`)
- Adapter-Konfiguration öffnen
- Buttons:
  - **Status aktualisieren**
  - **Konfiguration anwenden**
  - Peers erstellen und QR anzeigen

---

## Empfohlene Default-Policy (dein Use-Case)

### AllowedIPs
- **hostOnly**: setzt `ALLOWED_IPS` automatisch auf `<VPN-Server-IP>/32`  
  => Clients können nur den VPN-Server (Host) erreichen, kein LAN-Routing.

### Firewall
- `servicePortsTcp`: z. B. `8081,8082` (Admin + Web)
- `customerPortsTcp`: z. B. `8082` (nur Web, kein Admin)

Firewall-Regeln werden auf `wg0` angewendet und blocken außerdem Forwarding von/zu `wg0` (kein Zugriff ins Kundennetz).

---

## Hinweise / Einschränkungen

- Wenn `setupVars.conf` nicht existiert, kann der Adapter PiVPN nicht initialisieren.  
  In diesem Fall bitte PiVPN/WireGuard einmal manuell initial konfigurieren (PiVPN Setup) und danach den Adapter nutzen.
- Diese Version ist ein **MVP**. Bitte vor produktivem Einsatz testen und das Firewall-Verhalten im Kundenumfeld verifizieren (insbesondere falls UFW oder nftables aktiv sind).

---

## Lizenz

MIT
