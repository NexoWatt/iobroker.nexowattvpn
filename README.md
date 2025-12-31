# NexoWattVPN (ioBroker Adapter)

**Adapter‑Name:** `nexowattvpn`  
**Repository/Package:** `iobroker.nexowattvpn`

NexoWattVPN richtet auf dem ioBroker‑Host eine **WireGuard‑VPN** ein und erzwingt eine **strikte Firewall‑Politik am WireGuard‑Interface**:

- ✅ **Erlaubt über VPN:** **TCP** zum ioBroker‑Host auf ausgewählten Ports (Standard: **8081, 8082**)
- ❌ **Blockiert über VPN:** alles andere am WG‑Interface
- ❌ **Blockiert:** Forwarding vom WG‑Interface ins LAN (kein „Pivoting“ ins Kunden‑Netz)

Ziel: **VPN‑Clients können nur die freigegebenen ioBroker‑Dienste erreichen – nicht das gesamte Netzwerk.**

---

## Wichtiger Hinweis (Internet ohne Router‑Änderung)

Ein „klassischer“ WireGuard‑Server im Heimnetz benötigt für eingehende Verbindungen in der Regel:

- eine **UDP‑Portweiterleitung** am Router (z. B. 51820 → ioBroker‑Host), oder
- eine **direkte öffentliche Erreichbarkeit** (öffentliche IPv4 / IPv6), oder
- eine Router‑Funktion wie **UPnP/NAT‑PMP/PCP** (wenn aktiviert), oder
- einen **externen Hub/VPS (Reverse‑VPN)**, bei dem der Kunden‑Host **ausgehend** verbindet.

WireGuard selbst „umgeht“ NAT nicht zuverlässig. Wenn du *gar nichts* am Router konfigurieren willst, ist ein **Hub/VPS‑Design** die robuste Lösung.

---

## Voraussetzungen

- Linux Host (Debian/Ubuntu/Raspberry Pi OS empfohlen)
- Pakete: `wireguard-tools` und `nftables`

Du kannst die Voraussetzungen entweder

- über den Tab **Installieren** im Adapter (empfohlen), oder
- manuell installieren:

```bash
sudo apt update
sudo apt install -y wireguard-tools nftables
```

---

## Sicherheitsmodell / Rechte

Der Adapter läuft als normaler Benutzer **iobroker** und führt Root‑Aktionen über einen **minimalen Root‑Helper** aus:

- `lib/root-helper.js` (wird per `sudo` ausgeführt)
- schreibt/ändert `/etc/wireguard/<iface>.conf`
- startet/stoppt `wg-quick up|down <iface>`
- setzt Firewall‑Regeln über **nftables**

Damit `sudo` ohne Passwort funktioniert, wird einmalig eine minimale Regel unter `/etc/sudoers.d/nexowattvpn` erstellt.

---

## Einrichtung (empfohlen)

1. **Installieren → Bootstrap‑Befehl** kopieren
2. Den Bootstrap‑Befehl **einmal per SSH/Putty als root** ausführen
3. Zurück in ioBroker:
   - **Server → Server‑Konfiguration erstellen/aktualisieren**
   - **Server → Firewall‑Regeln anwenden**
   - **Server → VPN starten**
4. **Profile** erstellen und die Client‑Config per QR in die WireGuard‑App importieren.

---

## Support‑Zugang (optional, OPT‑IN)

Im Tab **Support (optional)** kann der Kunde einen dedizierten Support‑Peer aktivieren. Dieser kann jederzeit deaktiviert werden; optional mit Ablaufzeit.

---

## Entwicklung

- Node.js ≥ 16
- Adapter‑Logik: `main.js`
- Root‑Helper: `lib/root-helper.js`
- Admin UI: `admin/jsonConfig.json5`
