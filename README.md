# ioBroker.nexowattvpn

**Ziel:** Ein ioBroker-Adapter als lokale UI/Steuerung für **PiVPN** (WireGuard oder OpenVPN), inkl. Profilverwaltung (Service/Kunde), Export der Client-Konfiguration und optionaler Firewall-Härtung (VPN → nur Raspberry Pi).

> Hinweis: Du hast PiVPN bereits per  
> `curl -L https://install.pivpn.io | bash`  
> installiert. Dieser Adapter übernimmt **nicht** den PiVPN-Installer, sondern arbeitet **auf einem fertig installierten PiVPN**.

---

## Funktionsumfang

- ✅ **PiVPN-Protokoll automatisch erkennen** (WireGuard / OpenVPN)
- ✅ **Clients/Profiles anlegen** (Typ: `service` oder `customer`)
- ✅ **Clients exportieren**:
  - WireGuard: `.conf` Download + QR-Code
  - OpenVPN: `.ovpn` Download
- ✅ WireGuard: **Enable/Disable** von Clients
- ✅ **Host-only Hardening** (optional):
  - **VPN ➜ LAN Forwarding blockieren** (Clients können nur den RPi erreichen)
  - Optional: **Port-Allowlist** für INPUT vom VPN-Interface

---

## Wichtige Randbedingungen (dein Requirement)

- Der Zugriff soll **nur auf dem RPi selbst** stattfinden:
  - Das wird **am zuverlässigsten** erreicht durch **Blockieren von Forwarding** von `wg0`/`tun0` in das LAN (**iptables FORWARD DROP**).
- Zusätzlich soll mindestens erreichbar sein:
  - **alle ioBroker Ports** (auto-detect + bekannte Defaults)
  - **8086** (InfluxDB)
  - **8188** (Nexowattfis)

Der Adapter bietet dafür eine **Firewall-Helper-Funktion** (Tab „Firewall“).

---

## Rechte / sudo (wichtig)

PiVPN-Operationen (Clients anlegen/revoken/enable/disable) erfordern root.  
Der Adapter ist so gebaut, dass er per `sudo -n` arbeitet (ohne Passwortabfrage).

### Option A: iobroker in die PiVPN-Usergruppe aufnehmen (oft ausreichend fürs Lesen)

Wenn PiVPN unter Benutzer `pi` installiert wurde:

```bash
sudo usermod -a -G pi iobroker
# Danach einmal ab- und anmelden / reboot
sudo reboot
```

Damit kann der Adapter ggf. Client-Dateien lesen, aber **PiVPN-Kommandos** brauchen weiterhin root.

### Option B (empfohlen): Minimaler sudoers Eintrag

Erzeuge eine Datei:

```bash
sudo nano /etc/sudoers.d/iobroker-nexowattvpn
```

Inhalt (anpassen, falls Pfade abweichen):

```sudoers
# ioBroker NexowattVPN: erlaubte Kommandos ohne Passwort
iobroker ALL=(root) NOPASSWD: /usr/local/bin/pivpn
iobroker ALL=(root) NOPASSWD: /bin/cat /etc/pivpn/setupVars.conf
iobroker ALL=(root) NOPASSWD: /bin/cat /etc/pivpn/wireguard/setupVars.conf
iobroker ALL=(root) NOPASSWD: /bin/cat /etc/pivpn/openvpn/setupVars.conf
iobroker ALL=(root) NOPASSWD: /bin/cat /etc/wireguard/wg0.conf
iobroker ALL=(root) NOPASSWD: /bin/cat /etc/wireguard/configs/clients.txt
iobroker ALL=(root) NOPASSWD: /bin/cat /etc/openvpn/easy-rsa/pki/index.txt
iobroker ALL=(root) NOPASSWD: /bin/bash
iobroker ALL=(root) NOPASSWD: /usr/bin/systemctl
iobroker ALL=(root) NOPASSWD: /usr/bin/wg
iobroker ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/iptables-save, /usr/sbin/ip6tables-save
```

Dann:

```bash
sudo chmod 0440 /etc/sudoers.d/iobroker-nexowattvpn
sudo visudo -c
```

**Wichtig:** Das ist eine pragmatische Lösung für deine Zielsetzung. Wenn du die Rechte noch enger schneiden willst, kann man das später verfeinern.

---

## Installation des Adapters (lokal als Repo)

1) Repo in z. B. `/opt/iobroker/custom-adapters/iobroker.nexowattvpn` ablegen (oder beliebig).

2) Abhängigkeiten installieren:

```bash
cd /opt/iobroker/custom-adapters/iobroker.nexowattvpn
npm install
```

3) Adapter in ioBroker hinzufügen (lokaler Pfad):

```bash
cd /opt/iobroker
iobroker add /opt/iobroker/custom-adapters/iobroker.nexowattvpn
```

4) In Admin: Instanz starten, Konfiguration öffnen.

---

## Nutzung

### Tab „Clients“
- **Create profile**:
  - Name, Type (service/customer), Scope wählen
  - WireGuard: QR-Code möglich
- **Existing profiles**:
  - Download, QR (WireGuard), Enable/Disable (WireGuard), Remove

### Tab „Firewall“
- **Detect ioBroker ports**: Ermittelt Ports aus den Instance-Configs (best-effort) + Default-Ports + extra Ports aus Settings.
- **Apply firewall**:
  - `Block forwarding (VPN ➜ LAN)` = host-only
  - `Restrict INPUT ports` = echte Port-Allowlist (optional)

---

## Troubleshooting

### 1) Prüfen ob sudo ohne Passwort funktioniert
```bash
sudo -u iobroker sudo -n /usr/local/bin/pivpn help
echo $?
```
Wenn der Exit-Code **0** ist: ok.  
Wenn nicht: sudoers prüfen.

### 2) PiVPN-Protokoll erkennen
```bash
sudo -u iobroker sudo -n /bin/cat /etc/pivpn/setupVars.conf | grep -E '^VPN='
```

### 3) WireGuard Service
```bash
sudo systemctl status wg-quick@wg0
sudo wg show
```

---

## Stand / Disclaimer

Das Repo ist ein **funktionaler Startpunkt** (Development-Version 0.0.1).  
Ich habe die Umsetzung so gebaut, dass sie **nicht interaktiv** ist (keine Prompts), und mit minimalen sudo-Rechten betrieben werden kann.

Wenn du mir sagst:
- ob du **WireGuard** oder **OpenVPN** nutzt,
- welches Subnetz/LAN du ggf. für „Service“ routen willst,
- welche ioBroker Ports bei dir relevant sind (Admin/Web/Simple-API/Node-RED/MQTT/etc.),

kann ich die Defaults gezielter auf eure Nexowatt-Standard-Installation anpassen.
