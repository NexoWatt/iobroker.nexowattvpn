/* global systemDictionary */
'use strict';

systemDictionary = {
  "Settings": {
    "en": "Settings",
    "de": "Einstellungen"
  },
  "Clients": {
    "en": "Clients",
    "de": "Clients"
  },
  "Firewall": {
    "en": "Firewall",
    "de": "Firewall"
  },
  "Status": {
    "en": "Status",
    "de": "Status"
  },
  "Adapter settings": {
    "en": "Adapter settings",
    "de": "Adapter-Einstellungen"
  },
  "PiVPN binary path": {
    "en": "PiVPN binary path",
    "de": "PiVPN Binary-Pfad"
  },
  "Default is /usr/local/bin/pivpn": {
    "en": "Default is /usr/local/bin/pivpn",
    "de": "Standard ist /usr/local/bin/pivpn"
  },
  "Protocol": {
    "en": "Protocol",
    "de": "Protokoll"
  },
  "auto": {
    "en": "auto",
    "de": "auto"
  },
  "wireguard": {
    "en": "wireguard",
    "de": "wireguard"
  },
  "openvpn": {
    "en": "openvpn",
    "de": "openvpn"
  },
  "Use sudo (recommended)": {
    "en": "Use sudo (recommended)",
    "de": "sudo verwenden (empfohlen)"
  },
  "Defaults for new profiles": {
    "en": "Defaults for new profiles",
    "de": "Standardwerte für neue Profile"
  },
  "Customer scope": {
    "en": "Customer scope",
    "de": "Kunden-Scope"
  },
  "Service scope": {
    "en": "Service scope",
    "de": "Service-Scope"
  },
  "hostOnly (recommended)": {
    "en": "hostOnly (recommended)",
    "de": "hostOnly (empfohlen)"
  },
  "lan": {
    "en": "lan",
    "de": "LAN"
  },
  "fullTunnel": {
    "en": "fullTunnel",
    "de": "Full-Tunnel"
  },
  "Firewall options": {
    "en": "Firewall options",
    "de": "Firewall-Optionen"
  },
  "Host-only access means: VPN clients should only reach the Raspberry Pi itself, not other LAN devices.": {
    "en": "Host-only access means: VPN clients should only reach the Raspberry Pi itself, not other LAN devices.",
    "de": "Host-only Zugriff bedeutet: VPN-Clients sollen nur den Raspberry Pi selbst erreichen, nicht andere LAN-Geräte."
  },
  "Block forwarding (VPN ➜ LAN)": {
    "en": "Block forwarding (VPN ➜ LAN)",
    "de": "Forwarding blockieren (VPN ➜ LAN)"
  },
  "Restrict ports from VPN interface (allowlist)": {
    "en": "Restrict ports from VPN interface (allowlist)",
    "de": "Ports vom VPN-Interface einschränken (Allowlist)"
  },
  "Extra allowed TCP ports (CSV)": {
    "en": "Extra allowed TCP ports (CSV)",
    "de": "Zusätzliche erlaubte TCP-Ports (CSV)"
  },
  "Example: 8086,8188": {
    "en": "Example: 8086,8188",
    "de": "Beispiel: 8086,8188"
  },
  "Extra allowed UDP ports (CSV)": {
    "en": "Extra allowed UDP ports (CSV)",
    "de": "Zusätzliche erlaubte UDP-Ports (CSV)"
  },
  "Optional": {
    "en": "Optional",
    "de": "Optional"
  },
  "After changing settings, click SAVE at the top to apply. Some functions require a restart.": {
    "en": "After changing settings, click SAVE at the top to apply. Some functions require a restart.",
    "de": "Nach Änderungen oben auf SPEICHERN klicken. Einige Funktionen erfordern einen Neustart."
  },
  "Important notes": {
    "en": "Important notes",
    "de": "Wichtige Hinweise"
  },
  "PiVPN must already be installed (curl -L https://install.pivpn.io | bash).": {
    "en": "PiVPN must already be installed (curl -L https://install.pivpn.io | bash).",
    "de": "PiVPN muss bereits installiert sein (curl -L https://install.pivpn.io | bash)."
  },
  "For non-root operation the ioBroker user needs sudo permissions for specific commands (see README.md).": {
    "en": "For non-root operation the ioBroker user needs sudo permissions for specific commands (see README.md).",
    "de": "Für Betrieb ohne root benötigt der ioBroker-User sudo-Rechte für bestimmte Kommandos (siehe README.md)."
  },
  "WireGuard client names are limited to 15 characters (PiVPN).": {
    "en": "WireGuard client names are limited to 15 characters (PiVPN).",
    "de": "WireGuard-Clientnamen sind auf 15 Zeichen begrenzt (PiVPN)."
  },
  "Server info": {
    "en": "Server info",
    "de": "Server-Info"
  },
  "Create profile": {
    "en": "Create profile",
    "de": "Profil anlegen"
  },
  "Client name": {
    "en": "Client name",
    "de": "Client-Name"
  },
  "Allowed: a-z A-Z 0-9 . @ _ -": {
    "en": "Allowed: a-z A-Z 0-9 . @ _ -",
    "de": "Erlaubt: a-z A-Z 0-9 . @ _ -"
  },
  "Profile type": {
    "en": "Profile type",
    "de": "Profiltyp"
  },
  "service": {
    "en": "service",
    "de": "Service"
  },
  "customer": {
    "en": "customer",
    "de": "Kunde"
  },
  "Scope (AllowedIPs)": {
    "en": "Scope (AllowedIPs)",
    "de": "Scope (AllowedIPs)"
  },
  "LAN CIDR (optional)": {
    "en": "LAN CIDR (optional)",
    "de": "LAN CIDR (optional)"
  },
  "Only used when scope=lan and auto-detection fails.": {
    "en": "Only used when scope=lan and auto-detection fails.",
    "de": "Nur verwendet, wenn scope=lan und die Auto-Erkennung fehlschlägt."
  },
  "OpenVPN password (optional)": {
    "en": "OpenVPN password (optional)",
    "de": "OpenVPN Passwort (optional)"
  },
  "Only for OpenVPN. Leave empty to create nopass profile.": {
    "en": "Only for OpenVPN. Leave empty to create nopass profile.",
    "de": "Nur für OpenVPN. Leer lassen für ein nopass-Profil."
  },
  "Create": {
    "en": "Create",
    "de": "Anlegen"
  },
  "Existing profiles": {
    "en": "Existing profiles",
    "de": "Vorhandene Profile"
  },
  "Refresh": {
    "en": "Refresh",
    "de": "Aktualisieren"
  },
  "Name": {
    "en": "Name",
    "de": "Name"
  },
  "Type": {
    "en": "Type",
    "de": "Typ"
  },
  "Scope": {
    "en": "Scope",
    "de": "Scope"
  },
  "Actions": {
    "en": "Actions",
    "de": "Aktionen"
  },
  "Download": {
    "en": "Download",
    "de": "Download"
  },
  "QR": {
    "en": "QR",
    "de": "QR"
  },
  "Enable": {
    "en": "Enable",
    "de": "Aktivieren"
  },
  "Disable": {
    "en": "Disable",
    "de": "Deaktivieren"
  },
  "Remove": {
    "en": "Remove",
    "de": "Entfernen"
  },
  "enabled": {
    "en": "enabled",
    "de": "aktiv"
  },
  "disabled": {
    "en": "disabled",
    "de": "deaktiviert"
  },
  "Firewall helper": {
    "en": "Firewall helper",
    "de": "Firewall-Helfer"
  },
  "This applies iptables rules for the VPN interface. It can optionally block VPN ➜ LAN forwarding and/or restrict inbound ports from VPN clients.": {
    "en": "This applies iptables rules for the VPN interface. It can optionally block VPN ➜ LAN forwarding and/or restrict inbound ports from VPN clients.",
    "de": "Dies wendet iptables-Regeln für das VPN-Interface an. Optional kann VPN ➜ LAN Forwarding blockiert und/oder eingehende Ports eingeschränkt werden."
  },
  "Detect ioBroker ports": {
    "en": "Detect ioBroker ports",
    "de": "ioBroker-Ports erkennen"
  },
  "Allowed TCP ports (CSV)": {
    "en": "Allowed TCP ports (CSV)",
    "de": "Erlaubte TCP-Ports (CSV)"
  },
  "Allowed UDP ports (CSV)": {
    "en": "Allowed UDP ports (CSV)",
    "de": "Erlaubte UDP-Ports (CSV)"
  },
  "Restrict INPUT ports (allowlist)": {
    "en": "Restrict INPUT ports (allowlist)",
    "de": "INPUT-Ports einschränken (Allowlist)"
  },
  "Apply firewall": {
    "en": "Apply firewall",
    "de": "Firewall anwenden"
  },
  "Warning": {
    "en": "Warning",
    "de": "Warnung"
  },
  "Misconfigured firewall rules can lock you out. Test locally on the Raspberry Pi first.": {
    "en": "Misconfigured firewall rules can lock you out. Test locally on the Raspberry Pi first.",
    "de": "Falsch konfigurierte Firewall-Regeln können dich aussperren. Bitte zuerst lokal am Raspberry Pi testen."
  },
  "Runtime status": {
    "en": "Runtime status",
    "de": "Runtime-Status"
  },
  "Refresh status": {
    "en": "Refresh status",
    "de": "Status aktualisieren"
  },
  "WireGuard QR Code": {
    "en": "WireGuard QR Code",
    "de": "WireGuard QR-Code"
  },
  "Close": {
    "en": "Close",
    "de": "Schließen"
  }
};
