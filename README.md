# Enhanced Local Security Monitor

A cross-platform GUI-based security monitoring tool for Windows, Linux, and macOS, built with Python.  
It provides real-time monitoring and alerting for file integrity, network threats, suspicious processes, log events, and system/network anomalies.  
The tool features a multi-tab Tkinter interface with dashboards, customizable rules, and exportable alerts.

---

## Features

- **File Integrity Monitoring:**  
  Hash-based change detection for critical files (e.g., `/etc/hosts`, Windows hosts file, etc).

- **Log Event Analysis:**  
  Monitors and scans log files for suspicious or customizable keywords.

- **Network Threat Detection:**  
  - Live packet sniffing (requires [Scapy](https://scapy.net/)), supporting BPF filters (e.g. 'tcp', 'udp port 53', etc).
  - Checks network packets/flows against updatable IP and domain threat feeds.
  - Signature-based detection: customizable regex/text rules for network payloads.

- **Process & System Monitoring:**  
  - Detects suspicious process names, command-lines, and execution from unusual directories.
  - Alerts on processes connecting to known threat IPs.
  - Detects new or unexpected listening ports.

- **Firewall Checks:**  
  Verifies state of Windows Firewall, Linux iptables/UFW, or macOS pfctl.

- **Visualization Dashboard:**  
  Real-time graphs for network connection counts and threat activity.

- **Alerting:**  
  Alerts are categorized by severity, source, type, and can be filtered/exported (CSV).

- **Feeds Management:**  
  Supports both IP and domain threat intelligence feeds (configurable URLs & intervals).

- **Persistence:**  
  Configuration and monitoring state are persisted across restarts.

- **Extensible:**  
  Add your own log keywords, file paths, threat feeds, and signature rules via the GUI.

---

## Requirements

- Python 3.8+
- [Scapy](https://pypi.org/project/scapy/)
- [psutil](https://pypi.org/project/psutil/)
- [matplotlib](https://pypi.org/project/matplotlib/)
- [requests](https://pypi.org/project/requests/)

**Windows only:**  
- [Npcap](https://nmap.org/npcap/) or WinPcap for packet capture

---

### Installation

```bash
pip install scapy psutil matplotlib requests
# For full GUI experience (and packet capture on Windows), install Npcap from https://nmap.org/npcap/
```

---

## Usage

1. **Run the script:**
   ```bash
   python eLSM.py
   ```

2. **Configure Monitoring:**  
   - Use the Configuration tab to set files, logs, network interface, thresholds, and threat feed URLs.

3. **Customize Detection:**  
   - Use the Signatures tab to add/edit/delete custom detection rules (text or regex).

4. **Start Monitoring:**  
   - Click "Start Monitoring".  
   - Review alerts (with severity and source) in the Alerts Dashboard tab.
   - View real-time graphs in the Dashboard tab.

5. **Export Alerts:**  
   - Use the "Export Alerts (CSV)" button to save alerts for later analysis.

---

## How It Works

- **Multi-Threaded & Responsive:**  
  Background threads handle sniffing and system checks; GUI remains responsive.
- **Thread-Safe Logging/Alerts:**  
  Internal queue system ensures safe updates from background threads to the GUI.
- **Persistence:**  
  Config and state (hashes, positions, ports, etc.) are saved to JSON files.
- **Extensible:**  
  Add new detection logic or integrations by extending the class methods.

---

## Customization

- **Signatures:**  
  Each rule includes a pattern, category, severity, and regex flag.  
  Store signatures as JSON lines, e.g.:
  ```json
  {"pattern": "malicious.exe", "category": "Network", "severity": "High", "is_regex": false}
  {"pattern": "(PowerShell.+-enc)", "category": "System", "severity": "Critical", "is_regex": true}
  ```

- **Threat Feeds:**  
  Supports public or private IP/domain blocklists (format: plain IP per line or hosts file).

- **Log Keywords:**  
  Add patterns like "failed login", "denied" in the config.

---

## Limitations

- **Privileges Required:**  
  Root/Admin required for network sniffing, process inspection, and firewall checks.
- **Platform Support:**  
  Some features (like sound alerts or firewall checks) are platform-specific.
- **Performance:**  
  Heavy scanning/monitoring on large systems may impact responsiveness.
- **Not a Complete IDS/IPS:**  
  This is a lightweight monitoring/alerting tool, not a replacement for enterprise security solutions.

---

## Troubleshooting

- **Scapy ImportError:**  
  Install with `pip install scapy`
- **Permission Denied (Sniffing):**  
  Run as Administrator (Windows) or with `sudo` (Linux/macOS).
- **Firewall Check Fails:**  
  Some systems may require extra configuration or privileges.

---

## Disclaimer

This tool is intended for educational and monitoring purposes.  
It is **not** a replacement for dedicated security products or professional incident response.

---
