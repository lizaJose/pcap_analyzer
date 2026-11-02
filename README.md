# PCAP Analyzer

Explains in plain language what happens inside a `.pcap`/`.pcapng`: websites visited (HTTP and HTTPS via SNI),
DNS, SSH, FTP, Telnet, SMB, RDP, ICMP, ARP and DHCP.

## Requirements
- Python 3.9+
- Wireshark (includes `tshark`)
- `pip install -r requirements.txt`

## Usage
```
python pcap_analyzer.py                       # interactive menu (load pcap, summary, search, stats, export, web)
python pcap_analyzer.py capture.pcap          # menu with the pcap already loaded
python pcap_analyzer.py --web                 # straight to the web UI (upload button) at http://127.0.0.1:8000
python pcap_analyzer.py capture.pcap --text   # print report and exit (--category Web to filter)
python pcap_analyzer.py capture.pcap --json   # JSON output
```
Options: `--port`, `--host`, `--tshark "C:\path\tshark.exe"`.

Notes: HTTPS traffic only reveals the domain (SNI), not the content. FTP passwords are not included in the report.

## Web interface
Sidebar sections: **Overview**, **Websites** are grouped by site (e.g. `scontent.cdninstagram.com` and `www.instagram.com` become one "Instagram" row; click it to see the hosts it used),
with service name, HTTPS/HTTP badge, who visited, sort/filter. A site is a **Main site** when it has its own front page (apex or `www.`)
and is not ads/CDN; everything else goes to **Background**. Tune it with `ALIASES`, `SHARED_HOSTING`, `ADS_DOMAINS`, `INFRA_DOMAINS`
and `BG_TOKENS` at the top of `pcapanalyzer/index.html`; restart the server after editing.
**Remote access** (SSH/Telnet/RDP/VNC), **Files** (FTP/SMB), **DNS**, **Network** (ICMP/ARP/DHCP) and **All activity**.
Upload a pcap with the button or by dragging it onto the page.

## ARP spoofing / MITM (authorized testing only)
**Only use this against networks and devices you are explicitly authorized to test** (your own lab, or an
engagement covered by a signed scope/agreement). ARP spoofing disrupts normal network operation, and
intercepting traffic you are not authorized to see is illegal in most places.

Available both from the console menu (option **9**) and from the web UI's **ARP spoofing** sidebar section
(same engine, same options, driven from the browser instead of the terminal):
- Requires Npcap (installed with Wireshark) and the tool running as **Administrator** (Windows) / **root** (Linux) -
  raw ARP packets and IP-forwarding changes need elevated privileges. The menu/web UI will tell you clearly if you
  are not elevated.
- Pick a **network interface**; the gateway IP is auto-detected but can be overridden.
- **Scan the network** to list every host found (IP + MAC) and tick the one(s) you want to target, instead of
  typing IP addresses blindly - useful when you only want a single client. A manual IP field is also available.
  Each host is auto-identified, best-effort:
  - **Vendor** from the MAC's OUI (offline lookup against a curated copy of the IEEE registry,
    `pcapanalyzer/oui_vendors.json`) - e.g. router/ISP-gateway chipsets, Apple, Samsung, Nintendo, Raspberry Pi, etc.
    A MAC with the "locally administered" bit set is flagged as a **private/randomized address**, which is how
    modern phones/tablets hide their real vendor on Wi-Fi (iOS 14+/Android 10+ privacy feature) - seeing that
    badge is itself a strong hint that the device is a phone or tablet.
  - **Hostname**, via reverse DNS and/or a NetBIOS name query (same info Windows file/printer sharing uses) -
    often reveals a self-chosen device name (e.g. `Johns-iPhone`, `DESKTOP-ABC123`).
  - A rough **OS guess** from the TTL of a single ping reply (same trick used by `nmap`/`p0f`): Linux/Android/iOS/macOS
    vs. Windows vs. networking gear.
  None of this sends more than a handful of ordinary, read-only LAN packets per host (ARP, DNS, NetBIOS, one ICMP
  echo) - it does not spoof or disrupt anything by itself.
- Choose **two-way** poisoning (also spoofs the gateway, full MITM) or one-way.
- **IP forwarding** can be enabled/restored automatically so the victim keeps internet access while spoofed.
  On Windows this is set via the registry (`IPEnableRouter`) and commonly needs a reboot or NIC restart to fully
  take effect - the tool shows this note on screen.
- Optionally **capture the intercepted traffic** live to a `.pcap` file while the attack runs, so it can be
  loaded back into this same analyzer afterwards. The web UI suggests a timestamped filename that you can edit;
  the console menu also prompts for a filename. The web UI rejects existing filenames rather than overwriting them.
- Stopping (Ctrl+C in the console, or the "Stop & restore" button on the web UI) always **restores the real
  ARP mappings** on the affected hosts and reverts IP forwarding to what it was before.
