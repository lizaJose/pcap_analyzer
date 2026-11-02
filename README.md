# PCAP Analyzer

Explains in plain language what happens inside a `.pcap`/`.pcapng`: websites visited (HTTP and HTTPS via SNI),
DNS, SSH, FTP, Telnet, SMB, RDP, ICMP, ARP and DHCP.

## Requirements
- Python 3.9+
- Wireshark (including `tshark`), available on `PATH`
- `pip install -r requirements.txt`

### Windows
Install Wireshark and make sure `tshark.exe` is on `PATH`. The analyzer also checks the standard Wireshark
install folders; if needed, pass its location with `--tshark`.

### Linux
Install Wireshark/TShark using your distribution's package manager and ensure `tshark` is on `PATH`.
For example, on Debian/Ubuntu: `sudo apt install wireshark`.

Then install the Python dependencies with `python -m pip install -r requirements.txt` (use `python3` if that's
the command for your Python installation).

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
Browse traffic by category, including websites, remote access, file transfers, DNS, and network activity. Upload a capture
with the button or by dragging it onto the page.

## ARP spoofing / MITM (authorized testing only)
Only use this feature on networks and devices you are authorized to test. ARP spoofing can disrupt network
operation and expose traffic.

Available from console menu option **9** and the web UI's **ARP spoofing** section. On Windows it requires Npcap
and Administrator privileges; on Linux it requires libpcap and root privileges. Select an interface and authorized
target(s); the tool can scan the local subnet, optionally enable IP forwarding, and capture traffic to a `.pcap` file.
The suggested capture filename is editable;
existing filenames are not overwritten. Stop the session to restore ARP mappings and the previous forwarding setting.
