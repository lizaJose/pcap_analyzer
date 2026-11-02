"""Pcap analyzer: turns packets into human-readable events."""
import asyncio
import os
import shutil
from dataclasses import dataclass, field, asdict

import pyshark

from .knowledge import (DHCP_TYPES, ICMP_TYPES, PORT_SERVICES, service_for_domain)

# tshark display filter: only what carries "human" information (much faster analysis)
DISPLAY_FILTER = (
    "dns || http || tls.handshake.type == 1 || ssh || ftp || telnet || smb || smb2 "
    "|| rdp || icmp || icmpv6 || arp || bootp || (tcp.flags.syn == 1 && tcp.flags.ack == 0)"
)


@dataclass
class Event:
    ts: float
    src: str
    dst: str
    category: str   # Web, DNS, Remote access, Files, Network, Connection
    protocol: str
    summary: str
    details: dict = field(default_factory=dict)


def find_tshark():
    path = shutil.which("tshark")
    if path:
        return path
    for program_files in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if program_files:
            candidate = os.path.join(program_files, "Wireshark", "tshark.exe")
            if os.path.isfile(candidate):
                return candidate
    return None


def _values(layer, name):
    """Return all values of a field (it may repeat, e.g. DNS answers)."""
    try:
        f = layer.get_field(name)
    except Exception:
        return []
    if f is None:
        return []
    all_fields = getattr(f, "all_fields", None)
    if all_fields:
        return [str(x.show) for x in all_fields]
    return [str(f)]


def _first(layer, *names):
    for n in names:
        v = _values(layer, n)
        if v:
            return v[0]
    return None


def _has(pkt, name):
    try:
        return name in pkt
    except Exception:
        return False


class Analyzer:
    def __init__(self, pcap_path, tshark_path=None):
        self.pcap_path = pcap_path
        self.tshark_path = tshark_path or find_tshark()
        if not self.tshark_path:
            raise RuntimeError("tshark not found. Install Wireshark and add it to PATH (or use --tshark).")
        self.events = []
        self.ip_names = {}       # IP -> domain name seen in DNS/SNI/HTTP
        self.packet_count = 0

    # ------------------------------------------------------------------ API
    def analyze(self):
        # pyshark uses asyncio; web server threads have no event loop of their own
        asyncio.set_event_loop(asyncio.new_event_loop())
        cap = pyshark.FileCapture(
            self.pcap_path, display_filter=DISPLAY_FILTER,
            tshark_path=self.tshark_path, keep_packets=False,
        )
        try:
            for pkt in cap:
                self.packet_count += 1
                try:
                    self._handle(pkt)
                except Exception:
                    continue  # one odd packet must not abort the whole analysis
        finally:
            cap.close()
        self._enrich_connections()
        self.events.sort(key=lambda e: e.ts)
        return self.result()

    def result(self):
        return {
            "file": os.path.basename(self.pcap_path),
            "packets_analyzed": self.packet_count,
            "events": [asdict(e) for e in self.events],
            "hosts": self._host_summary(),
        }

    # ------------------------------------------------------------- handlers
    def _add(self, pkt, src, dst, category, protocol, summary, **details):
        self.events.append(Event(float(pkt.sniff_timestamp), src, dst, category,
                                 protocol, summary, {k: v for k, v in details.items() if v}))

    def _handle(self, pkt):
        src, dst = self._addrs(pkt)
        if _has(pkt, "arp"):
            return self._arp(pkt)
        if _has(pkt, "bootp"):
            return self._dhcp(pkt, src, dst)
        if _has(pkt, "dns"):
            return self._dns(pkt, src, dst)
        if _has(pkt, "http"):
            return self._http(pkt, src, dst)
        if _has(pkt, "tls") or _has(pkt, "ssl"):
            return self._tls(pkt, src, dst)
        if _has(pkt, "ssh"):
            return self._ssh(pkt, src, dst)
        if _has(pkt, "ftp"):
            return self._ftp(pkt, src, dst)
        if _has(pkt, "telnet"):
            return self._telnet(pkt, src, dst)
        if _has(pkt, "smb2") or _has(pkt, "smb"):
            return self._smb(pkt, src, dst)
        if _has(pkt, "rdp"):
            return self._add(pkt, src, dst, "Remote access", "RDP",
                             f"{src} uses Remote Desktop (RDP) to {dst}")
        if _has(pkt, "icmp") or _has(pkt, "icmpv6"):
            return self._icmp(pkt, src, dst)
        if _has(pkt, "tcp"):
            return self._syn(pkt, src, dst)

    @staticmethod
    def _addrs(pkt):
        for name in ("ip", "ipv6"):
            if _has(pkt, name):
                return pkt[name].src, pkt[name].dst
        if _has(pkt, "eth"):
            return pkt.eth.src, pkt.eth.dst
        return "?", "?"

    def _dns(self, pkt, src, dst):
        d = pkt.dns
        name = _first(d, "qry_name")
        if not name:
            return
        if _first(d, "flags_response") in ("1", "True", "true"):
            answers = [a for a in _values(d, "a") + _values(d, "aaaa")]
            for ip in answers:
                self.ip_names[ip] = name
            if answers:
                self._add(pkt, dst, src, "DNS", "DNS",
                          f"DNS server {src} tells {dst}: {name} is at {', '.join(answers[:3])}",
                          domain=name, answers=", ".join(answers))
            else:
                self._add(pkt, dst, src, "DNS", "DNS",
                          f"DNS server {src} has no answer for {name}", domain=name)
        else:
            svc = service_for_domain(name)
            extra = f" ({svc})" if svc else ""
            self._add(pkt, src, dst, "DNS", "DNS",
                      f"{src} asks for the address of {name}{extra}", domain=name, service=svc)

    def _http(self, pkt, src, dst):
        h = pkt.http
        method = _first(h, "request_method")
        if method:
            host = _first(h, "host") or dst
            uri = _first(h, "request_uri") or "/"
            self.ip_names.setdefault(dst, host)
            svc = service_for_domain(host)
            extra = f" ({svc})" if svc else ""
            self._add(pkt, src, dst, "Web", "HTTP",
                      f"{src} visits http://{host}{uri}{extra} (unencrypted) using {method}",
                      host=host, url=f"http://{host}{uri}", method=method, service=svc,
                      user_agent=_first(h, "user_agent"))
            return
        code = _first(h, "response_code")
        if code:
            phrase = _first(h, "response_code_desc") or ""
            ctype = _first(h, "content_type")
            self._add(pkt, src, dst, "Web", "HTTP",
                      f"Web server {src} answers {dst} with {code} {phrase}".strip()
                      + (f" ({ctype})" if ctype else ""), code=code, content_type=ctype)

    def _tls(self, pkt, src, dst):
        layer = pkt.tls if _has(pkt, "tls") else pkt.ssl
        sni = _first(layer, "handshake_extensions_server_name")
        if not sni:
            return
        self.ip_names.setdefault(dst, sni)
        svc = service_for_domain(sni)
        extra = f" ({svc})" if svc else ""
        self._add(pkt, src, dst, "Web", "HTTPS",
                  f"{src} browses {sni} over HTTPS{extra}", host=sni, service=svc,
                  version=_first(layer, "handshake_version"))

    def _ssh(self, pkt, src, dst):
        banner = _first(pkt.ssh, "protocol")
        if banner:
            self._add(pkt, src, dst, "Remote access", "SSH",
                      f"{src} starts an SSH session with {dst} (software: {banner})", software=banner)

    def _ftp(self, pkt, src, dst):
        f = pkt.ftp
        cmd, arg = _first(f, "request_command"), _first(f, "request_arg")
        if cmd:
            cmd = cmd.upper()
            texts = {
                "USER": f"{src} logs in to FTP server {dst} as user \"{arg}\"",
                "PASS": f"{src} sends a password over FTP to {dst} (sent in cleartext!)",
                "RETR": f"{src} downloads file \"{arg}\" from {dst} over FTP",
                "STOR": f"{src} uploads file \"{arg}\" to {dst} over FTP",
                "LIST": f"{src} lists a directory on {dst} over FTP",
                "CWD": f"{src} changes to directory \"{arg}\" on {dst} over FTP",
                "DELE": f"{src} deletes \"{arg}\" on {dst} over FTP",
            }
            text = texts.get(cmd, f"{src} sends FTP command {cmd} {arg or ''} to {dst}".strip())
            if cmd == "PASS":
                arg = None  # never dump credentials into the report
            self._add(pkt, src, dst, "Files", "FTP", text, command=cmd, argument=arg)
        else:
            code = _first(f, "response_code")
            if code in ("230", "530"):
                ok = "accepts" if code == "230" else "rejects"
                self._add(pkt, src, dst, "Files", "FTP",
                          f"FTP server {src} {ok} the login of {dst}", code=code)

    def _telnet(self, pkt, src, dst):
        self._add(pkt, src, dst, "Remote access", "Telnet",
                  f"{src} uses Telnet with {dst} (unencrypted remote session)")

    def _smb(self, pkt, src, dst):
        layer = pkt.smb2 if _has(pkt, "smb2") else pkt.smb
        name = _first(layer, "filename", "file_name", "tree")
        cmd = _first(layer, "cmd", "smb_cmd")
        if _has(pkt, "smb2") and not name and cmd not in ("3", "5"):
            return
        what = f" \"{name}\"" if name else ""
        self._add(pkt, src, dst, "Files", "SMB",
                  f"{src} accesses Windows shared resources (SMB){what} on {dst}", resource=name)

    def _icmp(self, pkt, src, dst):
        layer = pkt.icmp if _has(pkt, "icmp") else pkt.icmpv6
        t = _first(layer, "type")
        try:
            desc = ICMP_TYPES.get(int(t), f"type {t}")
        except (TypeError, ValueError):
            desc = "ICMP message"
        self._add(pkt, src, dst, "Network", "ICMP", f"{src} -> {dst}: {desc}")

    def _arp(self, pkt):
        a = pkt.arp
        op = _first(a, "opcode")
        sip, dip = _first(a, "src_proto_ipv4"), _first(a, "dst_proto_ipv4")
        smac = _first(a, "src_hw_mac")
        if op == "1":
            text = f"{sip} asks who has IP {dip} (ARP)"
        else:
            text = f"{sip} replies that its hardware address is {smac} (ARP)"
        self._add(pkt, sip or "?", dip or "?", "Network", "ARP", text)

    def _dhcp(self, pkt, src, dst):
        b = pkt.bootp
        t = _first(b, "option_dhcp")
        try:
            desc = DHCP_TYPES.get(int(t), f"type {t}")
        except (TypeError, ValueError):
            return
        host = _first(b, "option_hostname")
        who = f" ({host})" if host else ""
        ip = _first(b, "option_requested_ip_address", "ip_your")
        self._add(pkt, src, dst, "Network", "DHCP",
                  f"DHCP{who}: {desc}" + (f" - IP {ip}" if ip and ip != "0.0.0.0" else ""),
                  hostname=host, ip=ip)

    def _syn(self, pkt, src, dst):
        sport, dport = int(pkt.tcp.srcport), int(pkt.tcp.dstport)
        service = PORT_SERVICES.get(dport)
        if not service:
            return
        self._add(pkt, src, dst, "Connection", "TCP",
                  f"{src} opens a {service} connection (port {dport}) to {dst}",
                  service=service, port=dport, source_port=sport)

    # --------------------------------------------------------------- summary
    def _enrich_connections(self):
        """Append the known domain name to the destination of TCP connections."""
        for e in self.events:
            if e.category == "Connection" and e.dst in self.ip_names:
                e.summary += f" - {self.ip_names[e.dst]}"
                e.details["domain"] = self.ip_names[e.dst]

    def _host_summary(self):
        hosts = {}
        for e in self.events:
            h = hosts.setdefault(e.src, {"ip": e.src, "sites": set(), "services": set(),
                                         "remote": set(), "files": set(), "events": 0})
            h["events"] += 1
            site = e.details.get("host") or e.details.get("domain")
            if e.category in ("Web", "DNS") and site:
                h["sites"].add(site)
            if e.details.get("service"):
                h["services"].add(e.details["service"])
            if e.category == "Remote access" or e.details.get("port") in (22, 23, 3389, 5900):
                h["remote"].add(f"{e.protocol} -> {e.dst}")
            if e.category == "Files":
                h["files"].add(f"{e.protocol} -> {e.dst}")
        return [{**h, **{k: sorted(h[k]) for k in ("sites", "services", "remote", "files")}}
                for h in sorted(hosts.values(), key=lambda x: -x["events"])]
