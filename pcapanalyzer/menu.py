"""Interactive console menu (Kali-style tool)."""
import ipaddress
import json
import os
import shutil
import sys
import time
from collections import Counter
from datetime import datetime

from .analyzer import Analyzer
from .webserver import serve
from .wordlist import MAX_CANDIDATES, MAX_COMPONENTS, generate_wordlist

os.system("")  # enable ANSI colors in the Windows console

R, G, Y, B, C, D, X = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[2m", "\033[0m"
CAT_COLORS = {"Web": G, "DNS": Y, "Remote access": R, "Files": B, "Network": C, "Connection": D}
PAGE_SIZE = 25

BANNER = rf"""{C}
  ____   ____    _    ____      _                _
 |  _ \ / ___|  / \  |  _ \    / \   _ __   __ _| |_   _ _______ _ __
 | |_) | |     / _ \ | |_) |  / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
 |  __/| |___ / ___ \|  __/  / ___ \| | | | (_| | | |_| |/ / __/ |
 |_|    \____/_/   \_\_|    /_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                                                   |___/
{X}{D}  What happens inside a pcap, in plain language{X}
"""


def _line(e):
    t = datetime.fromtimestamp(e["ts"]).strftime("%H:%M:%S")
    color = CAT_COLORS.get(e["category"], "")
    return f"{D}{t}{X} {color}[{e['protocol']:<6}]{X} {e['summary']}"


def _pager(lines):
    if not lines:
        print(f"{Y}  No results.{X}")
        return
    for i in range(0, len(lines), PAGE_SIZE):
        print("\n".join(lines[i:i + PAGE_SIZE]))
        if i + PAGE_SIZE < len(lines):
            ans = input(f"{D}-- {min(i + PAGE_SIZE, len(lines))}/{len(lines)} · Enter = more, q = stop -- {X}")
            if ans.strip().lower() == "q":
                break


def _select_wordlist_options(title, options, defaults):
    print(f"\n  {title}:")
    for number, (label, _) in enumerate(options, 1):
        print(f"   {number}) {label}")
    default_text = ",".join(str(number) for number in defaults)
    while True:
        selected = input(f"  Select numbers separated by commas [{default_text}]: ").strip()
        if not selected:
            numbers = defaults
        else:
            values = [value.strip() for value in selected.split(",")]
            if not all(value.isascii() and value.isdigit() for value in values):
                print(f"{R}  Enter valid option numbers separated by commas.{X}")
                continue
            numbers = [int(value) for value in values]
        if not all(1 <= number <= len(options) for number in numbers):
            print(f"{R}  Enter valid option numbers separated by commas.{X}")
            continue
        return [options[number - 1][1] for number in dict.fromkeys(numbers)]


class Menu:
    def __init__(self, tshark=None, host="127.0.0.1", port=8000):
        self.tshark, self.host, self.port = tshark, host, port
        self.result = None
        self.path = None

    # ------------------------------------------------------------- actions
    def load(self, path=None):
        path = path or input("  Path to pcap/pcapng: ")
        path = path.strip().strip('"').strip("'")  # dragging a file into the console adds quotes
        if not path:
            return
        if not os.path.isfile(path):
            print(f"{R}  File not found: {path}{X}")
            return
        print(f"{D}  Analyzing (may take a while for large captures)...{X}")
        try:
            self.result = Analyzer(path, self.tshark).analyze()
            self.path = path
        except Exception as exc:
            print(f"{R}  Error: {exc}{X}")
            return
        print(f"{G}  ✔ {self.result['file']}: {len(self.result['events'])} events, "
              f"{len(self.result['hosts'])} hosts.{X}")

    def _need(self):
        if self.result is None:
            print(f"{Y}  Load a pcap first (option 1).{X}")
            return False
        return True

    def hosts(self):
        if not self._need():
            return
        for h in self.result["hosts"]:
            print(f"\n{C}● {h['ip']}{X} {D}({h['events']} events){X}")
            for label, key in (("Sites", "sites"), ("Services", "services"),
                               ("Remote access", "remote"), ("Files", "files")):
                if h[key]:
                    print(f"    {label}: {', '.join(h[key])}")

    def activity(self, events=None):
        if not self._need():
            return
        _pager([_line(e) for e in (self.result["events"] if events is None else events)])

    def by_category(self):
        if not self._need():
            return
        counts = Counter(e["category"] for e in self.result["events"])
        cats = sorted(counts)
        for i, c in enumerate(cats, 1):
            print(f"   {i}) {CAT_COLORS.get(c, '')}{c}{X} ({counts[c]})")
        sel = input("  Category (number, Enter = cancel): ").strip()
        if sel.isdigit() and 1 <= int(sel) <= len(cats):
            self.activity([e for e in self.result["events"] if e["category"] == cats[int(sel) - 1]])

    def search(self):
        if not self._need():
            return
        q = input("  Search (youtube, ssh, 192.168.1.10...): ").strip().lower()
        if q:
            self.activity([e for e in self.result["events"]
                           if q in (e["summary"] + json.dumps(e["details"], ensure_ascii=False)).lower()])

    def stats(self):
        if not self._need():
            return
        ev = self.result["events"]
        print(f"\n  Events: {len(ev)}   Hosts: {len(self.result['hosts'])}")
        for title, items in (
            ("Protocols", Counter(e["protocol"] for e in ev)),
            ("Most visited sites", Counter(e["details"]["host"] for e in ev if e["details"].get("host"))),
            ("Services", Counter(e["details"]["service"] for e in ev if e["details"].get("service"))),
        ):
            if items:
                print(f"\n  {C}{title}{X}")
                top = items.most_common(10)
                width = max(v for _, v in top)
                for name, n in top:
                    print(f"    {name:<32} {'█' * max(1, round(20 * n / width))} {n}")

    def export(self):
        if not self._need():
            return
        default = os.path.splitext(self.path)[0] + ".json"
        out = input(f"  Save JSON to [{default}]: ").strip().strip('"') or default
        with open(out, "w", encoding="utf-8") as f:
            json.dump(self.result, f, ensure_ascii=False, indent=2)
        print(f"{G}  ✔ Saved to {out}{X}")

    def web(self):
        analyze = lambda p: Analyzer(p, self.tshark).analyze()
        self.result = serve(analyze, self.result, self.host, self.port) or self.result

    def wordlist(self):
        print(f"\n{C}  Wordlist generator{X}")
        print(f"{Y}  Use only for authorized password audits. Profile fields are optional.{X}")
        words = [
            input(f"  {label}: ").strip()
            for label in ("First name", "Surname", "Nickname", "Pet name", "Partner name", "Company or team")
        ]
        year = input("  Birth year (4 digits): ").strip()
        words.extend(input("  Other words (comma-separated): ").split(","))
        cases = _select_wordlist_options("Capitalization", [
            ("As entered", "original"), ("lowercase", "lower"), ("First letter uppercase", "capitalized"),
            ("UPPERCASE", "upper"),
        ], [1, 2, 3])
        separators = _select_wordlist_options("Separators between components", [
            ("None", ""), ("Underscore _", "_"), ("Hyphen -", "-"), ("Dot .", "."),
        ], [1, 2])
        suffixes = _select_wordlist_options("Suffixes", [
            ("None", ""), ("!", "!"), ("123", "123"),
        ], [1])
        while True:
            answer = input("  Also use the last two digits of the birth year? [y/N] ").strip().lower()
            if answer in ("", "n", "no", "y", "yes"):
                short_year = answer in ("y", "yes")
                break
            print(f"{R}  Enter y or n.{X}")
        while True:
            value = input(f"  Maximum components per entry (1-{MAX_COMPONENTS}) [3]: ").strip() or "3"
            if value.isascii() and value.isdigit() and 1 <= int(value) <= MAX_COMPONENTS:
                max_components = int(value)
                break
            print(f"{R}  Enter a number from 1 to {MAX_COMPONENTS}.{X}")
        try:
            candidates = generate_wordlist(words, year, cases, separators, suffixes, short_year, max_components)
        except ValueError as exc:
            print(f"{R}  Error: {exc}{X}")
            return
        print(f"\n{G}  {len(candidates):,} unique entries{X} (limit: {MAX_CANDIDATES:,}).")
        print(f"  Preview of the first {min(30, len(candidates))}:")
        for candidate in candidates[:30]:
            print(f"    {candidate}")
        while True:
            answer = input("  Save the complete wordlist? [y/N] ").strip().lower()
            if answer in ("", "n", "no"):
                return
            if answer in ("y", "yes"):
                break
            print(f"{R}  Enter y or n.{X}")
        while True:
            path = input("  Save to [wordlist.txt] (or q to cancel): ").strip().strip('"') or "wordlist.txt"
            if path.lower() == "q":
                print(f"{Y}  Save cancelled.{X}")
                return
            try:
                with open(path, "x", encoding="utf-8", newline="\n") as file:
                    file.write("\n".join(candidates) + "\n")
            except FileExistsError:
                print(f"{R}  File already exists; choose a different path.{X}")
                continue
            except OSError as exc:
                print(f"{R}  Could not save wordlist: {exc}{X}")
                continue
            print(f"{G}  Saved {len(candidates):,} entries to {path}{X}")
            return

    # ---------------------------------------------------------- ARP spoofing
    def arp_spoof(self):
        try:
            from . import arpspoof as sp
        except ImportError:
            print(f"{R}  scapy is not installed. Run: pip install scapy{X}")
            return

        print(f"\n{R}  ARP spoofing intercepts other hosts' traffic.{X}")
        print(f"{Y}  Only use this against networks and hosts you are explicitly authorized to test.{X}")
        if input("  Continue? [y/N] ").strip().lower() != "y":
            return
        if not sp.is_admin():
            print(f"{R}  Administrator/root privileges are required (raw packets + IP forwarding).{X}")
            return

        ifaces = sp.list_interfaces()
        if not ifaces:
            print(f"{R}  No usable network interfaces found.{X}")
            return
        print("\n  Interfaces:")
        for i, (name, desc, ip) in enumerate(ifaces, 1):
            print(f"   {i}) {desc}  {D}({ip}){X}")
        sel = input("  Interface (number): ").strip()
        if not sel.isdigit() or not (1 <= int(sel) <= len(ifaces)):
            print(f"{Y}  Cancelled.{X}")
            return
        iface_name, _, my_ip = ifaces[int(sel) - 1]

        gw_guess = sp.default_gateway() or ""
        gateway_ip = input(f"  Gateway IP [{gw_guess}]: ").strip() or gw_guess
        if not gateway_ip:
            print(f"{Y}  A gateway IP is required.{X}")
            return

        print("\n  Mode:\n   1) Single target  <->  gateway\n   2) Multiple targets  <->  gateway\n"
              "   3) Full subnet (ARP-scan and spoof every host found)")
        mode = input("  Mode (number): ").strip()
        targets = []
        if mode == "1":
            t = input("  Target IP: ").strip()
            if t:
                targets = [t]
        elif mode == "2":
            raw = input("  Target IPs (comma-separated): ").strip()
            targets = [t.strip() for t in raw.split(",") if t.strip()]
        elif mode == "3":
            default_cidr = f"{my_ip.rsplit('.', 1)[0]}.0/24"
            cidr = input(f"  Subnet to scan [{default_cidr}]: ").strip() or default_cidr
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                print(f"{R}  Invalid subnet.{X}")
                return
            print(f"{D}  Scanning {cidr}...{X}")
            found = [(ip, mac) for ip, mac in sp.scan_subnet(cidr, iface_name) if ip not in (my_ip, gateway_ip)]
            if not found:
                print(f"{Y}  No hosts found.{X}")
                return
            print(f"{D}  Identifying devices (vendor/hostname/OS guess)...{X}")
            enriched = sp.identify_hosts(found, iface_name)
            print(f"  Found {len(enriched)} host(s):")
            for i, hst in enumerate(enriched, 1):
                bits = [hst["mac"]]
                if hst["vendor"]:
                    bits.append(hst["vendor"])
                if hst["hostname"]:
                    bits.append(hst["hostname"])
                if hst["os_guess"]:
                    bits.append(hst["os_guess"])
                print(f"   {i}) {hst['ip']}  {D}{' · '.join(bits)}{X}")
            sel = input("  Which ones? (comma-separated numbers, or 'all'): ").strip().lower()
            if sel == "all":
                targets = [hst["ip"] for hst in enriched]
            else:
                idx = [int(x) - 1 for x in sel.split(",") if x.strip().isdigit()]
                targets = [enriched[i]["ip"] for i in idx if 0 <= i < len(enriched)]
        else:
            print(f"{Y}  Cancelled.{X}")
            return
        if not targets:
            print(f"{Y}  No targets selected.{X}")
            return

        bidir = input("  Also poison the gateway (full two-way MITM)? [Y/n] ").strip().lower() != "n"
        do_fwd = input("  Enable IP forwarding automatically (so victims keep internet access)? [Y/n] ").strip().lower() != "n"
        cap_path = None
        if input("  Capture intercepted traffic to a pcap? [y/N] ").strip().lower() == "y":
            default_path = f"mitm_{datetime.now():%Y%m%d_%H%M%S}.pcap"
            cap_path = input(f"  Save to [{default_path}]: ").strip().strip('"') or default_path

        spoofer = sp.ArpSpoofer(iface_name, gateway_ip, targets, bidirectional=bidir)
        try:
            print(f"{D}  Resolving MAC addresses...{X}")
            spoofer.start()
        except Exception as exc:
            print(f"{R}  Error: {exc}{X}")
            return

        prev_fwd = sp.forwarding_get()
        if do_fwd:
            try:
                note = sp.forwarding_set(True)
                print(f"{D}  {note}{X}")
            except Exception as exc:
                print(f"{Y}  Could not change IP forwarding: {exc}{X}")
                do_fwd = False

        capture = None
        if cap_path:
            capture = sp.TrafficCapture(iface_name, targets, cap_path)
            capture.start()

        print(f"\n{G}  Spoofing {len(targets)} target(s) via {gateway_ip} on {iface_name}. "
              f"Press Ctrl+C to stop and restore ARP.{X}")
        started = time.time()
        try:
            while True:
                elapsed = int(time.time() - started)
                status = f"  running {elapsed}s"
                if capture:
                    status += f" · captured {capture.count} packets"
                print(f"\r{D}{status}   {X}", end="", flush=True)
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            print(f"\n{D}  Stopping and restoring ARP tables...{X}")
            try:
                spoofer.restore()
            except Exception as exc:
                print(f"{R}  Could not fully restore ARP tables: {exc}{X}")
            if capture:
                try:
                    capture.stop()
                    print(f"{G}  ✔ Saved {capture.count} packets to {cap_path}{X}")
                except Exception as exc:
                    print(f"{Y}  Could not stop capture cleanly: {exc}{X}")
            if do_fwd and prev_fwd is not None:
                try:
                    sp.forwarding_set(prev_fwd)
                except Exception as exc:
                    print(f"{Y}  Could not restore IP forwarding: {exc}{X}")
            print(f"{G}  ✔ Done.{X}")

    # ---------------------------------------------------------------- loop
    def run(self, initial=None):
        os.system("cls" if os.name == "nt" else "clear")
        print(BANNER)
        if initial:
            self.load(initial)
        actions = {"1": self.load, "2": self.hosts, "3": self.activity, "4": self.by_category,
                   "5": self.search, "6": self.stats, "7": self.export, "8": self.web, "9": self.arp_spoof,
                   "10": self.wordlist}
        while True:
            loaded = f"{G}{self.result['file']}{X}" if self.result else f"{Y}none{X}"
            width = shutil.get_terminal_size().columns
            print(f"\n{D}{'─' * min(width, 60)}{X}\n  Loaded file: {loaded}\n")
            print("   1) Load a pcap\n   2) Summary by host\n   3) Show all activity\n"
                  "   4) Show by category\n   5) Search\n   6) Statistics\n"
                  "   7) Export to JSON\n   8) Open web interface (with file upload)\n"
                  "   9) ARP spoofing / MITM (authorized testing only)\n"
                  "  10) Wordlist generator (authorized testing only)\n   0) Exit")
            try:
                choice = input(f"\n{C}pcap>{X} ").strip()
                if choice in ("0", "q", "exit", "quit"):
                    print("Bye.")
                    return
                action = actions.get(choice)
                if action:
                    action()
                else:
                    print(f"{Y}  Invalid option.{X}")
            except (KeyboardInterrupt, EOFError):
                print("\nBye.")
                return
