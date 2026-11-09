"""Local web server (standard library only) to browse the analysis."""
import ipaddress
import json
import os
import subprocess
import tempfile
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

PAGE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
MAX_UPLOAD = 1024 * 1024 * 1024  # 1 GB
CSP = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
       "connect-src 'self'")


def serve(analyze, result=None, host="127.0.0.1", port=8000):
    """analyze(path) -> dict. result: optional initial analysis (if a pcap was given on the console)."""
    state = {"result": result}
    lock = threading.Lock()  # one analysis at a time
    arp = {  # the single ARP-spoofing session this server can run at a time
        "spoofer": None, "capture": None, "started": None, "iface": None,
        "gateway": None, "targets": [], "prev_forwarding": None,
        "forwarding_requested": False, "cap_path": None, "forwarding_note": None,
    }
    arp_lock = threading.Lock()
    with open(PAGE_PATH, "rb") as f:
        page = f.read()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, ctype, data):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()
            self.wfile.write(data)

        def _json(self, code, obj):
            self._send(code, "application/json", json.dumps(obj).encode())

        def _is_local_client(self):
            try:
                return ipaddress.ip_address(self.client_address[0]).is_loopback
            except ValueError:
                return False

        def _arp_status(self):
            with arp_lock:
                running = arp["spoofer"] is not None
                out = {
                    "running": running,
                    "suggested_capture_name": f"mitm_{datetime.now():%Y%m%d_%H%M%S}.pcap",
                }
                if running:
                    out.update({
                        "elapsed": int(time.time() - arp["started"]),
                        "iface": arp["iface"], "gateway": arp["gateway"], "targets": arp["targets"],
                        "captured": arp["capture"].count if arp["capture"] else None,
                        "capture_path": arp["cap_path"], "forwarding_note": arp["forwarding_note"],
                    })
                return out

        def do_GET(self):
            parsed = urlparse(self.path)
            path, qs = parsed.path, parse_qs(parsed.query)
            if path == "/":
                self._send(200, "text/html; charset=utf-8", page)
            elif path == "/api/analysis":
                if state["result"] is None:
                    self._json(404, {"error": "No analysis yet"})
                else:
                    self._json(200, state["result"])
            elif path == "/api/arp/interfaces":
                try:
                    from . import arpspoof as sp
                except ImportError:
                    return self._json(501, {"error": "scapy is not installed"})
                self._json(200, {
                    "is_admin": sp.is_admin(),
                    "interfaces": [{"name": n, "desc": d, "ip": ip} for n, d, ip in sp.list_interfaces()],
                    "gateway": sp.default_gateway(),
                })
            elif path == "/api/arp/scan":
                try:
                    from . import arpspoof as sp
                except ImportError:
                    return self._json(501, {"error": "scapy is not installed"})
                if not sp.is_admin():
                    return self._json(403, {"error": "Administrator/root privileges are required to send ARP packets. Restart this tool elevated."})
                iface, cidr = qs.get("iface", [""])[0], qs.get("cidr", [""])[0]
                if not iface or not cidr:
                    return self._json(400, {"error": "iface and cidr are required"})
                try:
                    hosts = sp.scan_subnet(cidr, iface)
                    enriched = sp.identify_hosts(hosts, iface)
                    self._json(200, {"hosts": enriched})
                except Exception as exc:
                    self._json(400, {"error": str(exc)})
            elif path == "/api/arp/status":
                self._json(200, self._arp_status())
            elif path == "/api/discovery/interfaces":
                if not self._is_local_client():
                    return self._json(403, {"error": "Host discovery is available only from this computer"})
                try:
                    from . import hostdiscovery as hd
                except ImportError:
                    return self._json(501, {"error": "Scapy is not installed"})
                self._json(200, {"interfaces": hd.list_interfaces()})
            else:
                self.send_error(404)

        def _read_json(self):
            length = int(self.headers.get("Content-Length", "0") or 0)
            return json.loads(self.rfile.read(length) or b"{}")

        def _host_discovery(self, services=False):
            if not self._is_local_client():
                return self._json(403, {"error": "Host discovery is available only from this computer"})
            try:
                from . import hostdiscovery as hd
            except ImportError:
                return self._json(501, {"error": "Scapy is not installed"})
            try:
                body = self._read_json()
            except ValueError:
                return self._json(400, {"error": "Invalid JSON body"})
            if not isinstance(body, dict):
                return self._json(400, {"error": "Invalid request body"})
            if body.get("authorized") is not True:
                return self._json(400, {"error": "Confirm that you are authorized to scan this network"})
            try:
                if services:
                    hosts = hd.scan_services(body.get("interface"), body.get("cidr"), body.get("hosts"))
                else:
                    hosts = hd.scan_hosts(body.get("interface"), body.get("cidr"))
            except FileNotFoundError as exc:
                return self._json(501, {"error": str(exc)})
            except subprocess.TimeoutExpired:
                return self._json(504, {"error": "Nmap scan timed out"})
            except ValueError as exc:
                return self._json(400, {"error": str(exc)})
            except RuntimeError as exc:
                return self._json(502, {"error": str(exc)})
            except OSError as exc:
                return self._json(502, {"error": f"Could not run Nmap: {exc}"})
            self._json(200, {"hosts": hosts})

        def _arp_start(self):
            try:
                from . import arpspoof as sp
            except ImportError:
                return self._json(501, {"error": "scapy is not installed"})
            try:
                body = self._read_json()
            except Exception:
                return self._json(400, {"error": "Invalid JSON body"})
            with arp_lock:
                if arp["spoofer"] is not None:
                    return self._json(409, {"error": "A spoofing session is already running"})
                if not sp.is_admin():
                    return self._json(403, {"error": "Administrator/root privileges are required"})
                iface = body.get("iface")
                gateway = body.get("gateway") or None
                targets = [t.strip() for t in body.get("targets", []) if t and t.strip()]
                if not iface or not targets:
                    return self._json(400, {"error": "iface and at least one target are required"})
                bidirectional = bool(body.get("bidirectional", True))
                want_forwarding = bool(body.get("forwarding", True))
                want_capture = bool(body.get("capture", True))
                cap_path = None
                if want_capture:
                    cap_path = body.get("capture_name") or f"mitm_{datetime.now():%Y%m%d_%H%M%S}.pcap"
                    if not isinstance(cap_path, str):
                        return self._json(400, {"error": "Capture filename must be text"})
                    cap_path = cap_path.strip()
                    if (not cap_path or len(cap_path) > 120 or
                            any(ord(ch) < 32 or ch in '<>:"/\\|?*' for ch in cap_path) or
                            cap_path.endswith((".", " ")) or os.path.basename(cap_path) != cap_path):
                        return self._json(400, {"error": "Enter a valid filename without folders or reserved characters"})
                    if cap_path in (".", ".."):
                        return self._json(400, {"error": "Enter a valid capture filename"})
                    if not cap_path.lower().endswith(".pcap"):
                        if os.path.splitext(cap_path)[1]:
                            return self._json(400, {"error": "Capture filename must use the .pcap extension"})
                        cap_path += ".pcap"
                    if len(cap_path) > 120:
                        return self._json(400, {"error": "Capture filename must be 120 characters or fewer"})
                    if cap_path[:-5].upper() in {
                            "CON", "PRN", "AUX", "NUL",
                            *(f"COM{i}" for i in range(1, 10)),
                            *(f"LPT{i}" for i in range(1, 10))}:
                        return self._json(400, {"error": "That filename is reserved by Windows"})
                    if os.path.exists(cap_path):
                        return self._json(409, {"error": f"File already exists: {cap_path}"})

                spoofer = sp.ArpSpoofer(iface, gateway, targets, bidirectional=bidirectional)
                try:
                    spoofer.start()
                except Exception as exc:
                    return self._json(400, {"error": str(exc)})

                try:
                    prev_forwarding, forwarding_note = None, None
                    if want_forwarding:
                        prev_forwarding = sp.forwarding_get()
                        try:
                            forwarding_note = sp.forwarding_set(True)
                        except Exception as exc:
                            forwarding_note = f"Could not change IP forwarding: {exc}"

                    capture = None
                    if want_capture:
                        capture = sp.TrafficCapture(iface, targets, cap_path)
                        capture.start()
                except Exception as exc:
                    spoofer.restore()
                    return self._json(400, {"error": f"Could not fully start (ARP tables already restored): {exc}"})

                arp.update(spoofer=spoofer, capture=capture, started=time.time(), iface=iface,
                           gateway=gateway, targets=targets, prev_forwarding=prev_forwarding,
                           forwarding_requested=want_forwarding, cap_path=cap_path,
                           forwarding_note=forwarding_note)
                self._json(200, {"ok": True})

        def _arp_stop(self):
            try:
                from . import arpspoof as sp
            except ImportError:
                return self._json(501, {"error": "scapy is not installed"})
            with arp_lock:
                if arp["spoofer"] is None:
                    return self._json(409, {"error": "No spoofing session is running"})
                captured, cap_path = None, arp["cap_path"]
                warnings = []
                try:
                    arp["spoofer"].restore()
                except Exception as exc:
                    warnings.append(f"Could not fully restore ARP tables: {exc}")
                if arp["capture"]:
                    try:
                        arp["capture"].stop()
                        captured = arp["capture"].count
                    except Exception as exc:
                        warnings.append(f"Could not stop capture cleanly: {exc}")
                if arp["forwarding_requested"] and arp["prev_forwarding"] is not None:
                    try:
                        sp.forwarding_set(arp["prev_forwarding"])
                    except Exception as exc:
                        warnings.append(f"Could not restore IP forwarding: {exc}")
                arp.update(spoofer=None, capture=None, started=None, iface=None, gateway=None,
                           targets=[], prev_forwarding=None, forwarding_requested=False,
                           cap_path=None, forwarding_note=None)
                resp = {"ok": True, "captured": captured, "capture_path": cap_path}
                if warnings:
                    resp["warnings"] = warnings
                self._json(200, resp)

        def _upload(self):
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return self._json(411, {"error": "Missing Content-Length"})
            if length <= 0 or length > MAX_UPLOAD:
                return self._json(413, {"error": "File is empty or too large (max. 1 GB)"})
            name = os.path.basename(parse_qs(urlparse(self.path).query).get("name", ["upload.pcap"])[0])
            suffix = os.path.splitext(name)[1].lower()
            if suffix not in (".pcap", ".pcapng", ".cap"):
                suffix = ".pcap"
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
            try:
                remaining = length
                with tmp:
                    while remaining:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        if not chunk:
                            raise ValueError("Upload interrupted")
                        tmp.write(chunk)
                        remaining -= len(chunk)
                with lock:
                    res = analyze(tmp.name)
                res["file"] = name
                state["result"] = res
                self._json(200, res)
            except Exception as exc:
                self._json(400, {"error": f"Could not analyze the file: {exc}"})
            finally:
                os.unlink(tmp.name)

        def do_POST(self):
            path = urlparse(self.path).path
            if path == "/api/upload":
                self._upload()
            elif path == "/api/arp/start":
                self._arp_start()
            elif path == "/api/arp/stop":
                self._arp_stop()
            elif path == "/api/discovery/scan":
                self._host_discovery()
            elif path == "/api/discovery/services":
                self._host_discovery(services=True)
            else:
                self.send_error(404)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Web interface at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
    finally:
        with arp_lock:
            if arp["spoofer"] is not None:
                print("Restoring ARP tables before exit...")
                try:
                    arp["spoofer"].restore()
                except Exception as exc:
                    print(f"Could not fully restore ARP tables: {exc}")
                if arp["capture"]:
                    try:
                        arp["capture"].stop()
                    except Exception:
                        pass
                if arp["forwarding_requested"] and arp["prev_forwarding"] is not None:
                    try:
                        from . import arpspoof as sp
                        sp.forwarding_set(arp["prev_forwarding"])
                    except Exception:
                        pass
        server.server_close()
    return state["result"]
