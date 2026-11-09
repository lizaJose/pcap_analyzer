"""Nmap-based host discovery for directly connected private IPv4 networks."""
import ipaddress
import os
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET

from scapy.all import conf

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
MAX_SCAN_ADDRESSES = 256
SCAN_TIMEOUT = 90
SERVICE_SCAN_TIMEOUT = 300

DEVICE_NAME_PATTERNS = (
    (r"(?<![a-z0-9])(?:iphone)(?![a-z])", "Phone"),
    (r"(?<![a-z0-9])(?:ipad)(?![a-z])", "Tablet"),
    (r"(?<![a-z0-9])(?:android)(?![a-z])", "Phone or tablet"),
    (r"(?<![a-z0-9])(?:smarttv|smart-tv|tv|television)(?![a-z])", "TV"),
    (r"(?<![a-z0-9])(?:camera|camara|webcam|ipcam)(?![a-z])", "Camera"),
    (r"(?<![a-z0-9])(?:desktop|laptop|computer|macbook|imac)(?![a-z])", "Computer"),
    (r"(?<![a-z0-9])(?:printer|impresora)(?![a-z])", "Printer"),
    (r"(?<![a-z0-9])(?:router|gateway)(?![a-z])", "Router or gateway"),
)


def find_nmap():
    path = shutil.which("nmap")
    if path:
        return path
    for program_files in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if program_files:
            candidate = os.path.join(program_files, "Nmap", "nmap.exe")
            if os.path.isfile(candidate):
                return candidate
    return None


def _is_private_network(network):
    return any(network.subnet_of(private) for private in PRIVATE_NETWORKS)


def list_interfaces():
    """Return interface/network pairs for directly connected RFC1918 IPv4 networks."""
    out = []
    seen = set()
    for iface in conf.ifaces.values():
        ip = getattr(iface, "ip", None)
        if not ip or ip == "0.0.0.0":
            continue
        try:
            address = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            continue
        for route in conf.route.routes:
            if len(route) < 5 or str(route[4]) != str(address) or not route[1]:
                continue
            try:
                netmask = str(ipaddress.IPv4Address(route[1]))
                network = ipaddress.IPv4Network((route[0], netmask), strict=False)
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, TypeError):
                continue
            if network.prefixlen == 32 or address not in network or not _is_private_network(network):
                continue
            entry = (iface.name, str(address), str(network))
            if entry in seen:
                continue
            seen.add(entry)
            out.append({
                "name": iface.name,
                "description": getattr(iface, "description", iface.name) or iface.name,
                "ip": str(address),
                "network": str(network),
            })
    return sorted(out, key=lambda item: (item["description"].lower(), item["network"]))


def _target_network(interface, cidr):
    if not isinstance(interface, str) or not interface:
        raise ValueError("Select a network interface")
    if not isinstance(cidr, str) or not cidr:
        raise ValueError("Enter a private IPv4 subnet")
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError("Enter a valid IPv4 subnet") from exc
    if network.version != 4 or not _is_private_network(network):
        raise ValueError("Only RFC1918 private IPv4 subnets are allowed")
    if network.num_addresses > MAX_SCAN_ADDRESSES:
        raise ValueError("The scan is limited to 256 addresses")

    local_networks = {
        ipaddress.ip_network(item["network"])
        for item in list_interfaces()
        if item["name"] == interface
    }
    if not any(network.subnet_of(local) for local in local_networks):
        raise ValueError("The subnet must be within a private network connected to the selected interface")
    return network


def _guess_device_type(hostname):
    """Only make an explicitly tentative guess from recognizable hostname tokens."""
    for pattern, device_type in DEVICE_NAME_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            return device_type
    return ""


def _run_nmap(arguments, timeout):
    nmap = find_nmap()
    if not nmap:
        raise FileNotFoundError("Nmap was not found. Install Nmap and restart the application; "
                                "if installed elsewhere, add its folder to PATH.")

    result = subprocess.run(
        [nmap, *arguments],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        message = result.stderr.strip() or f"Nmap exited with status {result.returncode}"
        raise RuntimeError(message)
    try:
        return ET.fromstring(result.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("Nmap returned invalid XML output") from exc


def scan_hosts(interface, cidr):
    """Run a bounded Nmap ping scan and return hosts reported as up."""
    network = _target_network(interface, cidr)
    root = _run_nmap(["-sn", "-oX", "-", str(network)], SCAN_TIMEOUT)

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        address = next(
            (item.get("addr") for item in host.findall("address") if item.get("addrtype") == "ipv4"),
            None,
        )
        if not address:
            continue
        hostname = host.find("./hostnames/hostname")
        name = hostname.get("name", "") if hostname is not None else ""
        mac_element = next(
            (item for item in host.findall("address") if item.get("addrtype") == "mac"),
            None,
        )
        mac = mac_element.get("addr", "") if mac_element is not None else ""
        vendor = mac_element.get("vendor", "") if mac_element is not None else ""
        try:
            is_local_mac = bool(int(mac.split(":")[0], 16) & 2) if mac else False
        except ValueError:
            is_local_mac = False
        hosts.append({
            "ip": address,
            "hostname": name,
            "mac": mac,
            "vendor": vendor if not is_local_mac else "",
            "mac_randomized": is_local_mac,
            "device_type": _guess_device_type(name),
        })
    return sorted(hosts, key=lambda item: ipaddress.IPv4Address(item["ip"]))


def scan_services(interface, cidr, addresses):
    """Scan the top 100 TCP ports on explicitly selected local IPv4 addresses."""
    network = _target_network(interface, cidr)
    if not isinstance(addresses, list) or not addresses or len(addresses) > MAX_SCAN_ADDRESSES:
        raise ValueError("Provide 1 to 256 discovered host addresses")
    targets = []
    for address in addresses:
        if not isinstance(address, str):
            raise ValueError("Invalid host address")
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise ValueError("Invalid host address") from exc
        if ip not in network:
            raise ValueError("All host addresses must be within the selected subnet")
        if str(ip) not in targets:
            targets.append(str(ip))

    root = _run_nmap(
        ["-sT", "-sV", "--version-light", "--top-ports", "100", "-Pn", "-n",
         "--host-timeout", "60s", "-oX", "-", *targets],
        SERVICE_SCAN_TIMEOUT,
    )
    results = {ip: {"ip": ip, "complete": False, "services": [], "clues": []} for ip in targets}
    for host in root.findall("host"):
        address = next(
            (item.get("addr") for item in host.findall("address") if item.get("addrtype") == "ipv4"),
            None,
        )
        ports = host.find("ports")
        if address not in results or ports is None:
            continue
        entry = results[address]
        entry["complete"] = True
        clues = set()
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open" or port.get("protocol") != "tcp":
                continue
            service = port.find("service")
            info = service.attrib if service is not None else {}
            entry["services"].append({
                "port": port.get("portid", ""),
                "name": info.get("name", ""),
                "product": info.get("product", ""),
                "version": info.get("version", ""),
                "extrainfo": info.get("extrainfo", ""),
                "method": info.get("method", ""),
            })
            if info.get("method") == "probed":
                product_type = _guess_device_type(" ".join(
                    (info.get("product", ""), info.get("extrainfo", ""))
                ))
                if product_type:
                    clues.add(f"Service identification suggests: {product_type} (not conclusive)")
            if port.get("portid") == "631":
                clues.add("Printing service: possibly a printer or a computer sharing a printer")
            elif port.get("portid") == "554":
                clues.add("RTSP: possibly a camera or another streaming device")
            elif port.get("portid") == "445":
                clues.add("SMB: possibly a computer, NAS or other file-sharing device")
        entry["clues"] = sorted(clues)
    return list(results.values())
