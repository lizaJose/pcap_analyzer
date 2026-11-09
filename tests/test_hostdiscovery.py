import ipaddress
import os
import subprocess
import unittest
from unittest.mock import patch

from pcapanalyzer import hostdiscovery


class HostDiscoveryTests(unittest.TestCase):
    interfaces = [{
        "name": "Ethernet",
        "description": "Ethernet",
        "ip": "192.168.1.12",
        "network": "192.168.1.0/24",
    }]

    @patch("pcapanalyzer.hostdiscovery.os.path.isfile")
    @patch("pcapanalyzer.hostdiscovery.shutil.which", return_value=None)
    @patch.dict("pcapanalyzer.hostdiscovery.os.environ", {
        "ProgramFiles": r"C:\Program Files",
        "ProgramFiles(x86)": r"C:\Program Files (x86)",
    })
    def test_find_nmap_in_standard_windows_location(self, _which, isfile):
        expected = os.path.join(r"C:\Program Files (x86)", "Nmap", "nmap.exe")
        isfile.side_effect = lambda path: path == expected
        self.assertEqual(hostdiscovery.find_nmap(), expected)

    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    @patch("pcapanalyzer.hostdiscovery.find_nmap", return_value=None)
    def test_missing_nmap_reports_installation_requirement(self, _find_nmap, list_interfaces):
        list_interfaces.return_value = self.interfaces
        with self.assertRaisesRegex(FileNotFoundError, "Install Nmap"):
            hostdiscovery.scan_hosts("Ethernet", "192.168.1.0/24")

    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_accepts_subnet_of_connected_private_network(self, list_interfaces):
        list_interfaces.return_value = self.interfaces
        self.assertEqual(
            hostdiscovery._target_network("Ethernet", "192.168.1.0/25").with_prefixlen,
            "192.168.1.0/25",
        )

    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_rejects_public_network(self, list_interfaces):
        list_interfaces.return_value = self.interfaces
        with self.assertRaisesRegex(ValueError, "RFC1918"):
            hostdiscovery._target_network("Ethernet", "8.8.8.0/24")

    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_rejects_ranges_larger_than_256_addresses(self, list_interfaces):
        list_interfaces.return_value = self.interfaces
        with self.assertRaisesRegex(ValueError, "256 addresses"):
            hostdiscovery._target_network("Ethernet", "192.168.0.0/23")

    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_rejects_network_outside_selected_interface(self, list_interfaces):
        list_interfaces.return_value = self.interfaces
        with self.assertRaisesRegex(ValueError, "connected to the selected interface"):
            hostdiscovery._target_network("Ethernet", "192.168.2.0/24")

    @patch("pcapanalyzer.hostdiscovery.subprocess.run")
    @patch("pcapanalyzer.hostdiscovery.shutil.which", return_value="nmap.exe")
    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_parses_only_up_ipv4_hosts(self, list_interfaces, _which, run):
        list_interfaces.return_value = self.interfaces
        run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stderr="",
            stdout=(
                '<nmaprun><host><status state="up"/>'
                '<address addr="192.168.1.20" addrtype="ipv4"/>'
                '<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Example Corp"/>'
                '<hostnames><hostname name="laptop"/></hostnames></host>'
                '<host><status state="up"/>'
                '<address addr="192.168.1.10" addrtype="ipv4"/>'
                '<address addr="02:11:22:33:44:55" addrtype="mac" vendor="Unreliable"/>'
                '</host>'
                '<host><status state="up"/>'
                '<address addr="192.168.1.11" addrtype="ipv4"/>'
                '</host>'
                '<host><status state="down"/>'
                '<address addr="192.168.1.21" addrtype="ipv4"/></host></nmaprun>'
            ),
        )

        self.assertEqual(
            hostdiscovery.scan_hosts("Ethernet", "192.168.1.0/24"),
            [
                {"ip": "192.168.1.10", "hostname": "", "mac": "02:11:22:33:44:55",
                 "vendor": "", "mac_randomized": True, "device_type": ""},
                {"ip": "192.168.1.11", "hostname": "", "mac": "",
                 "vendor": "", "mac_randomized": False, "device_type": ""},
                {"ip": "192.168.1.20", "hostname": "laptop", "mac": "00:11:22:33:44:55",
                 "vendor": "Example Corp", "mac_randomized": False, "device_type": "Computer"},
            ],
        )
        self.assertEqual(
            run.call_args.args[0],
            ["nmap.exe", "-sn", "-oX", "-", "192.168.1.0/24"],
        )

    def test_device_type_is_a_conservative_hostname_guess(self):
        examples = {
            "iPhone-de-Ana": "Phone",
            "ipad-2": "Tablet",
            "android-123": "Phone or tablet",
            "smart-tv": "TV",
            "camera-01": "Camera",
            "desktop-123": "Computer",
            "printer.local": "Printer",
            "gateway": "Router or gateway",
            "samsung-device": "",
            "cameraman": "",
            "": "",
        }
        for hostname, expected in examples.items():
            with self.subTest(hostname=hostname):
                self.assertEqual(hostdiscovery._guess_device_type(hostname), expected)

    @patch("pcapanalyzer.hostdiscovery._run_nmap")
    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_service_scan_parses_ports_and_incomplete_hosts(self, list_interfaces, run_nmap):
        list_interfaces.return_value = self.interfaces
        run_nmap.return_value = hostdiscovery.ET.fromstring(
            '<nmaprun><host><address addr="192.168.1.10" addrtype="ipv4"/>'
            '<ports><port protocol="tcp" portid="554"><state state="open"/>'
            '<service name="rtsp" product="Example camera" version="1.0" method="probed"/>'
            '</port><port protocol="tcp" portid="80"><state state="closed"/></port>'
            '<port protocol="tcp" portid="445"><state state="open"/>'
            '<service name="microsoft-ds" method="table"/></port></ports></host>'
            '<host><address addr="192.168.1.11" addrtype="ipv4"/></host></nmaprun>'
        )
        hosts = hostdiscovery.scan_services(
            "Ethernet", "192.168.1.0/24", ["192.168.1.10", "192.168.1.11"]
        )
        self.assertTrue(hosts[0]["complete"])
        self.assertEqual([service["port"] for service in hosts[0]["services"]], ["554", "445"])
        self.assertEqual(hosts[0]["services"][0]["product"], "Example camera")
        self.assertEqual(hosts[0]["services"][1]["method"], "table")
        self.assertEqual(len(hosts[0]["clues"]), 3)
        self.assertIn("Service identification suggests: Camera (not conclusive)", hosts[0]["clues"])
        self.assertFalse(hosts[1]["complete"])
        self.assertEqual(hosts[1]["services"], [])
        self.assertEqual(run_nmap.call_args.args[0], [
            "-sT", "-sV", "--version-light", "--top-ports", "100", "-Pn", "-n",
            "--host-timeout", "60s", "-oX", "-", "192.168.1.10", "192.168.1.11",
        ])

    @patch("pcapanalyzer.hostdiscovery._run_nmap")
    @patch("pcapanalyzer.hostdiscovery.list_interfaces")
    def test_service_scan_rejects_invalid_or_out_of_scope_addresses(self, list_interfaces, run_nmap):
        list_interfaces.return_value = self.interfaces
        for addresses in ([], ["8.8.8.8"], ["192.168.2.1"], ["-sV"], [1], ["::1"], "192.168.1.1",
                          ["192.168.1.1"] * 257):
            with self.subTest(addresses=addresses), self.assertRaises(ValueError):
                hostdiscovery.scan_services("Ethernet", "192.168.1.0/24", addresses)
        run_nmap.assert_not_called()

    @patch("pcapanalyzer.hostdiscovery._run_nmap")
    @patch("pcapanalyzer.hostdiscovery._target_network", return_value=ipaddress.ip_network("192.168.1.0/24"))
    def test_service_scan_distinguishes_empty_and_missing_results(self, _target_network, run_nmap):
        run_nmap.return_value = hostdiscovery.ET.fromstring(
            '<nmaprun><host><address addr="192.168.1.10" addrtype="ipv4"/>'
            '<ports><extraports state="closed" count="100"/></ports></host></nmaprun>'
        )
        hosts = hostdiscovery.scan_services("Ethernet", "192.168.1.0/24", ["192.168.1.10", "192.168.1.11"])
        self.assertTrue(hosts[0]["complete"])
        self.assertEqual(hosts[0]["services"], [])
        self.assertFalse(hosts[1]["complete"])


if __name__ == "__main__":
    unittest.main()
