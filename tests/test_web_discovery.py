import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from pcapanalyzer import webserver


class WebDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.ready = threading.Event()
        self.server = None

        def create_server(address, handler):
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            self.ready.set()
            return self.server

        server_patch = patch.object(webserver, "ThreadingHTTPServer", side_effect=create_server)
        server_patch.start()
        self.addCleanup(server_patch.stop)
        self.thread = threading.Thread(target=webserver.serve, args=(lambda _: {},), daemon=True)
        self.thread.start()
        if not self.ready.wait(5):
            self.fail("Web server did not start")
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def post(self, payload):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request("POST", "/api/discovery/services", json.dumps(payload),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    @patch("pcapanalyzer.hostdiscovery.scan_services")
    def test_requires_authorization_then_returns_service_results(self, scan_services):
        scan_services.return_value = [{"ip": "192.168.1.10", "complete": True, "services": [], "clues": []}]
        payload = {"interface": "Ethernet", "cidr": "192.168.1.0/24", "hosts": ["192.168.1.10"]}
        status, response = self.post(payload)
        self.assertEqual(status, 400)
        self.assertIn("authorized", response["error"])
        scan_services.assert_not_called()

        payload["authorized"] = True
        payload["scripts"] = "yes"
        status, response = self.post(payload)
        self.assertEqual(status, 400)
        self.assertIn("boolean", response["error"])
        scan_services.assert_not_called()

        payload["scripts"] = True
        status, response = self.post(payload)
        self.assertEqual(status, 200)
        self.assertEqual(response["hosts"], scan_services.return_value)
        scan_services.assert_called_once_with(
            "Ethernet", "192.168.1.0/24", ["192.168.1.10"], include_scripts=True
        )


if __name__ == "__main__":
    unittest.main()
