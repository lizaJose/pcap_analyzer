import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from pcapanalyzer import webserver, wordlist


class WordlistTests(unittest.TestCase):
    def test_combinations_apply_case_separator_year_and_suffix(self):
        result = wordlist.generate_wordlist(
            ["maria", "Luna"], "1990", ["lower", "capitalized"], ["", "_"],
            ["", "!"], short_year=True,
        )
        self.assertIn("Maria_1990", result)
        self.assertIn("1990_Maria!", result)
        self.assertIn("Luna90", result)
        self.assertIn("maria", result)
        self.assertEqual(result, sorted(set(result)))

    def test_unicode_and_original_case_are_preserved(self):
        result = wordlist.generate_wordlist(
            ["Álex", "niña"], "", ["original"], ["_"], [""]
        )
        self.assertEqual(result, sorted(["Álex", "niña", "Álex_niña", "niña_Álex"]))

    def test_duplicate_inputs_do_not_create_duplicate_entries(self):
        result = wordlist.generate_wordlist(["maria", "maria"], "", ["lower"], [""], [""])
        self.assertEqual(result, ["maria"])

    def test_three_component_combinations_include_mixed_separators(self):
        result = wordlist.generate_wordlist(
            ["ana", "sol"], "2001", ["lower", "capitalized"], ["", "_"], [""]
        )
        self.assertIn("Ana_sol_2001", result)
        self.assertIn("Anasol_2001", result)
        self.assertIn("2001_anaSol", result)
        self.assertNotIn("ana_ana_2001", result)

    def test_maximum_components_can_be_changed(self):
        args = (["ana", "sol", "luna"], "", ["lower"], ["_"], [""])
        self.assertEqual(len(wordlist.generate_wordlist(*args, max_components=1)), 3)
        self.assertEqual(len(wordlist.generate_wordlist(*args, max_components=2)), 9)
        self.assertEqual(len(wordlist.generate_wordlist(*args, max_components=3)), 15)
        result = wordlist.generate_wordlist(
            ["ana", "sol", "luna", "mar"], "", ["lower"], ["_"], [""], max_components=4
        )
        self.assertIn("ana_sol_luna_mar", result)
        for value in (0, 5, "3", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                wordlist.generate_wordlist(*args, max_components=value)

    def test_realistic_profile_generates_more_than_two_components(self):
        result = wordlist.generate_wordlist(
            ["ana", "garcia", "annie", "luna", "montana", "verano"], "1990",
            ["original", "lower", "capitalized"], ["", "_"], [""], short_year=True
        )
        self.assertGreater(len(result), 5000)
        self.assertIn("Ana_garcia_1990", result)
        self.assertIn("anaGarcia90", result)

    def test_invalid_inputs_are_rejected(self):
        valid = (["name"], "1990", ["lower"], [""], [""], False)
        invalid = (
            ([], "", ["lower"], [""], [""], False),
            (["bad\nword"], "", ["lower"], [""], [""], False),
            (["x" * 101], "", ["lower"], [""], [""], False),
            (["name"] * 21, "", ["lower"], [""], [""], False),
            (["name"], "19ab", ["lower"], [""], [""], False),
            (["name"], "", [], [""], [""], False),
            (["name"], "", ["lower"], ["/"], [""], False),
            (["name"], "", ["lower"], [""], ["unknown"], False),
            (["name"], "", ["lower"], [""], [""], "yes"),
        )
        self.assertTrue(wordlist.generate_wordlist(*valid))
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                wordlist.generate_wordlist(*args)

    @patch("pcapanalyzer.wordlist.MAX_CANDIDATES", 2)
    def test_limit_is_reported_instead_of_truncating(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            wordlist.generate_wordlist(["one", "two"], "", ["lower"], [""], [""])


class WordlistWebTests(unittest.TestCase):
    def setUp(self):
        ready = threading.Event()
        self.server = None

        def create_server(address, handler):
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
            ready.set()
            return self.server

        server_patch = patch.object(webserver, "ThreadingHTTPServer", side_effect=create_server)
        server_patch.start()
        self.addCleanup(server_patch.stop)
        self.thread = threading.Thread(target=webserver.serve, args=(lambda _: {},), daemon=True)
        self.thread.start()
        if not ready.wait(5):
            self.fail("Web server did not start")
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def post(self, payload):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request("POST", "/api/wordlist", json.dumps(payload),
                               {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def test_generation_and_validation_through_http(self):
        payload = {
            "words": ["maria"], "year": "1990", "cases": ["capitalized"],
            "separators": ["_"], "suffixes": [""], "short_year": False,
        }
        status, response = self.post(payload)
        self.assertEqual(status, 200)
        self.assertIn("Maria_1990", response["words"])
        self.assertEqual(response["count"], len(response["words"]))

        payload["words"] = ["maria", "luna"]
        payload["max_components"] = 3
        status, response = self.post(payload)
        self.assertEqual(status, 200)
        self.assertIn("Maria_Luna_1990", response["words"])

        payload["max_components"] = 5
        status, response = self.post(payload)
        self.assertEqual(status, 400)
        self.assertIn("Maximum components", response["error"])
        payload["max_components"] = 3
        payload["year"] = "bad"
        status, response = self.post(payload)
        self.assertEqual(status, 400)
        self.assertIn("four digits", response["error"])

    def test_oversized_request_is_rejected(self):
        status, response = self.post({"words": ["x" * webserver.MAX_WORDLIST_REQUEST]})
        self.assertEqual(status, 413)
        self.assertIn("too large", response["error"])


if __name__ == "__main__":
    unittest.main()
