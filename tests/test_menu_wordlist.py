import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pcapanalyzer.menu import Menu
from pcapanalyzer.wordlist import generate_wordlist


class MenuWordlistTests(unittest.TestCase):
    def run_menu(self, inputs):
        output = io.StringIO()
        with patch("builtins.input", side_effect=inputs), contextlib.redirect_stdout(output):
            Menu().wordlist()
        return output.getvalue()

    def test_default_rules_save_complete_utf8_wordlist_without_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "words.txt"
            output = self.run_menu([
                "Álex", "sol", "", "", "", "", "1990", "",
                "", "", "", "y", "", "y", str(path),
            ])
            expected = generate_wordlist(
                ["Álex", "sol", "", "", "", "", ""], "1990",
                ["original", "lower", "capitalized"], ["", "_"], [""], True, 3,
            )
            self.assertEqual(path.read_bytes(), ("\n".join(expected) + "\n").encode("utf-8"))
            self.assertIn("unique entries", output)
            self.assertIn("Saved", output)

    def test_custom_options_and_invalid_selections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "words.txt"
            output = self.run_menu([
                "ana", "sol", "", "", "", "", "1990", "",
                "wrong", "2,3", "5", "2", "2,3", "maybe", "n", "5", "2", "y", str(path),
            ])
            expected = generate_wordlist(
                ["ana", "sol"], "1990", ["lower", "capitalized"], ["_"], ["!", "123"], False, 2,
            )
            self.assertEqual(path.read_text(encoding="utf-8").splitlines(), expected)
            self.assertIn("Enter valid option numbers", output)
            self.assertIn("Enter y or n", output)
            self.assertIn("Enter a number from 1 to 4", output)

    def test_existing_file_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "existing.txt"
            path.write_text("unchanged", encoding="utf-8")
            output = self.run_menu([
                "ana", "", "", "", "", "", "", "",
                "", "", "", "", "", "y", str(path), "q",
            ])
            self.assertEqual(path.read_text(encoding="utf-8"), "unchanged")
            self.assertIn("File already exists", output)
            self.assertIn("Save cancelled", output)

    def test_invalid_profile_reports_error_without_saving(self):
        output = self.run_menu([
            "ana", "", "", "", "", "", "bad", "",
            "", "", "", "", "",
        ])
        self.assertIn("Birth year must be four digits", output)

    def test_menu_exposes_wordlist_without_capture(self):
        with patch("pcapanalyzer.menu.os.system"), patch("builtins.input", side_effect=["10", "0"]), \
                patch.object(Menu, "wordlist") as action, contextlib.redirect_stdout(io.StringIO()):
            Menu().run()
        action.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
