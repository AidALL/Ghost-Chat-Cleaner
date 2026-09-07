"""Exercise packaged notice metadata with a non-UTF-8 process locale."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "generate_notices", PROJECT_ROOT / "scripts/generate-notices.py"
)
NOTICES = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NOTICES)


class NoticeMetadataEncodingTests(unittest.TestCase):
    def test_author_names_survive_non_utf8_process_locale(self):
        compiler = subprocess.run(
            ["rustc", "-vV"], capture_output=True, check=True, encoding="utf-8"
        ).stdout
        target = next(line.removeprefix("host: ") for line in compiler.splitlines()
                      if line.startswith("host: "))
        result = subprocess.run(
            ["cargo", "metadata", "--locked", "--offline", "--format-version", "1",
             "--filter-platform", target],
            cwd=PROJECT_ROOT, capture_output=True, check=True,
        )
        metadata = json.loads(result.stdout)
        author_lines = [
            "Authors (package metadata, not a reconstructed copyright statement): "
            + "; ".join(package.get("authors", []))
            for package in NOTICES.normal_packages(metadata)
        ]
        self.assertTrue(any(not line.isascii() for line in author_lines))
        real_popen = subprocess.Popen

        def legacy_text_process(*args, **kwargs):
            if (kwargs.get("text") or kwargs.get("universal_newlines")) and kwargs.get("encoding") is None:
                kwargs["encoding"] = "cp1252"
            return real_popen(*args, **kwargs)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "THIRD_PARTY_NOTICES.txt"
            arguments = ["generate-notices.py", "--target", target, "--output", str(output)]
            # Emulate a legacy default decoder at the public process boundary.
            # Cargo still executes and its output passes through a real pipe.
            with patch.object(sys, "argv", arguments), patch(
                "subprocess.Popen", side_effect=legacy_text_process
            ):
                NOTICES.main()
            rendered_lines = output.read_text(encoding="utf-8").splitlines()
            actual = [line for line in rendered_lines if line.startswith("Authors (")]
            self.assertEqual(author_lines, actual)


if __name__ == "__main__":
    unittest.main()
