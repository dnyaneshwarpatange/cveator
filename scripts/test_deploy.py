"""Deployment guard regression tests; no Docker or external services are called."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import deploy


class DeploymentTests(unittest.TestCase):
    def test_local_secrets_are_generated_and_never_overwritten(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ".env"
            deploy.create_local_environment(path)
            values = deploy.read_environment(path)
            self.assertGreaterEqual(len(values["JWT_SECRET"]), 32)
            self.assertNotIn("change-me", values["DATABASE_URL"])
            self.assertEqual(values["PAYMENT_PROVIDER"], "")
            with self.assertRaises(FileExistsError):
                deploy.create_local_environment(path)

    def test_wrong_environment_is_rejected(self):
        with self.assertRaises(ValueError):
            deploy.validate_target({"APP_ENV": "production"}, False)
        with self.assertRaises(ValueError):
            deploy.validate_target({"APP_ENV": "development"}, True)

    def test_production_requires_real_https_host(self):
        for url in ("http://monitor.acme.org", "https://monitor.example.com"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                deploy.validate_target({"APP_ENV": "production", "PUBLIC_APP_URL": url}, True)

    def test_mail_key_cannot_escape_its_directory(self):
        with self.assertRaisesRegex(ValueError, "DKIM_SELECTOR"):
            deploy.validate_target({"APP_ENV": "production", "PUBLIC_APP_URL": "https://monitor.acme.org",
                                    "APP_ADDRESS": "monitor.acme.org", "SMTP_HOST": "smtp",
                                    "DKIM_SELECTOR": "../../secret"}, True)

    def test_demo_cannot_run_in_production(self):
        with patch("sys.argv", ["deploy.py", "--production", "--demo"]):
            with self.assertRaises(SystemExit) as stopped:
                deploy.main()
            self.assertEqual(stopped.exception.code, 2)

    def test_docker_failure_prevents_startup(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / ".env"
            deploy.create_local_environment(path)
            with patch("sys.argv", ["deploy.py", "--env-file", str(path)]), \
                    patch.object(deploy, "run", side_effect=OSError("Docker unavailable")) as command:
                with self.assertRaises(OSError):
                    deploy.main()
                self.assertEqual(command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
